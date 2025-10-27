#include "protocols.h"
#include "queue.h"
#include "lib.h"
#include <arpa/inet.h>
#include <string.h>

#define MAX_IP_QUEUE_ENTRIES 128

typedef struct {
    uint32_t ip;     // IP in network byte order
    queue q;         // Queue for this IP
} ip_queue_entry;

ip_queue_entry ip_queues[MAX_IP_QUEUE_ENTRIES];
int ip_queue_count = 0;

struct route_table_entry *rtable;
int rtable_len;

struct arp_table_entry *arp_table;
int arp_table_len;

char arp_request[MAX_PACKET_LEN]; // Buffer for arp requests
struct packet {
	char *buf;
	size_t len;
	int interface;
};
typedef struct packet packet;

// Trie node
struct node {
	struct route_table_entry *route;
	struct node* next_node[2];
};
typedef struct node node;
node *root;

int get_ip_queue(uint32_t ip) {
    for (int i = 0; i < ip_queue_count; i++) {
        if (ip_queues[i].ip == ip) {
            return i;
        }
    }
	// IP not found, we should add new entry
    ip_queues[ip_queue_count].ip = ip;
    ip_queues[ip_queue_count].q = create_queue();
    return ip_queue_count++;
}

node *create_node()
{
	node *node = malloc(sizeof(node));
	node->route = NULL;
	node->next_node[0] = node->next_node[1] = NULL;
	return node;
}

/*Insert route in a trie*/
void insert_node(struct route_table_entry *route)
{
	node *cur = root;
	uint32_t prefix_ip = ntohl(route->prefix);
	uint32_t mask = ntohl(route->mask);

	for (int i = 31; i >= 0; i--) {
		int mask_bit = (mask >> i) & 1;
		if (!mask_bit)
			break;
		int prefix_bit = (prefix_ip >> i) & 1;
		if (!cur->next_node[prefix_bit])
			cur->next_node[prefix_bit] = create_node();
		cur = cur->next_node[prefix_bit];
	}
	cur->route = route;
}

struct route_table_entry *find_best_route(uint32_t dest_ip)
{
	node *cur = root;
	uint32_t ip_host = ntohl(dest_ip);

	for (int i = 31; i >= 0; i--) {
		int ip_bit = (ip_host >> i) & 1;
		if (!cur->next_node[ip_bit])
			break;
		cur = cur->next_node[ip_bit];
	}
	if (cur && cur->route)
		return cur->route;
	return NULL;
}

/*Returns ip address of the router interface in network order*/
uint32_t get_ip_address_n(int interface)
{
	const char *ip_str = get_interface_ip(interface);
    struct in_addr ip_addr;
	uint32_t ip_uint;

	inet_pton(AF_INET, ip_str, &ip_addr);
	ip_uint = ip_addr.s_addr;
	return ip_uint;
}

/*Returns ip address of the router interface in host order*/
uint32_t get_ip_address_hs(int interface)
{
	return ntohl(get_ip_address_n(interface));
}

struct arp_table_entry *get_arp_entry(uint32_t given_ip)
{	
	for (int i = 0; i < arp_table_len; i++) {
		if (arp_table[i].ip == given_ip) {
			return &arp_table[i];
		}
	}
	return NULL;
}

void generate_arp_request(struct route_table_entry *route)
{	
	struct ether_hdr *eth_hdr2 = (struct ether_hdr *)arp_request;
	struct arp_hdr *arp_hdr2 = (struct arp_hdr *)(arp_request + sizeof(struct ether_hdr));

	memcpy(eth_hdr2->ethr_dhost, "\xff\xff\xff\xff\xff\xff", 6);
	get_interface_mac(route->interface, eth_hdr2->ethr_shost);
	eth_hdr2->ethr_type = htons(0x806);
	arp_hdr2->hw_len = 6;
	arp_hdr2->hw_type = htons(1);
	arp_hdr2->opcode = htons(1);
	arp_hdr2->proto_len = 4;
	arp_hdr2->proto_type = htons(0x800);
	get_interface_mac(route->interface, arp_hdr2->shwa);
	arp_hdr2->sprotoa =  get_ip_address_n(route->interface);
	memcpy(arp_hdr2->thwa, "\x00\x00\x00\x00\x00\x00", 6);
	arp_hdr2->tprotoa = route->next_hop;
	send_to_link(sizeof(struct ether_hdr) + sizeof(struct arp_hdr), arp_request, route->interface);
}

void handle_arp_request(char *buf, size_t len, int interface)
{
	struct ether_hdr *eth_hdr = (struct ether_hdr *)buf;
	struct arp_hdr *arp_hdr = (struct arp_hdr *)(buf + sizeof(struct ether_hdr));

	uint32_t router_ip = get_ip_address_n(interface);
	if (arp_hdr->tprotoa != router_ip) {
		return; // Not for the router
	}

	// Build Ethernet header
	uint8_t src_mac[6];
	get_interface_mac(interface, src_mac);

	memcpy(eth_hdr->ethr_dhost, eth_hdr->ethr_shost, 6);   // target becomes source
	memcpy(eth_hdr->ethr_shost, src_mac, 6);

	// Build ARP reply
	arp_hdr->opcode = htons(2);
	memcpy(arp_hdr->thwa, arp_hdr->shwa, 6);
	get_interface_mac(interface, arp_hdr->shwa);
	arp_hdr->tprotoa = arp_hdr->sprotoa;
	arp_hdr->sprotoa = router_ip;
	send_to_link(len, buf, interface);
}

void print_mac_address(const unsigned char *mac) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x\n", 
           mac[0], mac[1], mac[2], 
           mac[3], mac[4], mac[5]);
}

void handle_arp_reply(char *buf, size_t len, int interface)
{
	struct ether_hdr *eth_hdr = (struct ether_hdr *)buf;
	struct arp_hdr *arp_hdr = (struct arp_hdr *)(buf + sizeof(struct ether_hdr));
	uint32_t ip_adr = arp_hdr->sprotoa;
	uint16_t bucket_index = get_ip_queue(ip_adr);
	
	arp_table[arp_table_len].ip = ip_adr;
	memcpy(arp_table[arp_table_len].mac, eth_hdr->ethr_shost, 6);
	arp_table_len++;
	while (!queue_empty(ip_queues[bucket_index].q)) {
		packet *p = (packet *)queue_deq(ip_queues[bucket_index].q);
		struct ether_hdr *eth_hdr2 = (struct ether_hdr *)p->buf;
		memcpy(eth_hdr2->ethr_dhost, eth_hdr->ethr_shost, 6);
		send_to_link(p->len, p->buf, p->interface);
	}
}

void handle_arp(char *buf, size_t len, int interface)
{
	struct arp_hdr *arp_hdr = (struct arp_hdr *)(buf + sizeof(struct ether_hdr));
	if (arp_hdr->opcode == ntohs(1))
		handle_arp_request(buf, len, interface);
	else
		handle_arp_reply(buf, len, interface);
}

void send_icmp(char *buf, size_t len, int interface, uint8_t type)
{
	packet *p = malloc(sizeof(packet));
	p->len = len;
	if (type)
		p->len += sizeof(struct icmp_hdr);
	p->interface = interface;
	p->buf = malloc(len);
	memcpy(p->buf, buf, len);
	struct ether_hdr *eth_hdr = (struct ether_hdr *)p->buf;
	struct ip_hdr *ip_hdr = (struct ip_hdr *)(p->buf + sizeof(struct ether_hdr));
	ip_hdr->proto = 1;
	ip_hdr->dest_addr = ip_hdr->source_addr;
	ip_hdr->source_addr = get_ip_address_n(p->interface);
	if (type) {
		ip_hdr->tot_len += sizeof(struct icmp_hdr);
		char *aux_buffer = malloc(64);
		memcpy(aux_buffer, buf + sizeof(struct ether_hdr) + sizeof(struct ip_hdr), 64);
		memcpy(p->buf + sizeof(struct ether_hdr) + sizeof(struct ip_hdr) + sizeof(struct icmp_hdr), aux_buffer, 64);
	}
	struct icmp_hdr *icmp_hdr = (struct icmp_hdr *)(p->buf + sizeof(struct ether_hdr) + sizeof(struct ip_hdr));
	icmp_hdr->mtype = type;
	icmp_hdr->mcode = 0;
	icmp_hdr->check = 0;
	icmp_hdr->check = checksum((uint16_t *)icmp_hdr, len - sizeof(struct ether_hdr) - sizeof(struct ip_hdr));
	memcpy(eth_hdr->ethr_dhost, eth_hdr->ethr_shost, 6);
	get_interface_mac(p->interface, eth_hdr->ethr_shost);
	send_to_link(p->len, p->buf, p->interface);
}

void ip_forward(char *buf, size_t len, int interface)
{
	struct ether_hdr *eth_hdr = (struct ether_hdr *) buf;
	struct ip_hdr *ip_hdr = (struct ip_hdr *)(buf + sizeof(struct ether_hdr));

	uint16_t check = ip_hdr->checksum;
	ip_hdr->checksum = 0;
	check = ntohs(check);

	if (check != checksum((uint16_t *)ip_hdr, sizeof(struct ip_hdr))) {
		return; // Wrong checksum
	}

	check = htons(check);
	ip_hdr->checksum = check;

	uint32_t ip_host = get_ip_address_hs(interface);
	uint32_t dest_ip_net = ip_hdr->dest_addr;
	uint32_t dest_ip_host = ntohl(dest_ip_net);

	if (dest_ip_host == ip_host) {
		if(ip_hdr->proto == 1) { // ICMP
			struct icmp_hdr *icmp_hdr = (struct icmp_hdr *)(buf + sizeof(struct ether_hdr) + sizeof(struct ip_hdr));
			if (icmp_hdr->mtype == 8 && icmp_hdr->mcode == 0) {
				send_icmp(buf, len, interface, 0);
			}
		}
		return;
	} else {
		if (ip_hdr->ttl <= 1) {
			send_icmp(buf, len, interface, 11); // ICMP time exceeded
			return;
		}
		ip_hdr->ttl--;
		ip_hdr->checksum = ~(~ip_hdr->checksum + ~((uint16_t)(ip_hdr->ttl + 1)) + (uint16_t)ip_hdr->ttl) - 1; // Checksum recalculated

		struct route_table_entry* best_route = find_best_route(ip_hdr->dest_addr);
		if (best_route == NULL) {
			send_icmp(buf, len, interface, 3);
			return;
		}
		get_interface_mac(best_route->interface, eth_hdr->ethr_shost);

		struct arp_table_entry *arp_entry = get_arp_entry(best_route->next_hop);
		if (arp_entry == NULL) {
			struct packet *p = malloc(sizeof(packet));
			p->buf = malloc(len);
			memcpy(p->buf, buf, len);
			p->interface = best_route->interface;
			p->len = len;
			int q_ip = get_ip_queue(best_route->next_hop);
			queue_enq(ip_queues[q_ip].q, p);
			generate_arp_request(best_route);
			return;
		}
		memcpy(eth_hdr->ethr_dhost, arp_entry->mac, sizeof(arp_entry->mac)); 
		send_to_link(len, buf, best_route->interface);
	}
}

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argv + 2, argc - 2);
	rtable = malloc(sizeof(struct route_table_entry) * 100000);
	rtable_len = read_rtable(argv[1], rtable);

	arp_table = malloc(sizeof(struct arp_table_entry) * 100);
	// arp_table_len = parse_arp_table("arp_table.txt", arp_table);


	root = create_node();
	for (int i = 0; i < rtable_len; i++)
		insert_node(&rtable[i]);

	while (1) {

		size_t interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		struct ether_hdr* eth_hdr = (struct ether_hdr *)buf;
		if (eth_hdr->ethr_type == ntohs(0x800))
			ip_forward(buf, len, interface);
		else if (eth_hdr->ethr_type == ntohs(0x806))
			handle_arp(buf, len, interface);
	}
}

