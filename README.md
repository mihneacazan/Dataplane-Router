# Dataplane Router in C

## Functionality
The code implements a router in C that provides IPv4 packet forwarding functionality based on a routing table and manages the reception/transmission of ARP/ICMP packets.

## Algorithms and Data Structures Used
- **Trie for the routing table**
    - Each entry in the routing table is inserted into the trie based on its prefix and mask value. For each entry, we perform steps equal to the number of 1s in the mask, so the time complexity is O(N * 32). The same limit applies to the space complexity, but in reality, it will be much smaller, as many addresses share common bits.
    - To search for an address, we perform a maximum of 32 steps, so the search complexity is O(32).
- **IP Queues for ARP**
    - Whenever the router needs to send a packet to a specific IP address for which it does not know the MAC address, the packet is placed in a queue associated with that IP. When the router receives an ARP reply, all packets from that queue are sent.
    - Since the number of nodes in the simulated network for this assignment is small, an array of queues was used, where search and insertion have linear complexity.
    - The queues contain elements of type `struct packet`, an auxiliary structure that stores the packet's content, length, and the interface it should be sent on.

## Implemented Protocols
- **IP forwarding**
    - The router inspects each IP packet and checks if the destination address matches one of its own interfaces.
        - If it does and the packet is an ICMP Echo Request, it responds with an ICMP Echo Reply.
        - If not, it searches for the best forwarding route in the trie and sends the packet on the respective interface.
    - It checks and updates the packet's TTL field. If TTL ≤ 1, it generates an ICMP Time Exceeded message.
    - If no route to the destination exists, an ICMP Destination Unreachable message is sent.
- **ARP**
    - If there is no ARP entry for the next-hop IP, an ARP Request is generated, and the packet is added to the queue associated with that IP.
    - Upon receiving an ARP Reply, the router:
        - Updates the ARP table.
        - Sends all waiting packets from the queue associated with that IP.
- **ICMP**
    - Responds to ICMP Echo Request (ping) packets with an Echo Reply if they are destined for the router.
    - Generates ICMP messages for:
        - Time Exceeded, type 11
        - Destination Unreachable, type 3
## Main Structures
- **`struct node`** - A node in the trie for the routing table.
- **`struct packet`** – Stores the data of a packet in the waiting queue (buffer, length, interface).
- **`ip_queue_entry`** – Associates an IP address with a packet queue.
- **`arp_table_entry`** – Stores IP ↔ MAC associations.
- **`route_table_entry`** - An entry in the routing table (prefix, mask, next hop, interface).
