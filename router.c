#include <queue.h>
#include "skel.h"

#define MAX_FILE_DIM 64265
#define LEN 20

struct arp_entry {
	__u32 ip;
	uint8_t mac[6];
};

struct route_table_entry {
	uint32_t prefix;
	uint32_t next_hop;
	uint32_t mask;
	int interface;
} __attribute__((packed));

// citeste tabela de rutare din fisier
void read_route_table(char *filename, struct route_table_entry *rtable, int *rtable_size) {
	FILE *in_file = fopen(filename, "r");
	DIE(in_file == NULL, "Can't open file");
	char prefix[LEN], next_hop[LEN], mask[LEN];  
	int interface;

	while (fscanf(in_file, "%s %s %s %d", prefix, next_hop, mask, &interface) != EOF) {
		rtable[*rtable_size].prefix = inet_addr(prefix);
		rtable[*rtable_size].mask = inet_addr(mask);
		rtable[*rtable_size].next_hop = inet_addr(next_hop);
		rtable[*rtable_size].interface = interface;	

		memset(prefix, 0, sizeof(prefix));
		memset(next_hop, 0, sizeof(next_hop));
		memset(mask, 0, sizeof(next_hop));
		(*rtable_size)++;
	}

	fclose(in_file);
}

// functie comparator pentru a sorta tabela de rutare dupa prefix si dupa masca 
int comparator(const void *a, const void *b) {
	const struct route_table_entry *left = a;
	const struct route_table_entry *right = b;

	if (left->prefix > right->prefix) {
		return 1;
	}
	if (left->prefix < right->prefix) {
		return -1;
	}
	if (left->mask > right->mask) {
		return 1;
	}
	return -1;
}

// cauta intrarea cea mai specifica din tabela de rutare
struct route_table_entry *get_best_route(__u32 dest_ip, struct route_table_entry *rtable, int rtable_size) {
	
	uint32_t max_mask = 0; // masca de dimensiune maxima
	int idx = -1; // indexul rutei matchuite
	int left = 0;
	int right = rtable_size - 1;
	while (left <= right) {
		int mid = (left + right) / 2;
		if ((rtable[mid].mask & dest_ip) == rtable[mid].prefix) {
			if (rtable[mid].mask > max_mask) {
				max_mask = rtable[mid].mask;
				idx = mid;
			}
			left = mid + 1;
		}
		if ((rtable[mid].mask & dest_ip) > rtable[mid].prefix) {
			left = mid + 1;
		} else {
			right = mid - 1;
		}
	}

	if (idx != -1) {
		return &rtable[idx];
	}
	return NULL;
}

// cauta adreasa IP data ca parametru in tabela ARP
struct arp_entry *get_arp_entry(__u32 ip, struct arp_entry *arp_table, int arp_table_len) {
   for (int i = 0; i < arp_table_len; i++) {
    	if (arp_table[i].ip == ip) {
    		return &arp_table[i];
    	}
    }
    return NULL;
}

// adauga IP-ul si adresa MAC in tabela ARP
void update_arp_table(struct arp_entry *arp_table, int *arp_table_size, uint32_t ip_addr, uint8_t *mac_addr) {
	arp_table[*arp_table_size].ip = ip_addr;
	memcpy(arp_table[*arp_table_size].mac, mac_addr, sizeof(arp_table[*arp_table_size].mac));
	(*arp_table_size)++;
}

// transforma o adresa IP ca string intr-un in_addr
struct in_addr cast_str_ip(char *str_ip) {
	struct in_addr ip_addr;
	inet_aton(str_ip, &ip_addr);
	return ip_addr;			
}

// transmite toate pachetele salvate in coada
void send_packets_from_q(queue q, struct route_table_entry *rtable, int rtable_size, struct arp_entry *arp_table, int arp_table_size) {
	while (!queue_empty(q)) {
		packet *pkt = (packet*)queue_deq(q);
		struct ether_header *old_eth_hdr = (struct ether_header*) pkt->payload;
		struct iphdr *ip_hdr = (struct iphdr*) (pkt->payload + sizeof(struct ether_header));
		struct route_table_entry *best_route = get_best_route(ip_hdr->daddr, rtable, rtable_size);
		struct arp_entry *match_arp = get_arp_entry(best_route->next_hop, arp_table, arp_table_size);
		memcpy(old_eth_hdr->ether_dhost, match_arp->mac, sizeof(match_arp->mac));
		send_packet(best_route->interface, pkt);
	}
}

// actualizeaza header-ul de ethernet
void update_ethernet_header(struct ether_header *eth_hdr, uint8_t *new_dhost, int interface) {
	if (new_dhost[0] == '\0') {
		// nu se cunoaste adresa MAC destinatie
		// se pregateste header-ul pentru a trimite un ARP REQUEST ca broadcast
		for (int i = 0; i < 6; i++) {
			eth_hdr->ether_dhost[i] = 0xFF;
		}
		eth_hdr->ether_type = htons(0x0806);
	} else {
		memcpy(eth_hdr->ether_dhost, new_dhost, sizeof(eth_hdr->ether_dhost));
	}
	get_interface_mac(interface, eth_hdr->ether_shost);
}

int main(int argc, char *argv[])
{
	setvbuf(stdout, NULL, _IONBF, 0);
	packet m;
	int rc;

	init(argc - 2, argv + 2);
	
	struct route_table_entry *rtable = malloc(sizeof(struct route_table_entry) * MAX_FILE_DIM);
	DIE(rtable == NULL, "memory");
	int rtable_size = 0;	
	read_route_table(argv[1], rtable, &rtable_size);
	struct arp_entry *arp_table = malloc(sizeof(struct arp_entry) * LEN);
	int arp_table_size = 0;
	qsort(rtable, rtable_size, sizeof(struct route_table_entry), comparator);
	queue q;
	q = queue_create();

	while (1) {
		rc = get_packet(&m);
		DIE(rc < 0, "get_message");
		struct ether_header *eth_hdr = (struct ether_header*) m.payload;
		// urmatorul protocol este de tip ARP
		if (eth_hdr->ether_type == htons(0x0806)) {

			struct arp_header *arp_hdr = parse_arp(m.payload);
			// ARP REQUEST
			if (arp_hdr->op == htons(1)) {
				update_arp_table(arp_table, &arp_table_size, arp_hdr->spa, eth_hdr->ether_shost);
				struct in_addr ip_addr = cast_str_ip(get_interface_ip(m.interface));
				// se verifica daca pachetul este pentru router
				if (arp_hdr->tpa == ip_addr.s_addr) {
					
					// se trimite un raspuns cu adresa MAC aflata
					update_ethernet_header(eth_hdr, eth_hdr->ether_shost, m.interface);
					send_arp(arp_hdr->spa, ip_addr.s_addr, eth_hdr, m.interface, htons(2));
				}
			} 
			// ARP REPLY
			if (arp_hdr->op == htons(2)) { 
					update_arp_table(arp_table, &arp_table_size, arp_hdr->spa, eth_hdr->ether_shost);
					send_packets_from_q(q, rtable, rtable_size, arp_table, arp_table_size);
				}
				continue;
			} 
			
		// urmoatorul protocol este de tip IP
		if (eth_hdr->ether_type == htons(0x0800)) {
			struct iphdr *ip_hdr = (struct iphdr*) (m.payload + sizeof(struct ether_header));
			struct icmphdr *icmp_hdr = parse_icmp(m.payload);
			
			char *ip = get_interface_ip(m.interface);
			// se verifica daca pachetul IP este destinat router-ului si are un pachet ICMP ECHO REQUEST
			if (ip_hdr->daddr == inet_addr(ip) && icmp_hdr->type == 8 && ip_hdr->protocol == 1) {
				send_icmp(ip_hdr->saddr, ip_hdr->daddr, eth_hdr->ether_dhost, eth_hdr->ether_shost, 0, 0, m.interface, 
					icmp_hdr->un.echo.id, icmp_hdr->un.echo.sequence);
				continue;	
			}

			// se verifica ttl-ul
			if (ip_hdr->ttl <= 1) {
				send_icmp_error(ip_hdr->saddr, ip_hdr->daddr, eth_hdr->ether_dhost, eth_hdr->ether_shost, 11, 0, m.interface);
				continue;
			} 

			uint16_t old_checksum = ip_hdr->check;
			ip_hdr->check = 0;
			uint16_t new_checksum = ip_checksum(ip_hdr, sizeof(struct iphdr));
			// se verifica checksum-ul
			if (old_checksum != new_checksum) {
				continue;
			}
			
			// se decrementeaza ttl-ul	
			ip_hdr->ttl--;

			// se recalculeaza checksum-ul
			ip_hdr->check = 0;
			ip_hdr->check = ip_checksum(ip_hdr, sizeof(struct iphdr));

			// se verifica existenta unei rute
			if (get_best_route(ip_hdr->daddr, rtable, rtable_size) == NULL) {
				send_icmp_error(ip_hdr->saddr, ip_hdr->daddr, eth_hdr->ether_dhost, eth_hdr->ether_shost, 3, 0, m.interface);
				continue;
			}

			struct route_table_entry *best_route = get_best_route(ip_hdr->daddr, rtable, rtable_size);
			struct arp_entry *match_arp = get_arp_entry(best_route->next_hop, arp_table, arp_table_size);

			if (match_arp == NULL) {
				// se salveaza pachetul in coada
				packet *copy = (packet *)malloc(sizeof(packet)); 
				memcpy(copy, &m, sizeof(packet));
				queue_enq(q, copy);
				update_ethernet_header(eth_hdr, (uint8_t *)"", m.interface);		
				m.interface = best_route->interface;
				struct in_addr ip_addr = cast_str_ip(get_interface_ip(best_route->interface));
				send_arp(best_route->next_hop, ip_addr.s_addr, eth_hdr, best_route->interface, htons(1));
				continue;
			}
			
			// se trimite pachetul
			update_ethernet_header(eth_hdr, match_arp->mac, best_route->interface);
			send_packet(best_route->interface, &m);
		}
	}
	free(arp_table);
	free(rtable);
}
