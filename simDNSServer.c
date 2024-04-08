#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <netpacket/packet.h>
#include <netdb.h>

#define SIM_DNS_PROTO 254
#define INTERFACE "eth0"
#define BUFF_SIZE 65536

#define SRC_IP "127.0.0.1"
#define DEST_IP "127.0.0.1"

#ifdef COLOR
#define ANSI_COLOR_GREEN   "\x1b[32m"
#define ANSI_COLOR_BLUE    "\x1b[34m"
#define ANSI_COLOR_RESET   "\x1b[0m"
#else
#define ANSI_COLOR_GREEN   ""
#define ANSI_COLOR_BLUE    ""
#define ANSI_COLOR_RESET   ""
#endif

struct sim_dns_hdr {

    unsigned short id;
    unsigned char type_and_length;
};

int checksum(struct iphdr *ip_header) {

    unsigned long sum = 0;
    unsigned short *ip_header_short = (unsigned short *)ip_header;
    for (int i = 0; i < sizeof(struct iphdr) / 2; i++) {
        sum += ip_header_short[i];
    }
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return (unsigned short)~sum;
}

int process_packet(unsigned char *eth_frame, int recv_len, struct sim_dns_hdr *sim_dns_header, char **domain_ip) {

    struct ethhdr *eth_header = (struct ethhdr *)eth_frame;
    if (ntohs(eth_header->h_proto) != ETH_P_IP) {
        return 0;
    }

    struct iphdr *ip_header = (struct iphdr *)(eth_frame + sizeof(struct ethhdr));
    if (ip_header->protocol != SIM_DNS_PROTO) {
        return 0;
    }

    struct sim_dns_hdr *sim_dns_packet = (struct sim_dns_hdr *)(eth_frame + sizeof(struct ethhdr) + sizeof(struct iphdr));
    char *domains = (char *)(eth_frame + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct sim_dns_hdr));

    sim_dns_header->id = sim_dns_packet->id;
    
    int type = (sim_dns_packet->type_and_length & 0xF0) >> 4;
    int N = sim_dns_packet->type_and_length & 0x0F;

    if (type == 1) {
        return 0;
    } 

    sim_dns_header->type_and_length = 0x10 | N;
    
    // get ip addresses from domain names
    int len;
    char domain_name[32];
    struct hostent *host;

    for (int i = 0; i < N; i++) {
        len = domains[i * 32] & 0xFF;
        strncpy(domain_name, domains + i * 32 + 1, len);
        domain_name[len] = '\0';

        // get the first ip address from domain name
        host = gethostbyname(domain_name);
        if (host == NULL) {
            domain_ip[i][0] = 0 & 0xFF;
        }
        else {
            struct in_addr **addr_list = (struct in_addr **)host->h_addr_list;
            if (addr_list[0] == NULL) {
                domain_ip[i][0] = 0 & 0xFF;
            }
            else {
                domain_ip[i][0] = 1 & 0xFF;
                memcpy(domain_ip[i] + 1, addr_list[0], 4);
            }
        }
    }

    return 1;
}

int construct_response_payload(unsigned char *eth_frame, struct sim_dns_hdr *sim_dns_header, char **domain_ip) {

    struct sim_dns_hdr *sim_dns_packet = (struct sim_dns_hdr *)(eth_frame + sizeof(struct ethhdr) + sizeof(struct iphdr));
    char *domains = (char *)(eth_frame + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct sim_dns_hdr));

    sim_dns_packet->id = sim_dns_header->id;
    sim_dns_packet->type_and_length = sim_dns_header->type_and_length;

    int N = sim_dns_packet->type_and_length & 0x0F;

    for (int i = 0; i < N; i++) {
        domains[i * 5] = domain_ip[i][0];
        if (domain_ip[i][0] == 1) {
            memcpy(domains + i * 5 + 1, domain_ip[i] + 1, 4);
        }
    }

    return sizeof(struct sim_dns_hdr) + N * 5;
}

void construct_ip_header(unsigned char *eth_frame, int id, int payload_siz) {

    struct iphdr *ip_header = (struct iphdr *)(eth_frame + sizeof(struct ethhdr));  // cast to struct iphdr pointer
    memset(ip_header, 0, sizeof(struct iphdr));                                     // zero out the header
    ip_header->ihl = 5;                                                             // set IP header length
    ip_header->version = 4;                                                         // set IP version
    ip_header->tos = 0;                                                             // set type of service
    ip_header->tot_len = htons(sizeof(struct iphdr) + payload_siz);                 // set total length                 
    ip_header->id = htons(id);                                                      // set identification
    ip_header->frag_off = 0;                                                        // set fragment offset
    ip_header->ttl = 64;                                                            // set time to live
    ip_header->protocol = SIM_DNS_PROTO;                                            // set protocol to 254
    ip_header->saddr = inet_addr(SRC_IP);                                           // set source IP address
    ip_header->daddr = inet_addr(DEST_IP);                                          // set destination IP address    
    ip_header->check = checksum(ip_header);                                         // calculate checksum
}

void construct_eth_header(unsigned char *eth_frame, unsigned char *dest_mac, unsigned char *src_mac) {

    struct ethhdr *eth_header = (struct ethhdr *)eth_frame; // cast to struct ethhdr pointer
    memset(eth_header, 0, sizeof(struct ethhdr));           // zero out the header
    memcpy(eth_header->h_dest, dest_mac, ETH_ALEN);         // set destination MAC address
    memcpy(eth_header->h_source, src_mac, ETH_ALEN);        // set source MAC address
    eth_header->h_proto = htons(ETH_P_IP);                  // set protocol to IP
}

void print_sent_eth_frame(unsigned char *eth_frame, int payload_len) {

    printf(ANSI_COLOR_GREEN "\nSent Packet:\n");
    
    for (int i = 0; i < ETH_ALEN; i++) {
        printf("%02x", eth_frame[i]);
        if (i < ETH_ALEN - 1) {
            printf(":");
        }
    }
    printf(" <- ");
    for (int i = ETH_ALEN; i < 2 * ETH_ALEN; i++) {
        printf("%02x", eth_frame[i]);
        if (i < 2 * ETH_ALEN - 1) {
            printf(":");
        }
    }
    printf("\n%17s -> %s\n", SRC_IP, DEST_IP);
    printf("Payload: %d bytes\n", payload_len);

    struct sim_dns_hdr *sim_dns_header = (struct sim_dns_hdr *)(eth_frame + sizeof(struct ethhdr) + sizeof(struct iphdr));
    
    printf("ID: %d\t", ntohs(sim_dns_header->id));
    printf("Type: %d\t", (sim_dns_header->type_and_length & 0xF0) >> 4);
    int N = sim_dns_header->type_and_length & 0x0F;
    printf("N: %d\n", N);
    char *payload = (char *)(eth_frame + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct sim_dns_hdr));
    for (int i = 0; i < N; i++) {
        printf(ANSI_COLOR_GREEN "Query %d: %d %s\n" ANSI_COLOR_RESET, i + 1, payload[i * 5] & 0xFF, inet_ntoa(*(struct in_addr *)(payload + i * 5 + 1)));
    }
}

void print_recv_eth_frame(unsigned char *eth_frame, int payload_len) {

    printf(ANSI_COLOR_BLUE "\nReceived Packet:\n");

    for (int i = 0; i < ETH_ALEN; i++) {
        printf("%02x", eth_frame[i]);
        if (i < ETH_ALEN - 1) {
            printf(":");
        }
    }
    printf(" <- ");
    for (int i = ETH_ALEN; i < 2 * ETH_ALEN; i++) {
        printf("%02x", eth_frame[i]);
        if (i < 2 * ETH_ALEN - 1) {
            printf(":");
        }
    }

    printf("\n%17s -> %s\n", SRC_IP, DEST_IP);
    printf("Payload: %d bytes\n", payload_len);

    struct sim_dns_hdr *sim_dns_header = (struct sim_dns_hdr *)(eth_frame + sizeof(struct ethhdr) + sizeof(struct iphdr));
    
    printf("ID: %d\t", ntohs(sim_dns_header->id));
    printf("Type: %d\t", (sim_dns_header->type_and_length & 0xF0) >> 4);
    int N = sim_dns_header->type_and_length & 0x0F;
    printf("N: %d\n", N);
    char *payload = (char *)(eth_frame + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct sim_dns_hdr));
    for (int i = 0; i < N; i++) {
        printf(ANSI_COLOR_BLUE "Query %d: %d %s\n" ANSI_COLOR_RESET, i + 1, payload[i * 32] & 0xFF, payload + i * 32 + 1);
    }
}

int main() {

    printf("simDNS server started...\n");

    int raw_sockfd;
    unsigned char eth_frame[ETH_FRAME_LEN];
    unsigned char recv_buff[BUFF_SIZE];
    struct sockaddr_ll cli_addr;
    socklen_t cli_len = sizeof(cli_addr);
    struct sim_dns_hdr sim_dns_header;
    int payload_siz;
    int prev_id = -1;
    
    char **domain_ip;
    domain_ip = (char **)malloc(8 * sizeof(char *));
    for (int i = 0; i < 8; i++) {
        domain_ip[i] = (char *)malloc(5 * sizeof(char));
    }

    // Create a raw socket
    raw_sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (raw_sockfd < 0) {
        perror("socket() failed");
        exit(1);
    }

    // Bind the raw socket to the network interface
    struct sockaddr_ll serv_addr_ll;
    serv_addr_ll.sll_family = AF_PACKET;
    serv_addr_ll.sll_protocol = htons(ETH_P_ALL);
    serv_addr_ll.sll_ifindex = if_nametoindex(INTERFACE);
    if (bind(raw_sockfd, (struct sockaddr *)&serv_addr_ll, sizeof(serv_addr_ll)) < 0) {
        perror("bind() failed");
        exit(1);
    }

    // Receive packets
    int recv_len;
    int filter;
    while (1) {
        recv_len = recvfrom(raw_sockfd, recv_buff, ETH_FRAME_LEN, 0, (struct sockaddr *)&cli_addr, &cli_len);
        if (recv_len < 0) {
            perror("recvfrom() failed");
            close(raw_sockfd);
            exit(1);
        }

        // Process the received packet
        filter = process_packet(recv_buff, recv_len, &sim_dns_header, domain_ip);
        if (filter == 0) {
            continue;
        }

        // Fill response payload
        payload_siz = construct_response_payload(eth_frame, &sim_dns_header, domain_ip);

        // Construct IP header
        if (ntohs(sim_dns_header.id) == prev_id) {
            continue;
        }

        // Print the received Ethernet frame
        print_recv_eth_frame(recv_buff, recv_len - sizeof(struct ethhdr) - sizeof(struct iphdr));
        prev_id = ntohs(sim_dns_header.id);
        
        construct_ip_header(eth_frame, 12345, payload_siz);

        // Get the source MAC address
        struct ifreq ifr;
        memset(&ifr, 0, sizeof(ifr));
        snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), INTERFACE);
        if (ioctl(raw_sockfd, SIOCGIFHWADDR, &ifr) < 0) {
            perror("ioctl() failed");
            close(raw_sockfd);
            exit(1);
        }
        unsigned char src_mac[ETH_ALEN];
        memcpy(src_mac, ifr.ifr_hwaddr.sa_data, ETH_ALEN);

        // Get the destination MAC address from the received packet
        unsigned char dest_mac[ETH_ALEN];
        struct ethhdr *eth_header = (struct ethhdr *)recv_buff;
        memcpy(dest_mac, eth_header->h_source, ETH_ALEN);
        
        // Construct Ethernet header
        construct_eth_header(eth_frame, dest_mac, src_mac);

        // Reply back to the client
        if (sendto(raw_sockfd, eth_frame, recv_len, 0, (struct sockaddr *)&cli_addr, cli_len) < 0) {
            perror("sendto() failed");
            close(raw_sockfd);
            exit(1);
        }

        // Print the sent Ethernet frame
        print_sent_eth_frame(eth_frame, payload_siz);
    }
}