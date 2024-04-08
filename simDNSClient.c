#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <netpacket/packet.h>
#include <fcntl.h>
#include <time.h>

#define SIM_DNS_PROTO 254
#define INTERFACE "eth0"
#define SRC_IP "127.0.0.1"
#define DEST_IP "127.0.0.1"
#define TIMEOUT 5
#define PENDING_QUERIES 8
#define input_len 100

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

struct pending_query {

    short num_retries;
    int N;
    char *queries[8];
};

short identity = 0;

void parse_mac_addr(char *mac_str, unsigned char mac[6]) {

    char *token = strtok(mac_str, ":");
    for (int i = 0; i < 6; i++) {
        mac[i] = strtol(token, NULL, 16);
        token = strtok(NULL, ":");
    }
}

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

// returns size of payload
int construct_payload(unsigned char *eth_frame, short id, int N, char *queries[], struct pending_query *pending_queries) {

    // fill pending query
    int retransmit = 0;

    if (pending_queries[id].num_retries == -1) pending_queries[id].num_retries = 0;
    else retransmit = 1;

    pending_queries[id].N = N;

    // fill payload
    memset(eth_frame, 0, ETH_FRAME_LEN);

    struct sim_dns_hdr *sim_dns_header = (struct sim_dns_hdr *)(eth_frame + sizeof(struct ethhdr) + sizeof(struct iphdr));

    sim_dns_header->id = htons(id);
    sim_dns_header->type_and_length = 0x00 | N;

    char *payload = (char *)(eth_frame + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct sim_dns_hdr));

    for (int i = 0; i < N; i++) {
        unsigned char len = strlen(queries[i]) & 0xFF;
        payload[i*32] = len; // 1 byte for length
        memcpy(payload + i*32 + 1, queries[i], len);
        
        if (retransmit) continue;

        memset(pending_queries[id].queries[i], '\0', 32);
        memcpy(pending_queries[id].queries[i], queries[i], len);
    }

    return sizeof(struct sim_dns_hdr) + N*32;
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

int process_packet(unsigned char *eth_frame, int recv_len, struct pending_query *pending_queries) {

    struct ethhdr *eth_header = (struct ethhdr *)eth_frame;
    if (ntohs(eth_header->h_proto) != ETH_P_IP) {
        return 0;
    }

    struct iphdr *ip_header = (struct iphdr *)(eth_frame + sizeof(struct ethhdr));
    if (ip_header->protocol != SIM_DNS_PROTO) {
        return 0;
    }

    struct sim_dns_hdr *sim_dns_header = (struct sim_dns_hdr *)(eth_frame + sizeof(struct ethhdr) + sizeof(struct iphdr));
    char *payload = (char *)(eth_frame + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct sim_dns_hdr));

    short id = ntohs(sim_dns_header->id);
    int type = (sim_dns_header->type_and_length & 0xF0) >> 4;
    int N = sim_dns_header->type_and_length & 0x0F;

    if (type == 0) {
        return 0;
    }

    if (pending_queries[id].num_retries == -1) {
        return 0;
    }

    printf("\n");
    printf("Query ID            : %d\n", id);
    printf("Total Query Strings : %d\n\n", N);
    for (int i=0; i<N; ++i) {
        int flag = payload[i*5] & 0xFF;
        if (flag == 0) {
            printf("%-32s IP not found\n", pending_queries[id].queries[i]);
        } else {
            printf("%-32s %s\n", pending_queries[id].queries[i], inet_ntoa(*(struct in_addr *)(payload + i*5 + 1)));
        }
    }
    printf("\n");

    pending_queries[id].num_retries = -1;

    return 1;
}

short get_id(struct pending_query *pending_queries) {
    short id = identity;

    for (short i=0; i<PENDING_QUERIES; ++i) {
        if (i != id && pending_queries[i].num_retries == -1) {
            identity = i;
            break;
        }
    }
    if (identity == id) {
        return -1;
    }

    return id;
}

void print_sent_eth_frame(unsigned char *eth_frame, int payload_len) {

    printf(ANSI_COLOR_BLUE "\nSent Packet:\n");

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
        printf("Query %d: %d %s\n", i + 1, payload[i * 32] & 0xFF, payload + i * 32 + 1);
    }
    printf(ANSI_COLOR_RESET "\n");
}

int main(int argc, char *argv[]) {

    char *destination_mac = NULL;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <dest_mac>\n", argv[0]);
    } else {
        destination_mac = argv[1];
    }

    // Variable declarations
    int raw_sockfd;
    struct sockaddr_ll server_addr;
    unsigned char *src_mac;
    unsigned char dest_mac[ETH_ALEN];
    struct ifreq ifr;
    unsigned char eth_frame[ETH_FRAME_LEN];
    int payload_len;

    // Create a raw socket
    raw_sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (raw_sockfd < 0) {
        perror("socket() failed");
        exit(1);
    }

    // Make the socket non-blocking
    fcntl(raw_sockfd, F_SETFL, O_NONBLOCK);

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sll_family = AF_PACKET;
    server_addr.sll_protocol = htons(ETH_P_ALL);
    server_addr.sll_ifindex = if_nametoindex(INTERFACE);
    server_addr.sll_halen = ETH_ALEN;

    // Get source MAC address
    strcpy(ifr.ifr_name, INTERFACE);
    if (ioctl(raw_sockfd, SIOCGIFHWADDR, &ifr) < 0) {
        perror("ioctl failed");
        close(raw_sockfd);
        exit(EXIT_FAILURE);
    }
    src_mac = (unsigned char *)ifr.ifr_hwaddr.sa_data;

    // Get destination MAC address
    if (destination_mac == NULL) {
        printf("Using broadcast MAC address: ff:ff:ff:ff:ff:ff\n");
        memset(dest_mac, 0xFF, ETH_ALEN);
    } else {
        parse_mac_addr(destination_mac, dest_mac);
    }

    // Select loop
    fd_set readfds;
    int activity = -1;
    struct timeval timeout;
    char input[input_len];
    char *token;
    int N;
    char *queries[8];
    int recv_len;

    struct pending_query pending_queries[PENDING_QUERIES];
    for (int i = 0; i < PENDING_QUERIES; i++) {
        pending_queries[i].num_retries = -1;
        for (int j = 0; j < 8; j++) {
            pending_queries[i].queries[j] = (char *)malloc(32 * sizeof(char));
        }
    }

    while (1) {
        FD_ZERO(&readfds);
        FD_SET(raw_sockfd, &readfds);
        FD_SET(0, &readfds);

        timeout.tv_sec = TIMEOUT;
        timeout.tv_usec = 0;

        if (activity != 0) {
            printf("client> "); 
            fflush(stdout);
        }

        activity = select(raw_sockfd + 1, &readfds, NULL, NULL, &timeout);
        if (activity < 0) {
            perror("select failed");
            close(raw_sockfd);
            exit(EXIT_FAILURE);
        }
        else if (activity == 0) {
            for (short i=0; i<PENDING_QUERIES; ++i) {
                if (pending_queries[i].num_retries != -1) {
                    if (pending_queries[i].num_retries == 3) {

                        printf("\n");
                        printf("Query ID            : %d\n", i);
                        printf("Total Query Strings : %d\n\n", pending_queries[i].N);
                        for (int j=0; j<pending_queries[i].N; ++j) {
                            printf("%-32s Request timed out\n", pending_queries[i].queries[j]);
                        }
                        printf("\n");
                        pending_queries[i].num_retries = -1;
                    } else {

                        pending_queries[i].num_retries++;
                        payload_len = construct_payload(eth_frame, i, pending_queries[i].N, pending_queries[i].queries, pending_queries);
                        if (payload_len == 0) {
                            printf("Too many pending queries\n");
                            continue;
                        }

                        construct_ip_header(eth_frame, i, payload_len);
                        construct_eth_header(eth_frame, dest_mac, src_mac);

                        if (sendto(raw_sockfd, eth_frame, payload_len + sizeof(struct iphdr) + sizeof(struct ethhdr), 0, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
                            perror("sendto failed");
                            close(raw_sockfd);
                            exit(EXIT_FAILURE);
                        }

                        printf("\nRetransmitting query ID: %d Retries: %d\n", i, pending_queries[i].num_retries);
                        print_sent_eth_frame(eth_frame, payload_len);
                        fflush(stdout);
                    }
                }
            }
        }
        else {
            // input from user
            if (FD_ISSET(0, &readfds)) {
                fgets(input, input_len, stdin);
                input[strcspn(input, "\n")] = 0;
                
                if (strlen(input) < 4) {
                    printf("Usage: getIP <# queries> <domain-1> <domain-2> ... <domain-N>\n");
                    continue;
                }

                if (strncmp(input, "EXIT", 4) == 0) {
                    break;
                }

                token = strtok(input, " ");
                if (strncmp(token, "getIP", 5) == 0) {

                    token = strtok(NULL, " ");
                    if (token == NULL) {
                        printf("Usage: getIP <# queries>\n");
                        continue;
                    }

                    N = atoi(token);
                    if (N < 0 || N >= 8) {
                        printf("Invalid number of queries\n");
                        continue;
                    }

                    for (int i=0; i<N; ++i) {
                        token = strtok(NULL, " ");
                        if (token == NULL) {
                            printf("Usage: getIP <# queries> <domain-1> <domain-2> ... <domain-N>\n");
                            break;
                        }
                        queries[i] = token;
                    }

                    // Fill payload
                    short id = get_id(pending_queries);
                    if (id == -1) {
                        printf("Too many pending queries\n");
                        continue;
                    }
                    payload_len = construct_payload(eth_frame, id, N, queries, pending_queries);

                    // Fill ip header
                    construct_ip_header(eth_frame, 12345, payload_len);

                    // Fill eth header
                    construct_eth_header(eth_frame, dest_mac, src_mac);

                    // Send the packet
                    if (sendto(raw_sockfd, eth_frame, payload_len + sizeof(struct iphdr) + sizeof(struct ethhdr), 0, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
                        perror("sendto failed");
                        close(raw_sockfd);
                        exit(EXIT_FAILURE);
                    }

                    // Print sent ethernet frame
                    print_sent_eth_frame(eth_frame, payload_len);

                }
                else {
                    printf("Invalid command.\nCorrect usage: getIP N <domain-1> <domain-2> ... <domain-N>\n");
                }
            }

            // receive packet
            if (FD_ISSET(raw_sockfd, &readfds)) {

                recv_len = recvfrom(raw_sockfd, eth_frame, ETH_FRAME_LEN, 0, NULL, NULL);
                if (recv_len < 0) {
                    perror("recvfrom failed");
                    close(raw_sockfd);
                    exit(EXIT_FAILURE);
                }

                // Process the received packet
                activity = process_packet(eth_frame, recv_len, pending_queries);
            }
        }
    }

    // Close the socket
    close(raw_sockfd);
}