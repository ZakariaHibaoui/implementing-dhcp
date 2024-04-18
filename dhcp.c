#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <time.h>
#include <sys/time.h>
#include <netinet/in.h>

#define DHCP_SERVER_PORT 67
#define DHCP_CLIENT_PORT 68
#define DHCP_HEADER_SIZE 240
#define DHCP_MAGIC_COOKIE 0x63825363
#define DHCP_OFFER_TIMEOUT 10


typedef struct {
    uint8_t op;         // Message type
    uint8_t htype;     // hardware addr
    uint8_t hlen;         // Length hardware addr
    uint8_t hops;           
    uint32_t xid;          // Id transaction
    uint16_t secs;        // Secondes since runnning
    uint16_t flags;         // Flags
    struct in_addr ciaddr;  // Addr ip client
    struct in_addr yiaddr;  // new addr ip client
    struct in_addr siaddr;  // ip addr of dhcp server
    struct in_addr giaddr;  // addr of relay agent
    uint8_t chaddr[16];     // addr hardware of client
    uint8_t sname[64];      // servername
    uint8_t file[128];      // boot file
    uint32_t magic_cookie;  // CookieDHCP
    uint8_t options[DHCP_HEADER_SIZE];  // Options DHCP
} dhcp_packet;

// Structure dhcp
typedef struct {
    struct in_addr ip_address;
    uint8_t mac_address[6];
    time_t lease_time;
} dhcp_lease;

// baie table DHCP expiration time
dhcp_lease leases[10];
int num_leases = 0;

// udp socket
int create_socket() {
    int sockfd;
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }
    return sockfd;
}

// binding addrwith socket
void bind_socket(int sockfd) {
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr.sin_port = htons(DHCP_SERVER_PORT);

    if (bind(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Socket binding failed");
        close(sockfd);
        exit(EXIT_FAILURE);
    }
}

// request dhcp
void send_dhcp_packet(int sockfd, dhcp_packet *packet, struct sockaddr_in *client_addr, socklen_t client_len) {
    if (sendto(sockfd, packet, sizeof(dhcp_packet), 0, (struct sockaddr *)client_addr, client_len) < 0) {
        perror("Send failed");
        close(sockfd);
        exit(EXIT_FAILURE);
    }
}

// managing the request
void handle_dhcp_request(int sockfd, dhcp_packet *request, struct sockaddr_in *client_addr, socklen_t client_len) {
    dhcp_packet reply;
    memset(&reply, 0, sizeof(reply));

    // cheking ip addr availability
    struct in_addr requested_ip = request->yiaddr;
    int i;
    for (i = 0; i < num_leases; i++) {
        if (leases[i].ip_address.s_addr == requested_ip.s_addr) {
            // if addr ip amready affected, send  message DHCP NAK
            reply.op = 2;  // Boot Reply
            reply.htype = 1;  // Ethernet
            reply.hlen = 6;  //length of hardware addr (Ethernet)
            reply.xid = request->xid;
            reply.flags = request->flags;
            reply.ciaddr = request->ciaddr;
            reply.magic_cookie = htonl(DHCP_MAGIC_COOKIE);

            uint8_t *options_ptr = reply.options;
            *options_ptr++ = 53;  // Type of msg DHCP (DHCP NAK)
            *options_ptr++ = 1;   // Length
            *options_ptr++ = 3;   // DHCP NAK
            *options_ptr++ = 255; 

            printf("Sending DHCP NAK\n");
            send_dhcp_packet(sockfd, &reply, client_addr, client_len);
            return;
        }
    }

    // searching the avilable addr in th table
    struct in_addr available_ip;
    for (i = 0; i < 255; i++) {
        available_ip.s_addr = htonl(0xC0A80100 + i); // 192.168.1.0 - 192.168.1.254
        int j;
        int ip_available = 1;
        for (j = 0; j < num_leases; j++) {
            if (leases[j].ip_address.s_addr == available_ip.s_addr) {
                ip_available = 0;
                break;
            }
        }
        if (ip_available) {
            break;
        }
    }

    if (i == 255) {
        // no ip addr available, senf DHCP NAK
        reply.op = 2;  
        reply.htype = 1;  
        reply.hlen = 6;  
        reply.xid = request->xid;
        reply.flags = request->flags;
        reply.ciaddr = request->ciaddr;
        reply.magic_cookie = htonl(DHCP_MAGIC_COOKIE);

        uint8_t *options_ptr = reply.options;
        *options_ptr++ = 53;  //
        *options_ptr++ = 1;   
        *options_ptr++ = 3;   
        *options_ptr++ = 255; 

        printf("Sending DHCP NAK\n");
        send_dhcp_packet(sockfd, &reply, client_addr, client_len);
        return;
    }

    // Addr IPavailable, send DHCP ACK
    reply.op = 2;  
    reply.htype = 1;  
    reply.hlen = 6;  
    reply.xid = request->xid;
    reply.flags = request->flags;
    reply.ciaddr = request->ciaddr;
    reply.yiaddr = available_ip;
    reply.magic_cookie = htonl(DHCP_MAGIC_COOKIE);

    uint8_t *options_ptr = reply.options;
    *options_ptr++ = 53;  
    *options_ptr++ = 1;   
    *options_ptr++ = 5;   // DHCP ACK
    *options_ptr++ = 1;   // Option Subnet Mask
    *options_ptr++ = 4;   // Longueur
    *options_ptr++ = 255; // 255.255.255.0
    *options_ptr++ = 3;  
    *options_ptr++ = 4;   
    *options_ptr++ = 192; // Addr IProuter (192.168.1.1)
    *options_ptr++ = 168;
    *options_ptr++ = 1;
    *options_ptr++ = 1;
    *options_ptr++ = 6;   
    *options_ptr++ = 4;   
    *options_ptr++ = 8;   
    *options_ptr++ = 8;
    *options_ptr++ = 8;
    *options_ptr++ = 8;
    *options_ptr++ = 255; 

    printf("!---------------Sending DHCP ACK------------------!\n");
    send_dhcp_packet(sockfd, &reply, client_addr, client_len);

    // adding ip addr to table so we can check after if th ip addr is affected or not
    leases[num_leases].ip_address = available_ip;
    memcpy(leases[num_leases].mac_address, request->chaddr, 6);
    leases[num_leases].lease_time = time(NULL) + DHCP_OFFER_TIMEOUT;
    num_leases++;
}


void update_dhcp_leases() {
    int i;
    for (i = 0; i < num_leases; i++) {
        if (time(NULL) >= leases[i].lease_time) {
            printf("Lease expired for IP address %s\n", inet_ntoa(leases[i].ip_address));
            // after cheking the time and addr is not used anymore we delete it from the table
            memmove(&leases[i], &leases[i+1], (num_leases - i - 1) * sizeof(dhcp_lease));
            num_leases--;
            i--;
        }
    }
}

int main() {
    int sockfd = create_socket();
    bind_socket(sockfd);

    printf("----------------DHCP server listening on port---------------!! :: %d\n", DHCP_SERVER_PORT);

    while (1) {
        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(sockfd, &read_fds);

        struct timeval timeout;
        timeout.tv_sec = 5;
        timeout.tv_usec = 0;

        if (select(sockfd + 1, &read_fds, NULL, NULL, &timeout) < 0) {
            perror("!!!!!!!!!Select failed");
            close(sockfd);
            exit(EXIT_FAILURE);
        }

        if (FD_ISSET(sockfd, &read_fds)) {
            dhcp_packet request;
            struct sockaddr_in client_addr;
            socklen_t client_len = sizeof(client_addr);

            if (recvfrom(sockfd, &request, sizeof(request), 0, (struct sockaddr *)&client_addr, &client_len) < 0) {
                perror("Receive failed!!!!!");
                close(sockfd);
                exit(EXIT_FAILURE);
            }

            if (request.op == 1 && request.magic_cookie == htonl(DHCP_MAGIC_COOKIE)) {
                printf("---------Received DHCP request from client\n");
                handle_dhcp_request(sockfd, &request, &client_addr, client_len);
            }
        }

        update_dhcp_leases();
    }

    close(sockfd);
    return 0;
}
