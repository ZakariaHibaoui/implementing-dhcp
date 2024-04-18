#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define DHCP_CLIENT_PORT 68
#define DHCP_SERVER_PORT 67
#define DHCP_MAGIC_COOKIE 0x63825363

// Structure representing a DHCP packet
typedef struct {
    uint8_t op;             // Message type (1 for DHCP request)
    uint8_t htype;          // Hardware address type (1 for Ethernet)
    uint8_t hlen;           // Hardware address length (6 for Ethernet)
    uint8_t hops;           
    uint32_t xid;           // Transaction ID
    uint16_t secs;          // Seconds  since running
    uint16_t flags;         // Flags
    struct in_addr ciaddr;  // Client IP address
    struct in_addr yiaddr;  // new  IP addr affected by dhcp server
    struct in_addr siaddr;  // IP add of DHCP server
    struct in_addr giaddr;  // Relay agent IP address
    uint8_t chaddr[16];     // Client hardware address
    uint8_t sname[64];      // Optional server host name
    uint8_t file[128];      // Boot file name
    uint32_t magic_cookie;  // Magic cookie (0x63825363)
    uint8_t options[64];    // DHCP options
} dhcp_packet;

int main() {
    int sockfd;
    struct sockaddr_in server_addr;

    // Creating a UDP socket
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    // Configure the server address
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(DHCP_SERVER_PORT);
    server_addr.sin_addr.s_addr = INADDR_ANY;

    dhcp_packet request;
    memset(&request, 0, sizeof(request));
    request.op = 1;                                     // DHCP request message
    request.htype = 1;                                  // Ethernet hardware type
    request.hlen = 6;                                   // Ethernet hardware addr length
    request.xid = htonl(getpid());                      // Transaction ID
    request.magic_cookie = htonl(DHCP_MAGIC_COOKIE);    // Magic cookie for DHCP

    // Send DHCP request
    if (sendto(sockfd, &request, sizeof(request), 0, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Send failed");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    printf("DHCP request sent\n");

    // Wait for DHCP server response
    dhcp_packet response;
    socklen_t server_len = sizeof(server_addr);
    recvfrom(sockfd, &response, sizeof(response), 0, (struct sockaddr *)&server_addr, &server_len);

    // Check if IP address is assigned
    if (response.yiaddr.s_addr != 0) {
        // ip addr succefully affected
        printf("Assigned IP address: %s\n", inet_ntoa(response.yiaddr));
    } else {
        // ip non affected
        printf("No IP address assigned by DHCP server.\n");
	exit(EXIT_FAILURE);
    }

    close(sockfd);
    return 0;
}
