#ifndef NET_H_
#define NET_H_

typedef struct TCP_SERVER{
	int reuse;
	int port;
	int backlog;
	struct sockaddr_in addr;
	char *eth;
	int sockfd;
}tcp_server;

typedef struct TCP_SERVER_ACCEPT{
	int sockfd;
	struct sockaddr_in client_addr;
	socklen_t client_addr_len;
	int connect_fd;
}tcp_server_accept;

typedef struct TCP_ALIVE{
	int *sockfd;
	int KeepAlive;
	int KeepIdle;
	int KeepInterval;
	int KeepCount;
}tcp_alive;

typedef struct TCP_CLIENT{
	char *ip;
	int port;
	struct sockaddr_in addr;
	char *eth;
	int sockfd;
}tcp_client;

typedef struct UDP_SERVER{
	int reuse;
	int port;
	struct sockaddr_in addr;
	char *eth;
	int sockfd;
}udp_server;

typedef struct UDP_CLIENT{
	char *ip;
	int port;
	struct sockaddr_in addr;
	char *eth;
	int sockfd;
}udp_client;

typedef struct GROUP_CAST_RECV{
	int reuse;
	int loop;
	int buffersize;
	char *ip;
	int port;
	struct sockaddr_in addr;
	char *eth;
	int sockfd;
}group_cast_recv;

typedef struct GROUP_CAST_SEND{
	int ttl;
	char *ip;
	int port;
	struct sockaddr_in addr;
	char *eth;
	int sockfd;
}group_cast_send;

int TCP_server_create_bind_listen(tcp_server *tcp_serv);
int TCP_server_accept(tcp_server_accept *accept_param);
int TCP_client_connect(tcp_client *tcp_cli);
int set_sockfd_noblock(int *sockfd);
int set_sockfd_alive(tcp_alive *alive_value);
int TCP_send(int sockfd, unsigned char *buff, int length);
int TCP_recv(int sockfd, unsigned char *buff, int length);
int UDP_server_create_bind(udp_server *udp_serv);
int UDP_client_create_bind(udp_client *udp_cli);
int Group_recv_sockfd_create(group_cast_recv *group_recv);
int Group_send_sockfd_create(group_cast_send *group_send);
char *get_eth_ip(char *eth);
void Net_print(unsigned char *buff, int len);

#endif 
