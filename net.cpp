#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <errno.h>
#include <netinet/tcp.h>

#include "net.h"

int TCP_server_create_bind_listen(tcp_server *tcp_serv)
{
	tcp_serv->sockfd = socket(AF_INET,SOCK_STREAM, 0);
	setsockopt(tcp_serv->sockfd, SOL_SOCKET, SO_REUSEADDR, &tcp_serv->reuse, sizeof(tcp_serv->reuse));
	memset(&tcp_serv->addr, 0, sizeof(tcp_serv->addr));
	tcp_serv->addr.sin_family = AF_INET;
	tcp_serv->addr.sin_port = htons(tcp_serv->port);
	inet_pton(AF_INET, get_eth_ip(tcp_serv->eth), &tcp_serv->addr.sin_addr);
	bind(tcp_serv->sockfd, (struct sockaddr *)&tcp_serv->addr, sizeof(tcp_serv->addr));
	listen(tcp_serv->sockfd, tcp_serv->backlog);
	return 0;
}

int TCP_server_accept(tcp_server_accept *accept_param)
{
	char str[INET_ADDRSTRLEN];
	memset(str, 0, INET_ADDRSTRLEN);
	fd_set sockset;
	FD_ZERO(&sockset);
	FD_SET(accept_param->sockfd, &sockset);
	if(select(accept_param->sockfd + 1, &sockset, NULL, NULL, NULL) == -1)
	{
		return -1;
	}else
	{
		accept_param->connect_fd = accept(accept_param->sockfd, (struct sockaddr *)&accept_param->client_addr, &accept_param->client_addr_len);
		inet_ntop(AF_INET, &accept_param->client_addr.sin_addr, str, sizeof(str));
		return 0;
	}
}

int TCP_client_connect(tcp_client *tcp_cli)
{
	tcp_cli->sockfd = socket(AF_INET, SOCK_STREAM, 0);
	struct sockaddr_in local;
	memset(&local, 0, sizeof(local));
	local.sin_family = AF_INET;
	local.sin_port = htons(0);
	inet_pton(AF_INET, get_eth_ip(tcp_cli->eth), &local.sin_addr);
	bind(tcp_cli->sockfd, (struct sockaddr *)&local, sizeof(local));
	memset(&tcp_cli->addr, 0, sizeof(tcp_cli->addr));
	tcp_cli->addr.sin_family = AF_INET;
	tcp_cli->addr.sin_port = htons(tcp_cli->port);
	inet_pton(AF_INET, tcp_cli->ip, &tcp_cli->addr.sin_addr);
	connect(tcp_cli->sockfd, (struct sockaddr *)&tcp_cli->addr, sizeof(tcp_cli->addr));
	return 0;
}

int set_sockfd_noblock(int *sockfd)
{
	int flags = fcntl(*sockfd, F_GETFL, 0);
	flags |= O_NONBLOCK;
	fcntl(*sockfd, F_SETFL, flags);
	return 0;
}

int set_sockfd_alive(tcp_alive *alive_value)
{
	setsockopt(*(alive_value->sockfd), SOL_SOCKET, SO_KEEPALIVE, &(alive_value->KeepAlive), sizeof(alive_value->KeepAlive));
	setsockopt(*(alive_value->sockfd), SOL_TCP, TCP_KEEPIDLE, &(alive_value->KeepIdle), sizeof(alive_value->KeepIdle));
	setsockopt(*(alive_value->sockfd), SOL_TCP, TCP_KEEPINTVL, &(alive_value->KeepCount), sizeof(alive_value->KeepCount));
	return 0;
}

int TCP_recv(int sockfd, unsigned char *buff, int length)
{
	int ret = 0;
	int recvlen = 0;
	while(recvlen < length)
	{
		ret = recv(sockfd, buff + recvlen, length - recvlen, 0);
		if(ret == 0)
		{
			return recvlen;
		}else if(ret < 0)
		{
			if(errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)
			{
				return -1;
			}else
			{
				continue;
			}
		}else
		{
			recvlen += ret;
			if(recvlen == length)
			{
				return recvlen;
			}
		}
	}
	return recvlen;
}

int TCP_send(int sockfd, unsigned char *buff, int length)
{
	int ret = 0;
	int sendlen = 0;
	while(sendlen < length)
	{
		ret = send(sockfd, buff + sendlen, length - sendlen, MSG_NOSIGNAL);
		if(ret == 0)
		{
			return sendlen;
		}else if(ret < 0)
		{
			if(errno == EAGAIN)
			{
				continue;
			}else
			{
				return -1;
			}
		}else
		{
			sendlen += ret;
		}
	}
	return sendlen;
}

int UDP_server_create_bind(udp_server *udp_serv)
{
	udp_serv->sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	setsockopt(udp_serv->sockfd, SOL_SOCKET, SO_REUSEADDR, &udp_serv->reuse, sizeof(udp_serv->reuse));
	memset(&udp_serv->addr, 0, sizeof(udp_serv->addr));
	udp_serv->addr.sin_family = AF_INET;
	udp_serv->addr.sin_port = htons(udp_serv->port);
	inet_pton(AF_INET, get_eth_ip(udp_serv->eth), &udp_serv->addr.sin_addr);
	bind(udp_serv->sockfd, (struct sockaddr *)&udp_serv->addr, sizeof(udp_serv->addr));
	return 0;
}

int UDP_client_create_bind(udp_client *udp_cli)
{
	udp_cli->sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	memset(&udp_cli->addr, 0, sizeof(udp_cli->addr));
	udp_cli->addr.sin_family = AF_INET;
	udp_cli->addr.sin_port = htons(udp_cli->port);
	inet_pton(AF_INET, udp_cli->ip, &udp_cli->addr.sin_addr);
	struct sockaddr_in local;
	memset(&local, 0, sizeof(local));
	local.sin_family = AF_INET;
	local.sin_port = htons(0);
	inet_pton(AF_INET, get_eth_ip(udp_cli->eth), &local.sin_addr);
	bind(udp_cli->sockfd, (struct sockaddr *)&local, sizeof(local));
	return 0;
}

int Group_recv_sockfd_create(group_cast_recv *group_recv)
{
	group_recv->sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	setsockopt(group_recv->sockfd, IPPROTO_IP, IP_MULTICAST_LOOP, &group_recv->loop, sizeof(group_recv->loop));
	setsockopt(group_recv->sockfd, SOL_SOCKET, SO_REUSEADDR, &group_recv->reuse, sizeof(group_recv->reuse));
	setsockopt(group_recv->sockfd, SOL_SOCKET, SO_RCVBUF, &group_recv->buffersize, sizeof(group_recv->buffersize));
	memset(&group_recv->addr, 0, sizeof(group_recv->addr));
	group_recv->addr.sin_family = AF_INET;
	group_recv->addr.sin_port = htons(group_recv->port);
	inet_pton(AF_INET, group_recv->ip, &group_recv->addr.sin_addr);
	bind(group_recv->sockfd, (struct sockaddr *)&group_recv->addr, sizeof(group_recv->addr));
	struct ip_mreq mreq;
	memset(&mreq, 0, sizeof(mreq));
	mreq.imr_interface.s_addr = inet_addr(get_eth_ip(group_recv->eth));
	inet_pton(AF_INET, group_recv->ip, &mreq.imr_multiaddr);
	setsockopt(group_recv->sockfd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq));
	return 0;
}

int Group_send_sockfd_create(group_cast_send *group_send)
{
	group_send->sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	setsockopt(group_send->sockfd, IPPROTO_IP, IP_MULTICAST_TTL, &group_send->ttl, sizeof(group_send->ttl));
	memset(&group_send->addr, 0, sizeof(group_send->addr));
	group_send->addr.sin_family = AF_INET;
	group_send->addr.sin_port = htons(group_send->port);
	inet_pton(AF_INET, group_send->ip, &group_send->addr.sin_addr);
	struct sockaddr_in local;
	memset(&local, 0, sizeof(local));
	local.sin_family = AF_INET;
	local.sin_port = htons(0);
	inet_pton(AF_INET, get_eth_ip(group_send->eth), &local.sin_addr);
	bind(group_send->sockfd, (struct sockaddr *)&local, sizeof(local));
	return 0;
}

char *get_eth_ip(char *eth)
{
	struct ifreq ifr;
	struct sockaddr_in sin;
	int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	strncpy(ifr.ifr_name, eth, strlen(eth) + 1);
	ioctl(sockfd, SIOCGIFADDR, &ifr);
	memcpy(&sin, &ifr.ifr_addr, sizeof(sin));
	close(sockfd);
	sockfd = -1;
	return inet_ntoa(sin.sin_addr);
}

void Net_print(unsigned char *buff, int len)
{
	int i = 0;
	printf("\n");
	for(i = 0;i < len; i++)
	{
		if(i % 16 == 0)
		{
			printf("\n");
		}
		printf("0x%02X ", buff[i]);
	}
	printf("\n\n");
}