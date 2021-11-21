/*
* @file socket.c
* @author: Wenrui Liu
* @lastEdit: 2021-11-21
* @brief socket implement
*/

#include "defs.h"
#include "utils.h"
#include "ip.h"
#include "tcp.h"
#include "socket.h"

extern socketInfo_t *sockets[];

int __wrap_socket(int domain, int type, int protocol){
    int index = 0;
    for(index = 0; index < MAX_CONNECT_NUM; index += 1){
        if(!sockets[index])
            break;
    }
    sockets[index] = malloc(sizeof(socketInfo_t));
    sockets[index]->sockfd = index+SOCKFD_OFFSET;
    sockets[index]->isn = 0;
    initrwBuffer(&(sockets[index]->send_buf));
    initrwBuffer(&(sockets[index]->receive_buf));
    sockets[index]->window_size = MAX_CONTENT_LENGTH;   //simple situation
    sockets[index]->state = CLOSED;
    sockets[index]->domain = domain;
    sockets[index]->type = type;
    sockets[index]->protocol = protocol;
    sockets[index]->bind_flag = 0;
    return index+SOCKFD_OFFSET;
}

int __wrap_bind(int socket, const struct sockaddr *address, socklen_t address_len){
    int index = socket-SOCKFD_OFFSET;
    struct sockaddr_in * addr_in;
    uint32_t ip = addr_in->sin_addr.s_addr;
    uint16_t port = addr_in->sin_port;
    if(check_ipv4_available(ip) == 0)
        return -1;
    for(int i = 0 ; i < MAX_CONNECT_NUM; i += 1){   //check if socket exists
        if(sockets[i])
            if(sockets[i]->tcpInfo.srcaddr == ip&&sockets[i]->tcpInfo.srcport == port)
                return -1;
    }
    if(!sockets[index])
        return -1;
    if(sockets[index]->state != CLOSED)
        return -1;
    if(address->sa_family != AF_INET)
        return -1;
    sockets[index]->tcpInfo.srcaddr = ip;
    sockets[index]->tcpInfo.srcport = port;
    sockets[index]->bind_flag = 1;
    return 0;
}

int __wrap_listen(int socket, int backlog){
    int index = socket-SOCKFD_OFFSET;
    if(!sockets[index]||backlog != 1)
        return -1;
    if(sockets[index]->state != CLOSED||sockets[index]->bind_flag != 1)
        return -1;
    sockets[index]->state = LISTEN;
    return 0;
}

int __wrap_connect(int socket, const struct sockaddr* address, socklen_t address_len){
    
}