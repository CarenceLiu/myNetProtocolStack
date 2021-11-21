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

void read_rw_thread(void * t){
    int sockfd = (uint64_t)t;
    int index = sockfd-SOCKFD_OFFSET;
    while(sockets[index]->state != CLOSED){
        clock_t start;
        segment_t content = read_rw_buf_block_new(&(sockets[index]->send_buf));
        uint32_t seq_num = sockets[index]->seq_num;
        int times = 0;
        while(times < 5){
            start = clock();
            sendTCPPacket(sockfd,content.buf,content.len,seq_num,sockets[index]->ack_num,0);
            while((float)(clock()-start)/CLOCKS_PER_SEC < RETRANS_WAIT_TIME&&seq_num == sockets[index]->seq_num);
            if(seq_num != sockets[index]->seq_num){
                break;
            }
            times += 1;
        }
        free(content.buf);
    }
}

int __wrap_socket(int domain, int type, int protocol){
    int index = 0;
    for(index = 0; index < MAX_CONNECT_NUM; index += 1){
        if(!sockets[index])
            break;
    }
    sockets[index] = malloc(sizeof(socketInfo_t));
    sockets[index]->sockfd = index+SOCKFD_OFFSET;
    sockets[index]->seq_num = 0;
    sockets[index]->ack_num = 0;
    initrwBuffer(&(sockets[index]->send_buf));
    initrwBuffer(&(sockets[index]->receive_buf));
    sockets[index]->window_size = MAX_CONTENT_LENGTH;   //simple situation
    sockets[index]->state = CLOSED;
    sockets[index]->domain = domain;
    sockets[index]->type = type;
    sockets[index]->protocol = protocol;
    sockets[index]->bind_flag = 0;
    sockets[index]->tcpInfo.dstaddr = 0;
    sockets[index]->tcpInfo.dstport = 0;
    sockets[index]->tcpInfo.srcaddr = 0;
    sockets[index]->tcpInfo.srcport = 0;
    sockets[index]->rw_flag = 0;
    return index+SOCKFD_OFFSET;
}

int __wrap_bind(int socket, const struct sockaddr *address, socklen_t address_len){
    int index = socket-SOCKFD_OFFSET;
    struct sockaddr_in * addr_in = (struct sockaddr_in *) address;
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
    sockets[index]->rw_flag = 0;
    return 0;
}

int __wrap_connect(int socket, const struct sockaddr* address, socklen_t address_len){
    int index = socket-SOCKFD_OFFSET;
    struct sockaddr_in * addr_in = (struct sockaddr_in *) address;
    uint32_t dst_ip = addr_in->sin_addr.s_addr;
    uint16_t dst_port = addr_in->sin_port;
    sockets[index]->rw_flag = 1;
    sockets[index]->tcpInfo.dstaddr = dst_ip;
    sockets[index]->tcpInfo.dstport = dst_port;
    sockets[index]->tcpInfo.srcaddr = find_available_ip();
    sockets[index]->tcpInfo.srcport = index+PORT_OFFSET;
    if(sockets[index]->tcpInfo.srcaddr == 0)
        return -1;
    clock_t start = clock();
    int syn_send_times = 0;
    while(syn_send_times < 5){      
        uint16_t flag = set_SYN(0);
        sendTCPPacket(socket,NULL,0,sockets[index]->seq_num,sockets[index]->ack_num,flag);
        sockets[index]->state = SYN_SENT;
        //busy waiting
        while((float)(clock()-start)/CLOCKS_PER_SEC < SYN_WAIT_TIME&&sockets[index]->state != ESTABLISHED);
        
        if(sockets[index]->state == ESTABLISHED){
            pthread_create(&(sockets[index]->send_thread),NULL,read_rw_thread,(void *)(sockets[index]->sockfd));
            pthread_detach(sockets[index]->send_thread);
            return 0;
        }
        syn_send_times += 1;
        start = clock();
    }

    //connect error, try 5 times
    free(sockets[index]);
    sockets[index] = NULL;
    return -1;
}

//when a listening socket use accept(), create a new socket for rw
int acc_sock_create(int socket){
    int oldIndex = socket-SOCKFD_OFFSET;
    int newIndex = 0;
    for(;newIndex < MAX_CONNECT_NUM; newIndex += 1){
        if(!sockets[newIndex])
            break;
    }
    if(newIndex == MAX_CONNECT_NUM)
        return -1;
    sockets[newIndex] = malloc(sizeof(socketInfo_t));
    sockets[newIndex]->sockfd = newIndex+SOCKFD_OFFSET;
    sockets[newIndex]->seq_num = 0;
    sockets[newIndex]->ack_num = 0;
    initrwBuffer(&(sockets[newIndex]->send_buf));
    initrwBuffer(&(sockets[newIndex]->receive_buf));
    sockets[newIndex]->window_size = MAX_CONTENT_LENGTH;   //simple situation
    sockets[newIndex]->state = LISTEN;
    sockets[newIndex]->domain = sockets[oldIndex]->domain;
    sockets[newIndex]->type = sockets[oldIndex]->type;
    sockets[newIndex]->protocol = sockets[oldIndex]->protocol;
    sockets[newIndex]->bind_flag = 1;
    sockets[newIndex]->tcpInfo.dstaddr = 0;
    sockets[newIndex]->tcpInfo.dstport = 0;
    sockets[newIndex]->tcpInfo.srcaddr = sockets[oldIndex]->tcpInfo.srcport;
    sockets[newIndex]->tcpInfo.srcport = newIndex+PORT_OFFSET;
    sockets[newIndex]->rw_flag = 1;
    return newIndex;
}

int __wrap_accept(int socket, struct sockaddr* address,socklen_t *address_len){
    int index = socket-SOCKFD_OFFSET;
    if(sockets[index]->bind_flag == 0)
        return -1;
    index = acc_sock_create(socket);
    struct sockaddr_in * addr_in = (struct sockaddr_in *) address;
    uint32_t dst_ip = addr_in->sin_addr.s_addr;
    uint16_t dst_port = addr_in->sin_port;
    sockets[index]->tcpInfo.dstaddr = dst_ip;
    sockets[index]->tcpInfo.dstport = dst_port;
    clock_t start = clock();
    //busy waiting
    while((float)(clock()-start)/CLOCKS_PER_SEC < ACC_SYN_WAIT&&sockets[index]->state == LISTEN);
    if(sockets[index]->state == LISTEN)     //wait out of time
        return -1;
    start = clock();
    while((float)(clock()-start)/CLOCKS_PER_SEC < ACC_ACK_WAIT&&sockets[index]->state != ESTABLISHED);
    if(sockets[index]->state == ESTABLISHED){
        pthread_create(&(sockets[index]->send_thread),NULL,read_rw_thread,(void *)(sockets[index]->sockfd));
        pthread_detach(sockets[index]->send_thread);
        return index+SOCKFD_OFFSET;
    }
    //if accept fail
    sockets[index]->state = LISTEN;
    sockets[index]->tcpInfo.dstaddr = 0;
    sockets[index]->tcpInfo.dstport = 0;
    return -1;
}

ssize_t __wrap_read(int fildes,void *buf, size_t nbyte){
    int index = fildes-SOCKFD_OFFSET;
    return read_rw_buf_nowait_to(&(sockets[index]->receive_buf),buf,nbyte);
}

ssize_t __wrap_write(int fildes, const void* buf, size_t nbyte){
    int index = fildes-SOCKFD_OFFSET;
    write_rw_buf(&(sockets[index]->send_buf),buf,nbyte);
    return nbyte;
}

int __wrap_close(int fildes){
    int index = fildes-SOCKFD_OFFSET;
    if(sockets[index]->state != ESTABLISHED&&sockets[index]->state != LAST_ACK&&sockets[index]->state != CLOSED)
        return -1;
    if(sockets[index]->state == ESTABLISHED){
        uint16_t flag = set_FIN(0);
        int fin_times = 0;
        clock_t start;
        //retrans if miss
        while(fin_times < 3){
            sendTCPPacket(fildes,NULL,0,sockets[index]->seq_num,sockets[index]->ack_num,flag);
            start = clock();
            while((float)(clock()-start)/CLOCKS_PER_SEC < FIN_ACK_WAIT||sockets[index]->state != TIME_WAIT);
            if(sockets[index]->state == TIME_WAIT){
                break;
            }
            fin_times += 1;
        }
    }
    else if(sockets[index]->state == CLOSED){
        if(pthread_cancel(sockets[index]->send_thread) == 0){
            free(sockets[index]);
            sockets[index] = NULL;
        }
    }
    return 0;
}

int __wrap_getaddrinfo(const char* node, const char* service, const struct addrinfo* hints,struct addrinfo **res){
    uint32_t ipv4;
    uint16_t port;
    memcpy((void *)(&ipv4),(void *)node,sizeof(uint32_t));
    memcpy((void *)(&port),(void *)service,sizeof(uint16_t));
    res = malloc(sizeof(struct addrinfo *));
    struct addrinfo * current = NULL;
    for(int i = 0 ; i < MAX_CONNECT_NUM; i+=1){
        if(sockets[i]){
            if(sockets[i]->tcpInfo.srcport == port&&sockets[i]->tcpInfo.srcaddr == ipv4){
                if(current == NULL){
                    res[0] = malloc(sizeof(struct addrinfo));
                    current = res[0];
                }
                else{
                    current->ai_next = malloc(sizeof(struct addrinfo));
                    current = current->ai_next;
                }
                current->ai_addrlen = 6;
                current->ai_family = sockets[i]->domain;
                current->ai_protocol = sockets[i]->protocol;
                current->ai_socktype = sockets[i]->type;
                current->ai_addr = malloc(sizeof(struct sockaddr));
                struct sockaddr_in * s =(struct sockaddr_in *)current->ai_addr;
                s->sin_addr.s_addr = ipv4;
                s->sin_port = port;
            }
        }
    }
    return 0;
}