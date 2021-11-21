/*
* @file tcp.c
* @author: Wenrui Liu
* @lastEdit: 2021-11-16
* @brief TCP implement
*/
#include "defs.h"
#include "utils.h"
#include "ip.h"
#include "tcp.h"

//to handle with tcp packet with content
void TCPACKHandler(int sockfd,packet_t packet,ip_hdr_t ipHdr,tcp_hdr_t tcpHdr);

socketInfo_t *sockets[MAX_CONNECT_NUM];

int is_SYN(uint16_t flag){
    return (flag&(1<<9));
}
int is_FIN(uint16_t flag){
    return (flag&(1<<8));
}
int is_ACK(uint16_t flag){
    return (flag&(1<<12));
}
uint16_t set_SYN(uint16_t flag){
    return (flag|(1<<9));
}
uint16_t set_FIN(uint16_t flag){
    return (flag|(1<<8));
}
uint16_t set_ACK(uint16_t flag){
    return (flag|(1<<12));
}

//! the buf can be NULL
segment_t buildTCPPacket(int sockfd,const void *buf,int len,
                uint32_t seq_num,uint32_t ack_num,uint16_t flag){
    sockfd = sockfd-SOCKFD_OFFSET;
    segment_t segment;
    tcp_hdr_t hdr;
    segment.len = len+sizeof(tcp_hdr_t);
    segment.buf = malloc(segment.len);
    memset(segment.buf,0,segment.len);
    hdr.src_port = sockets[sockfd]->tcpInfo.srcport;
    hdr.dst_port = sockets[sockfd]->tcpInfo.dstport;
    hdr.ack_num = htonl(seq_num);
    hdr.seq_num = htonl(ack_num);
    hdr.flag = flag;
    memcpy(segment.buf,&hdr,sizeof(tcp_hdr_t));
    if(buf != NULL)
        memcpy(segment.buf+sizeof(tcp_hdr_t),buf,len);
    return segment;
}

//only care about sending TCP Packet, don't care about alarming 
int sendTCPPacket(int sockfd,const void *buf,int len,
                uint32_t seq_num,uint32_t ack_num,uint16_t flag){
    sockfd = sockfd-SOCKFD_OFFSET;
    if(!sockets[sockfd]){
        if(TEST_MODE == 5||TEST_MODE >= 8)
            printf("sockfd doesn't exist\n");
        return -1;
    }
    segment_t segment = buildTCPPacket(sockfd,buf,len,seq_num,ack_num,flag);
    struct in_addr src,dst;
    src.s_addr = sockets[sockfd]->tcpInfo.srcport;
    src.s_addr = sockets[sockfd]->tcpInfo.dstport;
    sendIPPacket(src,dst,0x6,segment.buf,segment.len);
    free(segment.buf);
    return 0;
}

int parseTCPPacket(int sockfd,packet_t packet,ip_hdr_t ipHdr,tcp_hdr_t tcpHdr){
    sockfd = sockfd-SOCKFD_OFFSET;
    int state = sockets[sockfd]->state;
    uint32_t seq = ntohl(tcpHdr.seq_num);
    uint32_t ack = ntohl(tcpHdr.ack_num);
    if(is_SYN(tcpHdr.flag)&&!is_ACK(tcpHdr.flag)){
        if(state == LISTEN||state == SYN_SENT){        //single connect or synchronous
            sockets[sockfd]->tcpInfo.dstaddr = ipHdr.ip_src;
            sockets[sockfd]->tcpInfo.dstport = tcpHdr.src_port;
            uint16_t flag = 0;
            flag = set_ACK(flag);
            flag = set_SYN(flag);
            sendTCPPacket(sockfd,NULL,0,sockets[sockfd]->isn,seq+1,flag);
            sockets[sockfd]->state = SYN_RCVD;      //the order may need to change in multi-thread

        }
    }
    else if(is_SYN(tcpHdr.flag)&&is_ACK(tcpHdr.flag)){
        if(state == SYN_SENT){
            sockets[sockfd]->tcpInfo.dstaddr = ipHdr.ip_src;
            sockets[sockfd]->tcpInfo.dstport = tcpHdr.src_port;
            uint16_t flag = 0;
            flag = set_ACK(flag);
            sendTCPPacket(sockfd,NULL,0,ack,seq+1,flag);
            sockets[sockfd]->state = ESTABLISHED;
        }
    }
    else if(is_FIN(tcpHdr.flag)){
        if(state == ESTABLISHED){
            uint16_t flag = set_ACK(0);
            sendTCPPacket(sockfd,NULL,0,ack,seq+1,flag);
            flag = set_FIN(0);
            sendTCPPacket(sockfd,NULL,0,ack,seq+1,flag);
            sockets[sockfd]->state = LAST_ACK;
        }
        else if(state == FIN_WAIT_2){
            uint16_t flag = set_ACK(0);
            sendTCPPacket(sockfd,NULL,0,ack,seq+1,flag);
            sockets[sockfd]->state = TIME_WAIT;
        }
        else if(state == FIN_WAIT_1){
            uint16_t flag = set_ACK(0);
            sendTCPPacket(sockfd,NULL,0,ack,seq+1,flag);
            sockets[sockfd]->state = CLOSING;
        }
    }
    else if(is_ACK(tcpHdr.flag)){
        if(state == SYN_RCVD){
            sockets[sockfd]->state = ESTABLISHED;
        }
        else if(state == FIN_WAIT_1){
            sockets[sockfd]->state = FIN_WAIT_2;
        }
        else if(state == CLOSING){
            sockets[sockfd]->state = TIME_WAIT;
        }
        else if(state == LAST_ACK){
            sockets[sockfd]->state = CLOSED;
        }
        else if(state == ESTABLISHED){
            int hdrLen = sizeof(eth_hdr_t)+sizeof(ip_hdr_t)+sizeof(tcp_hdr_t);
            int cLen = packet.len-hdrLen-sizeof(checksum_t);
            if(cLen > 0){
                write_rw_buf(&(sockets[sockfd]->receive_buf),packet.packet+hdrLen,cLen);
            }
            if(cLen < 0)
                return -1;
            segment_t content = read_rw_buf_nowait_new(&(sockets[sockfd]->send_buf));
            if(content.len > 0){
                sendTCPPacket(sockfd,content.buf,content.len,ack,seq+cLen,0);
            }
            free(content.buf);
        }
    }
    else{   //a data packet. copy
        int hdrLen = sizeof(eth_hdr_t)+sizeof(ip_hdr_t)+sizeof(tcp_hdr_t);
        int cLen = packet.len-hdrLen-sizeof(checksum_t);
        if(cLen > 0){
            write_rw_buf(&(sockets[sockfd]->receive_buf),packet.packet+hdrLen,cLen);
        }
        if(cLen < 0)
            return -1;
        uint16_t flag = set_ACK(0);
        sendTCPPacket(sockfd,NULL,0,ack,seq+cLen,flag);
    }
}
