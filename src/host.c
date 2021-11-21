/*
* @file host.c
* @author: Wenrui Liu
* @lastEdit: 2021-10-19
* @brief the host program
*/
#include<netinet/ether.h>
#include<netinet/ip.h>
#include "defs.h"
#include "utils.h"
#include "device.h"
#include "packetio.h"
#include "ip.h"
#include "tcp.h"
#include "socket.h"

hostInfo_t host;

extern routeTable_t routingTable_exact;
extern routeTable_t routingTable_lpm;
extern device_t *currDevices[];
extern socketInfo_t *sockets[];

void * pcapReceive(void * t){
    int device_id = (uint64_t)t;
    if(TEST_MODE == 1|| TEST_MODE >=8){
        printf("receiving thread of device %d has created\n",device_id);
    }
    pcap_t *handler = currDevices[device_id]->pcapHandler;
    char errorBuf[PCAP_ERRBUF_SIZE];
    while(1){
        packet_t tmp;
        const u_char * packet;
        struct pcap_pkthdr header;
        packet = pcap_next(handler,&header);
        if(packet){
            if(TEST_MODE == 1|| TEST_MODE >=8){
                printf("[host.c] pcapReceive receive a packet and malloc\n");
            }
            u_char * content = malloc(header.len);
            memcpy(content,packet,header.len);
            tmp.len = header.len;
            tmp.packet = content;
            push(&(host.packetBuffer),tmp);
        }
    }
}

void showIPPacket(packet_t packet){
    eth_hdr_t ethHdr;
    ip_hdr_t ipHdr;
    memcpy(&ethHdr,packet.packet,sizeof(eth_hdr_t));
    memcpy(&ipHdr,packet.packet+sizeof(eth_hdr_t),sizeof(ip_hdr_t));
    printf("Receiving a packet\n");
    printf("ethernet header:\n");
    printf("src mac: %02x:%02x:%02x:%02x:%02x:%02x\n",ethHdr.src[0],ethHdr.src[1],
        ethHdr.src[2],ethHdr.src[3],ethHdr.src[4],ethHdr.src[5]);
    printf("dst mac: %02x:%02x:%02x:%02x:%02x:%02x\n",ethHdr.dst[0],ethHdr.dst[1],
        ethHdr.dst[2],ethHdr.dst[3],ethHdr.dst[4],ethHdr.dst[5]);
    printf("ip src: %d.%d.%d.%d\n",(ipHdr.ip_src&0xff),((ipHdr.ip_src>>8)&0xff),((ipHdr.ip_src>>16)&0xff),((ipHdr.ip_src>>24)&0xff));
    printf("ip dst: %d.%d.%d.%d\n",(ipHdr.ip_dst&0xff),((ipHdr.ip_dst>>8)&0xff),((ipHdr.ip_dst>>16)&0xff),((ipHdr.ip_dst>>24)&0xff));
    printf("content:%s\n",packet.packet+sizeof(eth_hdr_t)+sizeof(ip_hdr_t));
    printf("the complete packet: ");
    for(int i = 0; i < packet.len; i+= 1){
        printf("%02x ",(u_char)packet.packet[i]);
    }
    printf("\n\n");
}

//network packet
void parsePacket(){
    //warning: free the u_char *
    if(TEST_MODE == 5|| TEST_MODE >=8)
        printf("try pop buffer and parse Packet\n");
    packet_t packet = pop(&(host.packetBuffer));
    ip_hdr_t ipHdr;
    memcpy(&ipHdr,packet.packet+sizeof(eth_hdr_t),sizeof(ip_hdr_t));
    if(ipHdr.ip_p == DV_PROTOCOL){
        if(TEST_MODE == 5|| TEST_MODE >=8)
            printf("parse DVPacket\n");
        // showIPPacket(packet);
        refreshRoutingTable(packet);
    }
    else if(ipHdr.ip_p == 0x6){     //tcp segment
        tcp_hdr_t tcpHdr;
        memcpy(&tcpHdr,packet.packet+sizeof(eth_hdr_t)+sizeof(ip_hdr_t),sizeof(tcp_hdr_t));
        for(int i = 0; i < MAX_CONNECT_NUM; i += 1){
            if(sockets[i]){
                if(sockets[i]->tcpInfo.srcaddr == ipHdr.ip_dst&&sockets[i]->tcpInfo.srcport == tcpHdr.dst_port
                    &&sockets[i]->rw_flag){
                    // sockPush(&(sockets[i]->segmentBuff),spacket);
                    parseTCPPacket(sockets[i]->sockfd,packet,ipHdr,tcpHdr);
                    break;
                }
            }
        }
    }
    free(packet.packet);

}


int main(){

    addAllDevices();
    initBuffer(&(host.packetBuffer));
    initRoutingTable();
    
    //pthread to receive packets from different NICs.
    for(int i = 0; i < MAX_DEVICE_NUM; i+= 1){
        int * t = (int *)(uint64_t)i;
        if(currDevices[i]){
            pthread_t p;
            pthread_create(&p,NULL,pcapReceive,(void *)t);
            pthread_detach(p);
        }
    }

    //pthread to refresh routing table
    pthread_t refresh;
    pthread_create(&refresh,NULL,periodRefreshRT,NULL);
    pthread_detach(refresh);

    //pthread to parse packets
    while(1){
        parsePacket();
    }

    return 0;
}