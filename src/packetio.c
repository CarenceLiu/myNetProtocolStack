/*
* @file packetio.c
* @author: Wenrui Liu
* @date: 2021-10-16 
* @lastEdit: 2021-10-17
* @brief supporting sending/receiving Ethernet II frames.
*/
#include<netinet/ether.h>
#include<pcap.h>
#include "defs.h"
#include "utils.h"
#include "device.h"

struct frameInfo{
    char * frame;
    int frameLength;
};

typedef struct frameInfo frameInfo_t;

uint16_t changeTypeEndian(uint16_t n){
    uint16_t ret = ((n&0xff)<<8)|((n&(0xff<<8))>>8);
    return ret;
}

frameInfo_t buildFrame(const void * buf, int len, int ethtype, const void * destmac, int id){
    frameInfo_t ethFrame;
    uint16_t type = changeTypeEndian(ethtype);
    ethFrame.frameLength = len+sizeof(eth_hdr_t)+sizeof(checksum_t);
    ethFrame.frame = malloc(ethFrame.frameLength);
    memset(ethFrame.frame,0,sizeof(ethFrame.frame));

}

int sendFrame(const void * buf, int len, int ethtype, const void * destmac, int id){
    
}