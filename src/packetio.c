/*
* @file packetio.c
* @author: Wenrui Liu
* @lastEdit: 2021-10-19
* @brief supporting sending/receiving Ethernet II frames.
*/
#include<netinet/ether.h>
#include "defs.h"
#include "utils.h"
#include "device.h"
#include "packetio.h"

struct frameInfo{
    char * frame;
    int frameLength;
};

typedef struct frameInfo frameInfo_t;

extern device_t *currDevices[];
extern hostInfo_t host;

uint16_t changeTypeEndian(uint16_t n){
    uint16_t ret = ((n&0xff)<<8)|((n&(0xff<<8))>>8);
    return ret;
}

frameInfo_t buildFrame(const void * buf, int len, int ethtype, const void * destmac, int id){
    frameInfo_t ethFrame;
    uint16_t type = changeTypeEndian(ethtype);
    ethFrame.frameLength = len+sizeof(eth_hdr_t)+sizeof(checksum_t);
    ethFrame.frame = malloc(ethFrame.frameLength);
    
    memset(ethFrame.frame,0,ethFrame.frameLength);
    memcpy(ethFrame.frame,destmac,6);
    memcpy(ethFrame.frame+6,currDevices[id]->mac,6);
    memcpy(ethFrame.frame+12,&type,2);
    memcpy(ethFrame.frame+14,buf,len);
    //last 4 bytes are 0, checksum

    return ethFrame;
}

int sendFrame(const void * buf, int len, int ethtype, const void * destmac, int id){
    frameInfo_t ethFrame = buildFrame(buf,len,ethtype,destmac,id);
    int ret = pcap_sendpacket(currDevices[id]->pcapHandler,ethFrame.frame,ethFrame.frameLength);
    free(ethFrame.frame);
    return ret;
}


int setFrameReceiveCallback(frameReceiveCallback callback){
    host.frameCallback = callback;
    return 0;
}

// int main(){
//     addDevice("lo");
//     addDevice("ens33");
//     sendFrame("hello",5,0,currDevices[0]->mac,0);
//     return 0;
// }