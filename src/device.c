/* *
* @file device.c
* @author: Wenrui Liu
* @date: 2021-10-16 
* @lastEdit: 2021-10-17
*/

#include<pcap/pcap.h>
#include<ifaddrs.h>
#include<netpacket/packet.h>
#include "defs.h"
#include "device.h"


device_t *currDevices[MAX_DEVICE_NUM] = {};

uint8_t * getMac(const char * device){
    int ret = -1;
    uint8_t * deviceMac = NULL;
    struct ifaddrs *ifaddr = NULL,*ifa;
    if(getifaddrs(&ifaddr) == -1){
        fprintf(stderr,"[device.c getMac]\n");
        fprintf(stderr,"Error: getifaddrs error\n");
        return -1;
    }
    for(ifa = ifaddr; ifa; ifa=ifa->ifa_next){
        int flag = 0;
        if(!strcmp(ifa->ifa_name, device) && ifa->ifa_addr->sa_family == AF_PACKET) 
            flag = 1;
        if(flag){
            deviceMac = malloc(6);
            struct sockaddr_ll *sockAddr = (struct sockaddr_ll*)(ifa->ifa_addr);
            memcpy(deviceMac,sockAddr->sll_addr,6);
            return deviceMac;
        }
    }
    return NULL;
}

int addDevice(const char * device){
    if(!device){
        fprintf(stderr,"[device.c addDevice]\n");
        fprintf(stderr,"Error: device is NULL\n");
        return -1;
    }
    int deviceID = -1,ret;
    pcap_t *handler = NULL;
    char * errBuf[PCAP_ERRBUF_SIZE]= {};
    
    //create pcap handler
    handler = pcap_create(device,errBuf);

    if(handler == NULL){
        fprintf(stderr,"[device.c addDevice]\n");
        fprintf(stderr,"Error: pcap_create error, %s\n",errBuf);
        return -1;
    }

    ret = pcap_activate(handler);
    if(ret < 0){
        fprintf(stderr,"[device.c addDevice]\n");
        fprintf(stderr,"Error: pcap_activate error\n");
        pcap_close(handler);
        return -1;
    }

    //find an available position for this device
    for(int i = 0; i < MAX_DEVICE_NUM; i++){
        if(currDevices[i] == NULL){
            currDevices[i] = malloc(sizeof(device_t));
            uint8_t *mac = getMac(device);

            if(!mac){
                fprintf(stderr,"[device.c addDevice]\n");
                fprintf(stderr,"Error: getMac error\n");
                pcap_close(handler);
                free(currDevices[i]);
                currDevices[i] = NULL;
                return -1;
            }

            currDevices[i]->id = i;
            currDevices[i]->pcapHandler = handler;
            memcpy(currDevices[i]->mac,mac,6);
            free(mac);
            memcpy(currDevices[i]->pcapErrBuf,errBuf,PCAP_ERRBUF_SIZE);

            if(MAX_DEVICE_NAME_LENGTH < strlen(device)+1){
                fprintf(stderr,"[device.c addDevice]\n");
                fprintf(stderr,"Error: device name is too long\n");
                pcap_close(handler);
                free(currDevices[i]);
                currDevices[i] = NULL;
                return -1;
            }

            memcpy(currDevices[i]->deviceName,device,strlen(device)+1);
            memset(currDevices[i]->ip,0,sizeof(ipv4_t));
            memset(currDevices[i]->mac,0,sizeof(uint8_t)*6);
            deviceID = i;

            break;
        }
    }
    return deviceID;
}


int findDevice(const char * device){
    deviceID_t deviceID = -1;
    for(int i = 0 ; i < MAX_DEVICE_NUM; i += 1){
        if(currDevices[i] != NULL){
            if(!strcmp(device,currDevices[i]->deviceName)){
                return i;
            }
        }
    }
    return -1;
}