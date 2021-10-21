/* *
* @file device.c
* @author: Wenrui Liu
* @lastEdit: 2021-10-19
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
        return NULL;
    }
    for(ifa = ifaddr; ifa; ifa=ifa->ifa_next){
        if(!strcmp(ifa->ifa_name, device) && ifa->ifa_addr->sa_family == AF_PACKET){
            deviceMac = malloc(6);
            struct sockaddr_ll *sockAddr = (struct sockaddr_ll*)(ifa->ifa_addr);
            // printf("MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",sockAddr->sll_addr[0],
            // sockAddr->sll_addr[1],sockAddr->sll_addr[2],sockAddr->sll_addr[3],
            // sockAddr->sll_addr[4],sockAddr->sll_addr[5]);
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
    char errBuf[PCAP_ERRBUF_SIZE]= {};
    
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

            //set information
            currDevices[i]->id = i;
            currDevices[i]->pcapHandler = handler;
            currDevices[i]->ip = 0;
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


//add all device in currDevices and print them, just for CP1
void showAllDevice(){

    //way 1 segmentation fault
    // char err[PCAP_ERRBUF_SIZE];
    // pcap_if_t * ifaddr,*ifa;
    // if(pcap_findalldevs(&ifaddr,err) < 0){
    //     return;
    // }
    // for(ifa = ifaddr; ifa ;ifa = ifa->next){
    //         struct sockaddr * tmp = ifa->addresses->addr;
    //         if(tmp->sa_family == AF_PACKET){
    //             printf("Name: %s\n",ifa->name);
    //             printf("MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",tmp->sa_data[0],
    //             tmp->sa_data[1],tmp->sa_data[2],tmp->sa_data[3],
    //             tmp->sa_data[4],tmp->sa_data[5]);
    //         }
    // }

    //way 2
    struct ifaddrs *ifaddr = NULL,*ifa;
    if(getifaddrs(&ifaddr) == -1){
        fprintf(stderr,"[device.c getMac]\n");
        fprintf(stderr,"Error: getifaddrs error\n");
        return;
    }
    //traversal all suitable eth device
    for(ifa = ifaddr; ifa!=NULL; ifa=ifa->ifa_next){
        if(ifa->ifa_addr->sa_family == AF_PACKET)
            addDevice(ifa->ifa_name);
    }
    for(int i = 0; i < MAX_DEVICE_NUM; i += 1){
        if(currDevices[i]){
            printf("[device: %d]\n",currDevices[i]->id);
            printf("Name: %s\n",currDevices[i]->deviceName);
            printf("MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",currDevices[i]->mac[0],
            currDevices[i]->mac[1],currDevices[i]->mac[2],currDevices[i]->mac[3],
            currDevices[i]->mac[4],currDevices[i]->mac[5]);
        }
    }
}

// int main(){
//     showAllDevice();
//     return 0;
// }