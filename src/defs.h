/* *
* @file device.h
* @author: Wenrui Liu
* @date: 2021-10-16 
* @lastEdit: 2021-10-19
* @ define and typedef library.
*/
#include<string.h>
#include<stdio.h>
#include<stdlib.h>
#include<stdint.h>

#define MAX_DEVICE_NUM 256
#define MAX_DEVICE_NAME_LENGTH 100

typedef int deviceID_t;
typedef uint32_t ipv4_t;
typedef int (*frameReceiveCallback) (const void *, int, int);

struct hostInfo{
    frameReceiveCallback frameCallback;
};
typedef struct hostInfo hostInfo_t;

//device_t defination

struct device{
    deviceID_t id;
    pcap_t *pcapHandler;
    uint8_t mac[6];
    ipv4_t ip;
    char pcapErrBuf[MAX_DEVICE_NUM];
    char deviceName[MAX_DEVICE_NAME_LENGTH];
};

typedef struct device device_t;
extern device_t *currDevices[];


//ethernet frame header defination
struct eth_hdr{
    uint8_t dst[6];
    uint8_t src[6];
    uint16_t type;
};

typedef struct eth_hdr eth_hdr_t;
typedef uint32_t checksum_t;