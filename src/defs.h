/* *
* @file device.h
* @author: Wenrui Liu
* @lastEdit: 2021-10-25
* @ define and typedef library.
*/
#include<string.h>
#include<stdio.h>
#include<stdlib.h>
#include<stdint.h>
#include<pcap.h>
#include<pthread.h>

#define MAX_DEVICE_NUM 256
#define MAX_DEVICE_NAME_LENGTH 100
#define MAX_ROUTE_TABLE_LENGTH 1024

typedef int deviceID_t;
typedef uint32_t ipv4_t;
typedef int (*frameReceiveCallback) (const void *, int, int);
typedef int (*IPPacketReceiveCallback) (const void *, int);

struct hostInfo{
    frameReceiveCallback frameCallback;
    IPPacketReceiveCallback ipCallback;
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

struct ip_hdr{
    uint8_t ip_version_ihl;
    uint8_t ip_tos;
    uint16_t ip_len;
    uint32_t ip_id_off;
    uint8_t ip_ttl;
    uint8_t ip_p;
    uint16_t ip_sum;
    uint32_t ip_src;
    uint32_t ip_dst;
};

typedef struct ip_hdr ip_hdr_t;

//router table entry
struct rte{
    ipv4_t dst;
    ipv4_t mask;
    ipv4_t next_hop_ip;
    uint8_t next_hop_mac[6];
    int ttl;
};

typedef struct rte rte_t;

struct routeTable{
    rte_t * RTEs[MAX_ROUTE_TABLE_LENGTH];
    pthread_rwlock_t rwlock;
};

typedef struct routeTable routeTable_t;