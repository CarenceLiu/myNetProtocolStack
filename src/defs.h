/* *
* @file device.h
* @author: Wenrui Liu
* @lastEdit: 2021-10-28
* @ define and typedef library.
*/
#include<string.h>
#include<stdio.h>
#include<stdlib.h>
#include<stdint.h>
#include<pcap.h>
#include<pthread.h>

#define MAX_DEVICE_NUM 10
#define MAX_DEVICE_NAME_LENGTH 100
#define MAX_ROUTE_TABLE_LENGTH 128
#define MAX_BUFFER_SIZE 1024
#define DV_PROTOCOL 0xff
#define ETH_TYPE 0X0800
#define PACKET_TTL_DEFAULT 16
#define RTE_TTL_DEFAULT 25
#define true 1
#define false 0
#define TEST_MODE 0

typedef int deviceID_t;
typedef uint32_t ipv4_t;
typedef int (*frameReceiveCallback) (const void *, int, int);
typedef int (*IPPacketReceiveCallback) (const void *, int);

//device_t defination

struct device{
    deviceID_t id;
    pcap_t *pcapHandler;
    uint8_t mac[6];
    ipv4_t ip;
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
    uint8_t next_hop_mac[6];
    int distance;
    int src_device_id;
    int ttl;
};

typedef struct rte rte_t;

struct routeTable{
    rte_t * RTEs[MAX_ROUTE_TABLE_LENGTH];
    pthread_rwlock_t rwlock;
};

typedef struct routeTable routeTable_t;


//for a DVPacket, some DVInfo packets are the content
//record the send mac's infomation

//DV packet content
struct DVInfo{
    ipv4_t dst;
    ipv4_t mask;
    int distance;
};

typedef struct DVInfo DVInfo_t;

struct pcapPacket{
    u_char * packet;
    int len;
    int device_id;
};

typedef struct pcapPacket packet_t;

struct bufferQueue{
    packet_t buffer[MAX_BUFFER_SIZE];
    pthread_mutex_t mutex;
    pthread_cond_t full_cond;
    pthread_cond_t empty_cond;
    int start;
    int end;
};

typedef struct bufferQueue buffer_t;


struct hostInfo{
    frameReceiveCallback frameCallback;
    IPPacketReceiveCallback ipCallback;
    buffer_t packetBuffer;
};
typedef struct hostInfo hostInfo_t;

struct routerInfo{
    frameReceiveCallback frameCallback;
    buffer_t packetBuffer;
};
typedef struct routerInfo routerInfo_t;
