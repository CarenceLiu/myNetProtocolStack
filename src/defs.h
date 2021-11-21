/* *
* @file device.h
* @author: Wenrui Liu
* @lastEdit: 2021-11-17
* @ define and typedef library.
*/
#include<string.h>
#include<stdio.h>
#include<stdlib.h>
#include<stdint.h>
#include<pcap.h>
#include<pthread.h>
#include<sys/types.h>
#include<sys/socket.h>
#include<netdb.h>


#define MAX_DEVICE_NUM 10
#define MAX_DEVICE_NAME_LENGTH 100
#define MAX_ROUTE_TABLE_LENGTH 128
#define MAX_BUFFER_SIZE 512
#define MAX_SOCK_BUFFER_SIZE 256
#define MAX_RW_BUFFER_SIZE 65536
#define MAX_CONNECT_NUM 50
#define MAX_CONTENT_LENGTH 1200
#define DV_PROTOCOL 0xff
#define ETH_TYPE 0X0800
#define PACKET_TTL_DEFAULT 16
#define RTE_TTL_DEFAULT 25
#define SOCKFD_OFFSET 128
#define PORT_OFFSET 10000
#define true 1
#define false 0
#define TEST_MODE 0

typedef int deviceID_t;
typedef uint32_t ipv4_t;
// typedef int (*frameReceiveCallback) (const void *, int, int);
// typedef int (*IPPacketReceiveCallback) (const void *, int);


/*
* link layer
*/
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


/*
* network layer
*/
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
    uint8_t next_hop_mac[6];
    int distance;
};

typedef struct DVInfo DVInfo_t;

struct pcapPacket{
    u_char * packet;
    int len;
    int device_id;
};

typedef struct pcapPacket packet_t;

//NIC buffer
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
    buffer_t packetBuffer;
};
typedef struct hostInfo hostInfo_t;

struct routerInfo{
    buffer_t packetBuffer;
};
typedef struct routerInfo routerInfo_t;



/*
* transport layer
*/

struct socketPacket{
    u_char * packet;        //for free()
    u_char * segment;
    int segment_len;
};

typedef struct socketPacket sockPacket_t;

struct sockBufQueue{
    sockPacket_t buffer[MAX_SOCK_BUFFER_SIZE];
    pthread_mutex_t mutex;
    pthread_cond_t full_cond;
    pthread_cond_t empty_cond;
    int start;
    int end;
};

typedef struct sockBufQueue sockBuffer_t;


struct tcp_hdr{
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq_num;
    uint32_t ack_num;
    uint16_t flag;
    uint16_t window;
    uint32_t blank;
};
typedef struct tcp_hdr tcp_hdr_t;

//TCP state
#define CLOSED 0
#define LISTEN 1
#define SYN_SENT 2
#define SYN_RCVD 3
#define ESTABLISHED 4
#define CLOSE_WAIT 5
#define LAST_ACK 6
#define CLOSING 7
#define FIN_WAIT_1 8
#define FIN_WAIT_2 9
#define TIME_WAIT 10

#define CLIENT 1
#define SERVER 2
#define UNDECIDED 0

struct connectInfo{
    uint32_t srcaddr;
    uint32_t dstaddr;
    uint16_t srcport;
    uint16_t dstport;
};

typedef struct connectInfo connectInfo_t;

struct rw_buffer{       //ring buffer for read/write
    u_char buf[MAX_RW_BUFFER_SIZE];
    int start;
    int end;
    int size;
    pthread_mutex_t lock;
    pthread_cond_t cond;
};

typedef struct rw_buffer rw_buffer_t;

struct socketInfo
{
    int sockfd;
    uint32_t isn;

    rw_buffer_t send_buf;

    rw_buffer_t receive_buf;

    uint16_t window_size;
    sockBuffer_t segmentBuff;
    
    int state;
    int domain;
    int type;
    int protocol;

    struct sockaddr *address;
    socklen_t address_len;

    //TCP
    connectInfo_t tcpInfo;
};

typedef struct socketInfo socketInfo_t;

struct segment{
    u_char * buf;
    int len;
};

typedef struct segment segment_t;