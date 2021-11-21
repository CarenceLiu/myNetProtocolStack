/* *
* @file ip.h
* @author: Wenrui Liu
* @lastEdit: 2021-10-28
*/

#include<netinet/ip.h>
#include<unistd.h>
#include "defs.h"
#include "utils.h"
#include "device.h"
#include "packetio.h"
#include "ip.h"

//waring: all ip addresses are little-endian.

extern device_t *currDevices[];

struct packetInfo{
    u_char * packet;
    int packetLength;
};

typedef struct packetInfo packetInfo_t;

struct DVContent{
    u_char * buf;
    int len;
};

typedef struct DVContent DVContent_t; 

routeTable_t routingTable_exact;
routeTable_t routingTable_lpm;


packetInfo_t buildPacket(const struct in_addr src, const struct in_addr dest, int proto, const void * buf, int len,int ttl){
    packetInfo_t ipPacket;
    ip_hdr_t ipHdr;
    ipPacket.packetLength = len +sizeof(ip_hdr_t);
    if(TEST_MODE == 4|| TEST_MODE >=8){
        printf("[ip.c] buildPacket malloc\n");
    }
    ipPacket.packet = malloc(ipPacket.packetLength);
    ipHdr.ip_version_ihl = 0x45;
    ipHdr.ip_tos = 0;
    ipHdr.ip_len = changeTypeEndian((uint16_t)ipPacket.packetLength);
    ipHdr.ip_id_off = 0;
    ipHdr.ip_ttl = PACKET_TTL_DEFAULT;
    ipHdr.ip_p = proto;
    ipHdr.ip_sum = 0;
    ipHdr.ip_src = src.s_addr;
    ipHdr.ip_dst = dest.s_addr;
    
    memset(ipPacket.packet,0,ipPacket.packetLength);
    memcpy(ipPacket.packet,(u_char *)(&ipHdr),sizeof(ip_hdr_t));
    memcpy(ipPacket.packet+sizeof(ip_hdr_t),buf,len);

    return ipPacket;
    
}

/*
* control plane
*/

void initRoutingTable(){
    pthread_rwlock_init(&(routingTable_exact.rwlock),NULL);
    pthread_rwlock_init(&(routingTable_lpm.rwlock),NULL);
    for(int i = 0; i < MAX_ROUTE_TABLE_LENGTH; i += 1){
        routingTable_exact.RTEs[i] = NULL;
    }
    for(int i = 0; i < MAX_ROUTE_TABLE_LENGTH; i += 1){
        routingTable_lpm.RTEs[i] = NULL;
    }

    for(int i = 0; i < MAX_DEVICE_NUM; i += 1){
        if(currDevices[i]){
            if(TEST_MODE == 4|| TEST_MODE >=8){
                printf("[ip.c] initRoutingTable malloc\n");
            }
            routingTable_exact.RTEs[i] = malloc(sizeof(rte_t));
            routingTable_exact.RTEs[i]->distance = 0;
            routingTable_exact.RTEs[i]->mask = 0xffffffff;
            routingTable_exact.RTEs[i]->dst = currDevices[i]->ip;
            routingTable_exact.RTEs[i]->src_device_id = i;
            memcpy(&(routingTable_exact.RTEs[i]->next_hop_mac),&(currDevices[i]->mac),6);
            routingTable_exact.RTEs[i]->ttl = 0x7fffffff;
            if(TEST_MODE == 4|| TEST_MODE >=8){
                printf("[ip.c] initRoutingTable add RTE %d.%d.%d.%d\n",
                (currDevices[i]->ip&0xff),((currDevices[i]->ip>>8)&0xff),((currDevices[i]->ip>>16)&0xff),((currDevices[i]->ip>>24)&0xff));
            }
        }
    }

    if(TEST_MODE == 4|| TEST_MODE >=8){
        printf("[ip.c] initRoutingTable finish\n");
    }
    return;
}

//the sender's IP and mac can get from the IP/Eth header.
DVContent_t buildDVPacket(){
    DVContent_t res;
    DVInfo_t tmp_info;
    //send mac info

    pthread_rwlock_rdlock(&(routingTable_exact.rwlock));
    if(TEST_MODE == 4|| TEST_MODE >=8){
        printf("[ip.c] buildDVPacket get routing table rdlock\n");
    }
    int sum = 0;
    for(int i = 0; i < MAX_ROUTE_TABLE_LENGTH; i += 1){
        if(routingTable_exact.RTEs[i]&&routingTable_exact.RTEs[i]->ttl > 0)
            sum += 1;
    }
    sum = sum*sizeof(DVInfo_t);
    res.len = sum;
    if(TEST_MODE == 4|| TEST_MODE >=8){
        printf("[ip.c] buildDVPacket malloc\n");
    }
    res.buf = malloc(sum);
    int p = 0;
    for(int i = 0; i < MAX_ROUTE_TABLE_LENGTH; i += 1){
        if(routingTable_exact.RTEs[i]&&routingTable_exact.RTEs[i]->ttl > 0){
            tmp_info.distance = routingTable_exact.RTEs[i]->distance;
            tmp_info.dst = routingTable_exact.RTEs[i]->dst;
            tmp_info.mask = routingTable_exact.RTEs[i]->mask;
            memcpy(tmp_info.next_hop_mac,routingTable_exact.RTEs[i]->next_hop_mac,6);
            memcpy(res.buf+p,&(tmp_info),sizeof(DVInfo_t));
            if(TEST_MODE == 7|| TEST_MODE >=8){
                printf("[ip.c] buildDVPacket add DV content %d %d %d\n",tmp_info.dst,tmp_info.mask,tmp_info.distance);
            }
            p += sizeof(DVInfo_t);
        }
    }
    pthread_rwlock_unlock(&routingTable_exact.rwlock);
    if(TEST_MODE == 4|| TEST_MODE >=8){
        printf("[ip.c] buildDVPacket give up routing table rdlock\n");
    }
    return res;
}

int sendDVPackets(){
    int ret = 0;
    DVContent_t content = buildDVPacket();
    uint8_t mac[6] = {0xff,0xff,0xff,0xff,0xff,0xff};
    for(int i = 0; i < MAX_DEVICE_NUM; i += 1){
        if(currDevices[i]){
            struct in_addr src;
            struct in_addr dst;
            src.s_addr = currDevices[i]->ip;
            dst.s_addr = 0xffffffff;
            packetInfo_t ipPacket = buildPacket(src,dst,DV_PROTOCOL,content.buf,content.len,PACKET_TTL_DEFAULT);
            // printf("send DV Packet: ");
            ret |= sendFrame(ipPacket.packet,ipPacket.packetLength,ETH_TYPE,mac,i);
            free(ipPacket.packet);
        }
    }
    free(content.buf);
}

void refreshRoutingTable(packet_t packet){
    eth_hdr_t ethHdr;
    ip_hdr_t ipHdr;
    int pointer = sizeof(eth_hdr_t)+sizeof(ip_hdr_t);
    uint32_t dst,mask;
    uint8_t next_hop_mac[6];
    int distance,flag;
    int src_device_id = packet.device_id;

    memcpy(&ethHdr,packet.packet,sizeof(eth_hdr_t));
    memcpy(&ipHdr,packet.packet+sizeof(eth_hdr_t),sizeof(ip_hdr_t));
    dst = ipHdr.ip_src;
    mask = 0xffffffff;
    distance = 1;
    memcpy(next_hop_mac,ethHdr.src,6);

    pthread_rwlock_wrlock(&(routingTable_exact.rwlock));
    if(TEST_MODE == 4|| TEST_MODE >=8){
        printf("[ip.c] refreshRoutingTable get routing table wrlock\n");
    }
    flag = 1;
    for(int i = 0; i < MAX_ROUTE_TABLE_LENGTH; i += 1){
        if(routingTable_exact.RTEs[i]&&routingTable_exact.RTEs[i]->dst == dst){
            flag = 0;
            routingTable_exact.RTEs[i]->distance = distance;
            routingTable_exact.RTEs[i]->mask = mask;
            routingTable_exact.RTEs[i]->src_device_id = src_device_id;
            routingTable_exact.RTEs[i]->ttl = RTE_TTL_DEFAULT;
            memcpy(routingTable_exact.RTEs[i]->next_hop_mac,next_hop_mac,6);
            break;
        }
    }

    if(flag){
        for(int i = 0; i < MAX_ROUTE_TABLE_LENGTH; i += 1){
            if(!routingTable_exact.RTEs[i]){
                if(TEST_MODE == 4|| TEST_MODE >=8){
                    printf("[ip.c] refreshRoutingTable_1 malloc\n");
                }
                routingTable_exact.RTEs[i] = malloc(sizeof(rte_t));
                routingTable_exact.RTEs[i]->dst = dst;
                routingTable_exact.RTEs[i]->distance = distance;
                routingTable_exact.RTEs[i]->mask = mask;
                routingTable_exact.RTEs[i]->src_device_id = src_device_id;
                routingTable_exact.RTEs[i]->ttl = RTE_TTL_DEFAULT;
                if(TEST_MODE == 4|| TEST_MODE >=8){
                    printf("[ip.c] refreshRoutingTable_1 add rte %d\n",dst);
                }
                memcpy(routingTable_exact.RTEs[i]->next_hop_mac,next_hop_mac,6);
                break;
            }
        }
    }

    for(;pointer < packet.len-4; pointer += sizeof(DVInfo_t)){
        DVInfo_t DVPacket;
        memcpy(&DVPacket,packet.packet+pointer,sizeof(DVInfo_t));
        dst = DVPacket.dst;
        mask = DVPacket.mask;
        distance = DVPacket.distance+1;
        uint8_t next_next_hop_mac[6];
        memcpy(next_next_hop_mac,DVPacket.next_hop_mac,6);

        if(macEqual(next_next_hop_mac,currDevices[src_device_id]->mac)){
            continue;
        }

        flag = 1;
        for(int i = 0; i < MAX_ROUTE_TABLE_LENGTH; i += 1){
            if(routingTable_exact.RTEs[i]&&routingTable_exact.RTEs[i]->dst == dst){
                flag = 0;
                if(routingTable_exact.RTEs[i]->distance > distance){
                    routingTable_exact.RTEs[i]->distance = distance;
                    routingTable_exact.RTEs[i]->mask = mask;
                    routingTable_exact.RTEs[i]->src_device_id = src_device_id;
                    routingTable_exact.RTEs[i]->ttl = RTE_TTL_DEFAULT;
                    memcpy(routingTable_exact.RTEs[i]->next_hop_mac,next_hop_mac,6);
                }
                break;
            }
        }

        if(flag){
            for(int i = 0; i < MAX_ROUTE_TABLE_LENGTH; i += 1){
                if(!routingTable_exact.RTEs[i]){
                    if(TEST_MODE == 4|| TEST_MODE >=8){
                        printf("[ip.c] refreshRoutingTable_2 malloc\n");
                    }
                    routingTable_exact.RTEs[i] = malloc(sizeof(rte_t));
                    routingTable_exact.RTEs[i]->dst = dst;
                    routingTable_exact.RTEs[i]->distance = distance;
                    routingTable_exact.RTEs[i]->mask = mask;
                    routingTable_exact.RTEs[i]->src_device_id = src_device_id;
                    routingTable_exact.RTEs[i]->ttl = RTE_TTL_DEFAULT;
                    if(TEST_MODE == 4|| TEST_MODE >=8){
                        printf("[ip.c] refreshRoutingTable_2 add rte %d\n",dst);
                    }
                    memcpy(routingTable_exact.RTEs[i]->next_hop_mac,next_hop_mac,6);
                    break;
                }
            }
        }
    }
    pthread_rwlock_unlock(&(routingTable_exact.rwlock));
    if(TEST_MODE == 4|| TEST_MODE >=8){
        printf("[ip.c] refreshRoutingTable give up routing table wrlock\n");
    }
}


int setRoutingTable(const struct in_addr dest, const struct in_addr mask, const void * nextHopMAC, const char * device,int distance){
    pthread_rwlock_wrlock(&(routingTable_exact.rwlock));
    if(TEST_MODE == 4|| TEST_MODE >=8){
        printf("[ip.c] setRoutingTable get routing table wrlock\n");
    }
    for(int i = 0; i < MAX_ROUTE_TABLE_LENGTH; i+= 1){
        if(!routingTable_exact.RTEs[i]){
            if(TEST_MODE == 4|| TEST_MODE >=8){
                printf("[ip.c] setRoutingTable malloc\n");
            }
            routingTable_exact.RTEs[i] = malloc(sizeof(rte_t));
            routingTable_exact.RTEs[i]->dst = dest.s_addr;
            routingTable_exact.RTEs[i]->mask = mask.s_addr;
            routingTable_exact.RTEs[i]->src_device_id = findDevice(device);
            memcpy(&(routingTable_exact.RTEs[i]->next_hop_mac),nextHopMAC,6);
            routingTable_exact.RTEs[i]->distance = distance;
            routingTable_exact.RTEs[i]->ttl = RTE_TTL_DEFAULT;
            break;
        }
    }
    pthread_rwlock_unlock(&(routingTable_exact.rwlock));
    if(TEST_MODE == 4|| TEST_MODE >=8){
        printf("[ip.c] setRoutingTable give up routing table wrlock\n");
    }
}

//only care about exact match
void * periodRefreshRT(){
    uint32_t clock_p = 0;
    if(TEST_MODE == 4|| TEST_MODE >=8){
        printf("[ip.c] periodRefreshRT begin\n");
    }
    while(1){
        sleep(1);
        clock_p += 1;
        pthread_rwlock_wrlock(&(routingTable_exact.rwlock));
        if(TEST_MODE == 4|| TEST_MODE >=8){
            printf("[ip.c] periodRefresh get routing table wrlock\n");
        }
        for(int i = 0; i < MAX_ROUTE_TABLE_LENGTH; i += 1){
            //ttl = 0x7fffffff is the host's ip route entry
            if(routingTable_exact.RTEs[i]&&routingTable_exact.RTEs[i]->ttl != 0x7fffffff){
                routingTable_exact.RTEs[i]->ttl -= 1;
                if(routingTable_exact.RTEs[i]->ttl <= 0){
                    free(routingTable_exact.RTEs[i]);
                    routingTable_exact.RTEs[i] = NULL;
                }
            }
        }
        pthread_rwlock_unlock(&(routingTable_exact.rwlock));
        if(TEST_MODE == 4|| TEST_MODE >=8){
            printf("[ip.c] periodRefresh give up routing table wrlock\n");
        }

        if(clock_p%5 == 0){
            sendDVPackets();
        }

        if(clock_p%10 == 0){
            showRoutingTable();
        }
    }
}

void showRoutingTable(){
    pthread_rwlock_rdlock(&(routingTable_exact.rwlock));
    if(TEST_MODE == 4|| TEST_MODE >=8){
        printf("[ip.c] showRoutingTable get routing table rdlock\n");
    }
    printf("|dst ip | mask | next hop mac | distance | ttl |\n");
    for(int i = 0; i < MAX_ROUTE_TABLE_LENGTH; i += 1){
        if(routingTable_exact.RTEs[i]){
            int ip = routingTable_exact.RTEs[i]->dst;
            int mask = routingTable_exact.RTEs[i]->mask;
            printf("%d.%d.%d.%d ",(ip&0xff),((ip>>8)&0xff),((ip>>16)&0xff),((ip>>24)&0xff));
            printf("%d.%d.%d.%d ",(mask&0xff),((mask>>8)&0xff),((mask>>16)&0xff),((mask>>24)&0xff));
            printf("%02X:%02X:%02X:%02X:%02X:%02X ",routingTable_exact.RTEs[i]->next_hop_mac[0],
            routingTable_exact.RTEs[i]->next_hop_mac[1],routingTable_exact.RTEs[i]->next_hop_mac[2],routingTable_exact.RTEs[i]->next_hop_mac[3],
            routingTable_exact.RTEs[i]->next_hop_mac[4],routingTable_exact.RTEs[i]->next_hop_mac[5]);
            printf("%d %d\n",routingTable_exact.RTEs[i]->distance,routingTable_exact.RTEs[i]->ttl);
        }
    }
    pthread_rwlock_unlock(&(routingTable_exact.rwlock));
    if(TEST_MODE == 4|| TEST_MODE >=8){
        printf("[ip.c] showRoutingTable give up routing table rdlock\n");
    }
}

/*
* data plane
*/


//host send
int sendIPPacket(const struct in_addr src, const struct in_addr dest, int proto, const void * buf, int len){
    packetInfo_t ipPacket = buildPacket(src,dest,proto,buf,len,PACKET_TTL_DEFAULT);
    int ret = 0;

    //default action: drop
    if(dest.s_addr == 0xfffffff){
        //broadcast
        uint8_t mac[6] = {0xff,0xff,0xff,0xff,0xff,0xff};
        for(int i = 0 ; i < MAX_DEVICE_NUM; i += 1){
            if(currDevices[i]){
                ret |= sendFrame(ipPacket.packet,ipPacket.packetLength,ETH_TYPE,mac,i);
            }
        }
    }
    else{
        rte_t nextHop = lookForNextHop(dest.s_addr);
        if(nextHop.ttl == -1){
            return -1;
        }
        else{
            sendFrame(ipPacket.packet,ipPacket.packetLength,ETH_TYPE,nextHop.next_hop_mac,nextHop.src_device_id);
        }
    }
    free(ipPacket.packet);
}

rte_t lookForNextHop(ipv4_t dst){
    rte_t ret;
    ret.ttl = -1;

    //exact match
    pthread_rwlock_rdlock(&(routingTable_exact.rwlock));
    if(TEST_MODE == 4|| TEST_MODE >=8){
        printf("[ip.c] lookForNextHop get routing table rdlock\n");
    }
    for(int i = 0; i < MAX_ROUTE_TABLE_LENGTH; i += 1){
        if(routingTable_exact.RTEs[i]&&routingTable_exact.RTEs[i]->ttl > 0){
            if(dst == routingTable_exact.RTEs[i]->dst){
                memcpy(&ret,routingTable_exact.RTEs[i],sizeof(rte_t));
                break;
            }
        }
    }
    pthread_rwlock_unlock(&(routingTable_exact.rwlock));
    if(TEST_MODE == 4|| TEST_MODE >=8){
        printf("[ip.c] lookForNextHop give up routing table rdlock\n");
    }

    // if(ret.ttl != -1)
        return ret;

    //exact match failure, lpm
    pthread_rwlock_rdlock(&(routingTable_lpm.rwlock));
    if(TEST_MODE == 4|| TEST_MODE >=8){
        printf("[ip.c] lookForNextHop get routing table rdlock\n");
    }
    int position = 0;
    uint32_t max_one_position = 0;
    for(int i = 0; i < MAX_ROUTE_TABLE_LENGTH; i += 1){
        if(routingTable_lpm.RTEs[i]&&routingTable_lpm.RTEs[i]->ttl > 0){
            uint32_t match = (~(routingTable_lpm.RTEs[i]->dst^dst))&routingTable_lpm.RTEs[i]->mask;
            for(int j = 0; j < 32; ++j){
                if((1<<j)&match == 0){
                    if(j > max_one_position){
                        max_one_position = j;
                        position = i;
                    }
                    break;
                }
            }
        }
    }
    memcpy(&ret,routingTable_lpm.RTEs[position],sizeof(rte_t));
    pthread_rwlock_unlock(&(routingTable_lpm.rwlock));
    if(TEST_MODE == 4|| TEST_MODE >=8){
        printf("[ip.c] lookForNextHop give up routing table rdlock\n");
    }
    return ret;
}

void forward(packet_t packet){
    eth_hdr_t ethHdr;
    ip_hdr_t ipHdr;
    memcpy(&ethHdr,packet.packet,sizeof(eth_hdr_t));
    memcpy(&ipHdr,packet.packet+sizeof(eth_hdr_t),sizeof(ip_hdr_t));
    ipHdr.ip_ttl -= 1;

    //drop
    if(ipHdr.ip_ttl <= 0){
        return;
    }

    int device_id = -1;
    uint8_t next_hop_mac[6] = {};
    pthread_rwlock_rdlock(&(routingTable_exact.rwlock));
    if(TEST_MODE == 4|| TEST_MODE >=8){
        printf("[ip.c] forward get routing table rdlock\n");
    }
    for(int i = 0; i < MAX_ROUTE_TABLE_LENGTH; i += 1){
        if(routingTable_exact.RTEs[i]){
            if(routingTable_exact.RTEs[i]->dst == ipHdr.ip_dst){
                device_id = routingTable_exact.RTEs[i]->src_device_id;
                memcpy(next_hop_mac,routingTable_exact.RTEs[i]->next_hop_mac,6);
                break;
            }
        }
    }
    pthread_rwlock_unlock(&(routingTable_exact.rwlock));
    if(TEST_MODE == 4|| TEST_MODE >=8){
        printf("[ip.c] forward give up routing table rdlock\n");
    }

    if(device_id != -1){
        memcpy(ethHdr.dst,next_hop_mac,6);
        memcpy(ethHdr.src,currDevices[device_id]->mac,6);
        memcpy(packet.packet,&ethHdr,sizeof(eth_hdr_t));
        memcpy(packet.packet+sizeof(eth_hdr_t),&ipHdr,sizeof(ip_hdr_t));
        pcap_sendpacket(currDevices[device_id]->pcapHandler,packet.packet,packet.len);
    }

}

void broadcast(packet_t packet){
    eth_hdr_t ethHdr;
    ip_hdr_t ipHdr;
    memcpy(&ethHdr,packet.packet,sizeof(eth_hdr_t));
    memcpy(&ipHdr,packet.packet+sizeof(eth_hdr_t),sizeof(ip_hdr_t));
    ipHdr.ip_ttl -= 1;
    memcpy(packet.packet+sizeof(eth_hdr_t),&ipHdr,sizeof(ip_hdr_t));
    for(int i = 0; i < MAX_DEVICE_NUM; i+= 1){
        if(i != packet.device_id){
            memcpy(ethHdr.src,currDevices[i]->mac,6);
            memcpy(packet.packet,&ethHdr,sizeof(eth_hdr_t));
            pcap_sendpacket(currDevices[i]->pcapHandler,packet.packet,packet.len);
        }
    }
}

int check_ipv4_available(uint32_t ip_addr){
    for(int i = 0; i < MAX_DEVICE_NUM; i += 1){
        if(currDevices[i]){
            if(currDevices[i]->ip == ip_addr)
                return 1;
        }
    }
    return 0;
}