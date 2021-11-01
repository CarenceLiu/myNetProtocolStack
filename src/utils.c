#include "defs.h"
#include "utils.h"



int initBuffer(buffer_t *buffer){
    pthread_mutex_init(&(buffer->mutex),NULL);
    pthread_cond_init(&(buffer->full_cond),NULL);
    pthread_cond_init(&(buffer->empty_cond),NULL);
    buffer->end = 0;
    buffer->start = 0;
    if(TEST_MODE == 1|| TEST_MODE >=8){
        printf("[utils.c] initBuffer finish\n");
    }
    return 0;
}

packet_t pop(buffer_t * buf){
    packet_t ret;
    pthread_mutex_lock(&(buf->mutex));
    if(TEST_MODE == 1|| TEST_MODE >=8){
        printf("[utils.c] pop lock buffer mutex\n");
    }
    while(empty(buf)){
        pthread_cond_wait(&(buf->empty_cond),&(buf->mutex));
        if(TEST_MODE == 1|| TEST_MODE >=8){
            printf("[utils.c] pop buffer empty, wait\n");
        }
    }
    ret.packet = buf->buffer[buf->start].packet;
    ret.len = buf->buffer[buf->start].len;
    ret.device_id = buf->buffer[buf->start].device_id;
    buf->start = (buf->start+1)%MAX_BUFFER_SIZE;
    if(TEST_MODE == 1|| TEST_MODE >=8){
        printf("queue pop %d\n",buf->start);
    }
    pthread_cond_signal(&(buf->full_cond));
    pthread_mutex_unlock(&(buf->mutex));
    if(TEST_MODE == 1|| TEST_MODE >=8){
        printf("[utils.c] pop buffer unlock mutex\n");
    }
    return ret;
}

void push(buffer_t * buf,packet_t packet){
    pthread_mutex_lock(&(buf->mutex));
    if(TEST_MODE == 1|| TEST_MODE >=8){
        printf("[utils.c] push buffer lock mutex\n");
    }
    while(full(buf)){
        pthread_cond_wait(&(buf->full_cond),&(buf->mutex));
        if(TEST_MODE == 1|| TEST_MODE >=8){
            printf("[utils.c] push buffer full, wait\n");
        }
    }
    buf->buffer[buf->end].len = packet.len;
    buf->buffer[buf->end].packet = packet.packet;
    buf->buffer[buf->end].device_id = packet.device_id;
    buf->end = (buf->end+1)%MAX_BUFFER_SIZE;
    if(TEST_MODE == 1|| TEST_MODE >=8){
        printf("queue push %d\n",buf->end);
    }
    pthread_cond_signal(&(buf->empty_cond));
    pthread_mutex_unlock(&(buf->mutex));
    if(TEST_MODE == 1|| TEST_MODE >=8){
        printf("[utils.c] push buffer unlock mutex\n");
    }
    return;
}

int empty(buffer_t * buf){
    return buf->start == buf->end;
}

int full(buffer_t * buf){
    return (buf->start+MAX_BUFFER_SIZE-1-buf->end)%MAX_BUFFER_SIZE == 0;
}

int macEqual(const uint8_t * m1,const uint8_t * m2){
    int res = 1;
    for(int i = 0; i < 6; i += 1){
        if(m1[i] != m2[i]){
            res = 0;
            break;
        }
    }
    return res;
}


//header transform
// eth_hdr_t ethHdrToLittleEndian(eth_hdr_t ethHdr){
//     eth_hdr_t res;
//     res.type = ((ethHdr.type&0xff)<<8)+((ethHdr.type&0xff00)>>8);
//     return res;
// }

// eth_hdr_t ethHdrToBigEndian(eth_hdr_t ethHdr){
//     eth_hdr_t res;
//     res.type = ((ethHdr.type&0xff)<<8)+((ethHdr.type&0xff00)>>8);
//     return res;
// }

// ip_hdr_t ipHdrToLittleEndian(ip_hdr_t ipHdr){
//     ip_hdr_t res;
//     res.ip_version_ihl = ipHdr.ip_version_ihl;
//     res.ip_tos = ipHdr.ip_tos;
//     res.ip_len = ((ipHdr.ip_len&0xff)<<8)+((ipHdr.ip_len&0xff00)>>8);
//     res.ip_ttl = ipHdr.ip_ttl;
//     res.ip_p = ipHdr.ip_p;
//     res.ip_sum = ((ipHdr.ip_sum&0xff)<<8)+((ipHdr.ip_sum&0xff00)>>8);
//     res.ip_src = ((ipHdr.ip_src&0xff000000)>>24)+((ipHdr.ip_src&0x00ff0000)>>8)
//                 +((ipHdr.ip_src&0x0000ff00)<<8)+((ipHdr.ip_src&0xff)<<24);
//     res.ip_dst = ((ipHdr.ip_dst&0xff000000)>>24)+((ipHdr.ip_dst&0x00ff0000)>>8)
//                 +((ipHdr.ip_dst&0x0000ff00)<<8)+((ipHdr.ip_dst&0xff)<<24);
//     return res;
// }

// ip_hdr_t iphdrToBigEndian(ip_hdr_t ipHdr){
//     ip_hdr_t res;
//     res.ip_version_ihl = ipHdr.ip_version_ihl;
//     res.ip_tos = ipHdr.ip_tos;
//     res.ip_len = ((ipHdr.ip_len&0xff)<<8)+((ipHdr.ip_len&0xff00)>>8);
//     res.ip_ttl = ipHdr.ip_ttl;
//     res.ip_p = ipHdr.ip_p;
//     res.ip_sum = ((ipHdr.ip_sum&0xff)<<8)+((ipHdr.ip_sum&0xff00)>>8);
//     res.ip_src = ((ipHdr.ip_src&0xff000000)>>24)+((ipHdr.ip_src&0x00ff0000)>>8)
//                 +((ipHdr.ip_src&0x0000ff00)<<8)+((ipHdr.ip_src&0xff)<<24);
//     res.ip_dst = ((ipHdr.ip_dst&0xff000000)>>24)+((ipHdr.ip_dst&0x00ff0000)>>8)
//                 +((ipHdr.ip_dst&0x0000ff00)<<8)+((ipHdr.ip_dst&0xff)<<24);
//     return res;
// }