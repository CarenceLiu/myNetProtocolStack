/* *
* @file utils.c
* @author: Wenrui Liu
* @lastEdit: 2021-11-18
* @ some data structure implement.
*/
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


int initSockBuffer(sockBuffer_t *buffer){
    pthread_mutex_init(&(buffer->mutex),NULL);
    pthread_cond_init(&(buffer->full_cond),NULL);
    pthread_cond_init(&(buffer->empty_cond),NULL);
    buffer->end = 0;
    buffer->start = 0;
    if(TEST_MODE == 1|| TEST_MODE >=8){
        printf("[utils.c] initSockBuffer finish\n");
    }
    return 0;
}

sockPacket_t sockPop(sockBuffer_t * buf){
    sockPacket_t ret;
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
    ret.segment = buf->buffer[buf->start].segment;
    ret.segment_len = buf->buffer[buf->start].segment_len;
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

void sockPush(sockBuffer_t * buf,sockPacket_t packet){
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
    buf->buffer[buf->end].segment = packet.segment;
    buf->buffer[buf->end].packet = packet.packet;
    buf->buffer[buf->end].segment_len = packet.segment_len;
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
int sockEmpty(sockBuffer_t * buf){
    return buf->start == buf->end;
}    
int sockFull(sockBuffer_t * buf){
    return (buf->start+MAX_BUFFER_SIZE-1-buf->end)%MAX_BUFFER_SIZE == 0;
}

void initrwBuffer(rw_buffer_t * buf){
    buf->end = 0;
    buf->start = 0;
    buf->size = 0;
    pthread_mutex_init(&(buf->lock),NULL);
    pthread_cond_init(&(buf->empty),NULL);
    pthread_cond_init(&(buf->full),NULL);
}

int read_rw_buf_nowait_to(rw_buffer_t *buf,u_char * buf_aim,int len){
    pthread_mutex_lock(&(buf->lock));
    int size = buf->size > MAX_CONTENT_LENGTH? MAX_CONTENT_LENGTH:buf->size;
    if(size == 0){
        pthread_mutex_unlock(&(buf->lock));
        return 0;
    }
    int partition = 0;
    if(buf->start+size > MAX_RW_BUFFER_SIZE){
        partition = MAX_RW_BUFFER_SIZE-buf->start;
    }
    if(partition > 0){
        memcpy(buf_aim,buf->buf+buf->start,partition);
        memcpy(buf_aim+partition,buf->buf,size-partition);
    }
    else{
        memcpy(buf_aim,buf->buf+buf->start,size);
    }

    buf->start = (buf->start+size)%MAX_RW_BUFFER_SIZE;
    if(buf->size == MAX_RW_BUFFER_SIZE)
        pthread_cond_signal(&(buf->full));
    buf->size -= size;
    if(buf->size == 0){     //the buf is empty, refresh all buf
        buf->start = 0;
        buf->end = 0;
    }
    pthread_mutex_unlock(&(buf->lock));
    return size;
}

segment_t read_rw_buf_nowait_new(rw_buffer_t * buf){
    pthread_mutex_lock(&(buf->lock));
    int size = buf->size > MAX_CONTENT_LENGTH? MAX_CONTENT_LENGTH:buf->size;
    segment_t segment;
    if(size == 0){
        segment.buf = NULL;
        segment.len = 0;
        pthread_mutex_unlock(&(buf->lock));
        return segment;
    }
    int partition = 0;
    segment.buf = malloc(size);
    segment.len = size;
    if(buf->start+size > MAX_RW_BUFFER_SIZE){
        partition = MAX_RW_BUFFER_SIZE-buf->start;
    }
    if(partition > 0){
        memcpy(segment.buf,buf->buf+buf->start,partition);
        memcpy(segment.buf+partition,buf->buf,size-partition);
    }
    else{
        memcpy(segment.buf,buf->buf+buf->start,size);
    }

    buf->start = (buf->start+size)%MAX_RW_BUFFER_SIZE;
    if(buf->size == MAX_RW_BUFFER_SIZE)
        pthread_cond_signal(&(buf->full));
    buf->size -= size;
    if(buf->size == 0){     //the buf is empty, refresh all buf
        buf->start = 0;
        buf->end = 0;
    }
    pthread_mutex_unlock(&(buf->lock));
    return segment;
}

void write_rw_buf(rw_buffer_t * buf, u_char * buf_src,int len){
    pthread_mutex_lock(&(buf->lock));
    while(buf->size + len > MAX_CONTENT_LENGTH){
        pthread_cond_wait(&(buf->full),&(buf->lock));
    }
    int partition = 0;
    if(buf->end+len > MAX_RW_BUFFER_SIZE){
        partition = MAX_RW_BUFFER_SIZE-buf->end;
    }
    if(partition > 0){
        memcpy(buf->buf+buf->end,buf_src,partition);
        memcpy(buf->buf,buf_src+partition,len-partition);
    }
    else{
        memcpy(buf->buf+buf->end,buf_src,len);
    }

    buf->end = (buf->end+len)%MAX_RW_BUFFER_SIZE;
    if(buf->size == 0)
        pthread_cond_signal(&(buf->empty));
    buf->size += len;
    pthread_mutex_unlock(&(buf->lock));
    return;
}

segment_t read_rw_buf_block_new(rw_buffer_t * buf){
    pthread_mutex_lock(&(buf->lock));
    while(buf->size == 0){
        pthread_cond_wait(&(buf->empty),&(buf->lock));
    }
    int size = buf->size > MAX_CONTENT_LENGTH? MAX_CONTENT_LENGTH:buf->size;
    segment_t segment;
    if(size == 0){
        segment.buf = NULL;
        segment.len = 0;
        pthread_mutex_unlock(&(buf->lock));
        return segment;
    }
    int partition = 0;
    segment.buf = malloc(size);
    segment.len = size;
    if(buf->start+size > MAX_RW_BUFFER_SIZE){
        partition = MAX_RW_BUFFER_SIZE-buf->start;
    }
    if(partition > 0){
        memcpy(segment.buf,buf->buf+buf->start,partition);
        memcpy(segment.buf+partition,buf->buf,size-partition);
    }
    else{
        memcpy(segment.buf,buf->buf+buf->start,size);
    }

    buf->start = (buf->start+size)%MAX_RW_BUFFER_SIZE;
    if(buf->size == MAX_RW_BUFFER_SIZE)
        pthread_cond_signal(&(buf->full));
    buf->size -= size;
    if(buf->size == 0){     //the buf is empty, refresh all buf
        buf->start = 0;
        buf->end = 0;
    }
    pthread_mutex_unlock(&(buf->lock));
    return segment;
}