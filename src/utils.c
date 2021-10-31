#include "defs.h"
#include "utils.h"


int initBuffer(buffer_t *buffer){
    pthread_mutex_init(&(buffer->mutex),NULL);
    pthread_cond_init(&(buffer->full_cond),NULL);
    pthread_cond_init(&(buffer->empty_cond),NULL);
    buffer->end = 0;
    buffer->start = 0;
    if(TEST_MODE){
        printf("[utils.c] initBuffer finish\n");
    }
    return 0;
}

packet_t pop(buffer_t * buf){
    packet_t ret;
    pthread_mutex_lock(&(buf->mutex));
    if(TEST_MODE){
        printf("[utils.c] pop get buffer mutex\n");
    }
    while(empty(buf)){
        pthread_cond_wait(&(buf->empty_cond),&(buf->mutex));
        if(TEST_MODE){
            printf("[utils.c] pop buffer empty, wait\n");
        }
    }
    ret.packet = buf->buffer[buf->start].packet;
    ret.len = buf->buffer[buf->start].len;
    ret.device_id = buf->buffer[buf->start].device_id;
    buf->start = (buf->start+1)%MAX_BUFFER_SIZE;
    if(TEST_MODE){
        printf("queue pop %d\n",buf->start);
    }
    pthread_cond_signal(&(buf->empty_cond));
    pthread_mutex_unlock(&(buf->mutex));
    if(TEST_MODE){
        printf("[utils.c] pop buffer unlock mutex\n");
    }
    return ret;
}

void push(buffer_t * buf,packet_t packet){
    pthread_mutex_lock(&(buf->mutex));
    if(TEST_MODE){
        printf("[utils.c] push buffer unlock mutex\n");
    }
    while(full(buf)){
        pthread_cond_wait(&(buf->full_cond),&(buf->mutex));
        if(TEST_MODE){
            printf("[utils.c] push buffer full, wait\n");
        }
    }
    buf->buffer[buf->end].len = packet.len;
    buf->buffer[buf->end].packet = packet.packet;
    buf->buffer[buf->end].device_id = packet.device_id;
    buf->end = (buf->end+1)%MAX_BUFFER_SIZE;
    if(TEST_MODE){
        printf("queue push %d\n",buf->end);
    }
    pthread_cond_signal(&(buf->full_cond));
    pthread_mutex_unlock(&(buf->mutex));
    if(TEST_MODE){
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
