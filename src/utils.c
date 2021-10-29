#include "defs.h"
#include "utils.h"


int initBuffer(buffer_t *buffer){
    pthread_mutex_init(&(buffer->mutex),NULL);
    pthread_cond_init(&(buffer->full_cond),NULL);
    pthread_cond_init(&(buffer->empty_cond),NULL);
    buffer->end = 0;
    buffer->start = 0;
    return 0;
}

char * pop(buffer_t * buf){
    char * tmp = NULL;
    pthread_mutex_lock(&(buf->mutex));
    while(empty(buf)){
        pthread_cond_wait(&(buf->empty_cond),&(buf->mutex));
    }
    tmp = buf->buffer[buf->start];
    buf->start = (buf->start+1)%MAX_ROUTE_TABLE_LENGTH;
    pthread_cond_signal(&(buf->empty_cond));
    pthread_mutex_unlock(&(buf->mutex));
    return tmp;
}

void push(buffer_t * buf,char * packet){
    pthread_mutex_lock(&(buf->mutex));
    while(full(buf)){
        pthread_cond_wait(&(buf->full_cond),&(buf->mutex));
    }
    buf->buffer[buf->end] = packet;
    pthread_cond_signal(&(buf->full_cond));
    pthread_mutex_unlock(&(buf->mutex));
    return;
}

int empty(buffer_t * buf){
    return buf->start == buf->end;
}

int full(buffer_t * buf){
    return (buf->start+MAX_ROUTE_TABLE_LENGTH-1-buf->end)%MAX_ROUTE_TABLE_LENGTH == 0;
}
