/* *
* @file device.h
* @author: Wenrui Liu
* @lastEdit: 2021-10-28
* @ some data structure library.
*/

//a queue for packet buffer. use condition for pthread security
struct bufferQueue{
    char * buffer[MAX_BUFFER_SIZE];
    pthread_mutex_t mutex;
    pthread_cond_t full_cond;
    pthread_cond_t empty_cond;
    int start;
    int end;
};

typedef struct bufferQueue buffer_t;


int initBuffer(buffer_t *buffer);
//pop the front pointer of the queue
char * pop(buffer_t * buffer);
//push a new pointer to the back of the queue
void push(buffer_t * buffer,char * packet);
int empty(buffer_t * buffer);       
int full(buffer_t * buffer);
