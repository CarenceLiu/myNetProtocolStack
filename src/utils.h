/* *
* @file device.h
* @author: Wenrui Liu
* @lastEdit: 2021-10-28
* @ some data structure library.
*/

//a queue for packet buffer. use condition for pthread security


int initBuffer(buffer_t *buffer);
//pop the front pointer of the queue
packet_t pop(buffer_t * buffer);
//push a new pointer to the back of the queue
void push(buffer_t * buffer,packet_t packet);
int empty(buffer_t * buffer);       
int full(buffer_t * buffer);
