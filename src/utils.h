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


/*
* Compare if two mac addresses are equal
* return 1 equal,0 not equal
*/
int macEqual(const uint8_t * m1,const uint8_t * m2);

// eth_hdr_t ethHdrToLittleEndian(eth_hdr_t ethHdr);
// eth_hdr_t ethHdrToBigEndian(eth_hdr_t ethHdr);
// ip_hdr_t ipHdrToLittleEndian(ip_hdr_t ipHdr);
// ip_hdr_t iphdrToBigEndian(ip_hdr_t ipHdr);