/* *
* @file utils.h
* @author: Wenrui Liu
* @lastEdit: 2021-11-21
* @ some data structure library.
*/

//a queue for pcap packet buffer. use condition for pthread security


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


int initSockBuffer(sockBuffer_t *buffer);
//pop the front pointer of the queue
sockPacket_t sockPop(sockBuffer_t * buffer);
//push a new pointer to the back of the queue
void sockPush(sockBuffer_t * buffer,sockPacket_t packet);
int sockEmpty(sockBuffer_t * buffer);       
int sockFull(sockBuffer_t * buffer);


//a group of API to read/write buffer pthread-safely.
void initrwBuffer(rw_buffer_t * buf);
int read_rw_buf_nowait_to(rw_buffer_t * buf, u_char * buf_aim,int len);
segment_t read_rw_buf_nowait_new(rw_buffer_t * buf);
segment_t read_rw_buf_block_new(rw_buffer_t * buf);
void write_rw_buf(rw_buffer_t * buf, u_char * buf_src,int len);