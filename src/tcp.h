/*
* @file tcp.h
* @author: Wenrui Liu
* @lastEdit: 2021-11-21
* @brief TCP declaration
*/

/*
* sendTCPPacket
* @brief send the content in the buf with socket
* @param sockfd
* @param buf the content
* @param len content length
*/
int sendTCPPacket(int sockfd,const void *buf,int len,
                uint32_t seq_num,uint32_t ack_num,uint16_t flag);

/*
* parseTCPPacket
* @brief parse TCP segment, put the content in the buf and send ACK
* @param sockfd
* @param buf the content
* @param len content length
*/
int parseTCPPacket(int sockfd,packet_t packet,ip_hdr_t ipHdr,tcp_hdr_t tcpHdr);

//some flag set
int is_SYN(uint16_t flag);
int is_FIN(uint16_t flag);
int is_ACK(uint16_t flag);
uint16_t set_SYN(uint16_t flag);
uint16_t set_FIN(uint16_t flag);
uint16_t set_ACK(uint16_t flag);

