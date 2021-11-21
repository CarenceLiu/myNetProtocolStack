/* *
* @file ip.h
* @author: Wenrui Liu
* @lastEdit: 2021-10-28
* @brief Library supporting ip layer.
*/


/* *
* @brief Send an IP packet to specified host .
*
* @param src Source IP address .
* @param dest Destination IP address .
* @param proto Value of ‘ protocol ‘ field in IP header .
* @param buf pointer to IP payload
* @param len Length of IP payload
* @return 0 on success , -1 on error .
*/
int sendIPPacket(const struct in_addr src, const struct in_addr dest,
int proto, const void * buf, int len);

/* *
* @brief Process an IP packet upon receiving it .
*
* @param buf Pointer to the packet .
* @param len Length of the packet .
* @return 0 on success , -1 on error .
* @see addDevice
*/
typedef int (*IPPacketReceiveCallback)(const void *, int);


/* *
* @brief Manully add an item to routing table . Useful when talking
with real Linux machines .
*
* @param dest The destination IP prefix .
* @param mask The subnet mask of the destination IP prefix .
* @param nextHopMAC MAC address of the next hop .
* @param device Name of device to send packets on .
* @return 0 on success , -1 on error
*/
int setRoutingTable(const struct in_addr dest, const struct in_addr mask,
const void * nextHopMAC, const char * device,int distance);

/*
* @brief Initiate routing tables
* 
*/
void initRoutingTable();

/*
* @brief print routing tables
* 
*/
void showRoutingTable();

/*
* @brief build DV packet info 
* return char * for a buffer of DV packet
*/
//char * buildDVPacket(int src_device_id);

/*
* @brief send DV packets to neighbors; 
* return 0 success, -1 on error
*/
int sendDVPackets();

/*
* @brief when receive a DV packet, call this function to routeTable
* 
*/
void refreshRoutingTable(packet_t packet);

/*
* @brief periord refresh routing table
* 
*/
void * periodRefreshRT();


/*
* @brief look for the next hop RTE
* @ param dst
*/
rte_t lookForNextHop(ipv4_t dst);

//data platform
/*
* @brief forward a unicast packet. TTL -1. If cannot find the nextHop, drop.
* @ param the packet forwarding
*/
void forward(packet_t packet);

/*
* @brief broadcast a packet. except the mac which the packet came. TTL -1.
* @ param the packet broadcasting
*/
void broadcast(packet_t packet);

/*
* @brief check if ip address in device list(available)
*/
int check_ipv4_available(uint32_t ip_addr);