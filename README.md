## README

#### link layer

For the device, I declare a struct called device_t in `src/device.h`

```c
struct device{
    deviceID_t id;
    pcap_t *pcapHandler;
    uint8_t mac[6];
    ipv4_t ip;
    char pcapErrBuf[MAX_DEVICE_NUM];
    char deviceName[MAX_DEVICE_NAME_LENGTH];
};
typedef struct device device_t;
```

`src/device.c` define `device_t *currDevices[MAX_DEVICE_NUM] = {};` to memorize the available device in libpcap.

#### IP layer design

The design of network layer can be divided into control plane and data plane.

In the control plane, a routing table is maintained to route, which means helping the packet to find the next hop. In this part, I use the distance vector(DV) algorithm to refresh the routing table and find the new hosts. To avoid count-to-infinity problem, a TTL is added in each routing table entry(RTE). When the TTL is equal to zero, the routing table will dismiss the corresponding RTE.

As we mentioned above, the RTE can be defined:

```c
struct rte{
    ipv4_t dst;		//destination ip address
    ipv4_t mask;	//netmask
    uint8_t next_hop_mac[6];	//next hop mac address
    int distance;	//the shortest distance
    int src_device_id;	//the veth device id for sending or forwarding the packet
    int ttl;	//time to live
};
```

In addition, DV packet needs to be designed to send DV to neighbors, so I define a new IP protocol type(0xff) to identify the DV packet. 

A distance content is shown as follow:

```c 
struct DVInfo{
    ipv4_t dst;		//destination IP address
    ipv4_t mask;	//netmask
    int distance;	//the shortest distance of between the sender and the destination
};
```

The DV packet structure:

| eth_header | ip_header | DV_info | DV_info | ...(DV_info*n) | eth_checksum |
| ---------- | --------- | ------- | ------- | -------------- | ------------ |

The control plane interface can be designed(in `ip.c`):

```c
/* Initiate routing tables*/
void initRoutingTable();
/*print routing tables*/
void showRoutingTable();
/* send DV packets to neighbors; */
int sendDVPackets();
/*when receive a DV packet, call this function to routeTable*/
void refreshRoutingTable(packet_t packet);
/*periord refresh routing table(TTL minus one and dismiss the outdated RTE)*/
void * periodRefreshRT();
```



In the data plane, host/router forwards or receives a packet according to the routing table. 

```c
/*Send an IP packet to specified host .*/
int sendIPPacket(const struct in_addr src, const struct in_addr dest,int proto, const void * buf, int len);
/*look for the next hop RTE*/
rte_t lookForNextHop(ipv4_t dst);
/*forward a unicast packet. TTL -1. If cannot find the nextHop, drop.*/
void forward(packet_t packet);
/*broadcast a packet. except the mac which the packet came. TTL -1.*/
void broadcast(packet_t packet);
```



After finishing network layer, `host.c` and `router.c` are programmed for host and router. The host used in the edge of the network while the router is in the middle to simulate the real net circumstance.  Each host/router has an ip layer buffer to buffer the packets received from veth devices. The buffer is based on a thread-security queue defined in `utils.c`. 

In each router and host, a thread is used to handle the packets, each veth device has a receiving thread to receive packets. Each host has an additional thread for receiving and sending packets.

#### Transport layer

In this part, I implement a simple TCP reliable connect in files `tcp.c tcp.h socket.c socket.h`. In more detailed, `tcp.*` contained the state changing and send a TCP segment reliably. `socket.*` is used as API for the higher layer.

There is a brief introduction. 

 For each socket, a `struct socketInfo` is maintained to store the vital information.

```c
struct socketInfo
{
    int sockfd;		//fd
    rw_buffer_t send_buf;		//content buffer
    rw_buffer_t receive_buf;
    uint16_t window_size;
    sockBuffer_t segmentBuff;	//segmentBuff
    int state;		//socket state
    int domain;
    int type;
    int protocol;
    int bind_flag;
    int rw_flag;        //if it is a listen socket
    uint32_t ack_num;
    uint32_t seq_num;
    connectInfo_t tcpInfo;
    pthread_t send_thread;
};
```

The main idea of socket functions is to manipulate the state in `socketInfo`  and to send segments for communication. The details are as follows.

`socket()`: create a new `struct socketInfo` and return the sockfd

`bind()`: check the ipv4 address and TCP port and bind them with the socket

`listen()`: change the socket state from CLOSED to LISTEN

`connect()`: allocate an ipv4 address and TCP port, then try to perform three handshakes with the target socket

`accept`: create a new socket for read/write and waiting for connecting(SYN/ACK). If success, the state will be changed to ESTABLISHED

`close`: close the connection with FIN/ACKs. Deallocate the `struct socketInfo`

The `tcp.*` files implements sending TCP packets and parsing TCP packets.

`sendTCPPacket`: add a TCP header before the content and call `sendIPPacket` 

`parseTCPPacket`: analyze a TCP packet. Changing the socket state or buffering the content.

