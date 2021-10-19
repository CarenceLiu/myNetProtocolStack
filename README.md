## lab2a



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



Here are some design details.

`src/defs.h` declares some struct and constant, include `struct device`, `struct eth_hdr` for the frame header and some typedef.

`src/utils.c` and `src/utils.c` are the position for some basic function.

`src/device.c` and `src/device.h`  are implementation for Program 1

`src/packetio.c` and `src/packetio.h` are implementation for Program 2
