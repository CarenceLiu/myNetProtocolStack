/* *
* @file device.h
* @author: Wenrui Liu
* @lastEdit: 2021-10-25
* @brief Library supporting network device management .
*/


/* *
* Add a device to the library for sending / receiving packets .
*
* @param device Name of network device to send / receive packet on .
* @return A non - negative _device - ID_ on success , -1 on error .
*/
int addDevice(const char * device);

/* *
* Find a device added by ‘ addDevice ‘.
*
* @param device Name of the network device .
* @return A non - negative _device - ID_ on success , -1 if no such device
* was found .
*/
int findDevice(const char * device);


/*
* add all available devices
*
* @return non-negative the number of devices added. -1 error occured.
*/
int addAllDevices();