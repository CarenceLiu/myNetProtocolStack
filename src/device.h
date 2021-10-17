/* *
* @file device.h
* @author: Wenrui Liu
* @date: 2021-10-16 
* @lastEdit: 2021-10-17
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