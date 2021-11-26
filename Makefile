sender = src/sender
receiver = src/receiver
router = src/router
objdevice = src/device.o
objip = src/ip.o
objutils = src/utils.o
objtcp = src/tcp.o
objsocket = src/socket.o
objrouter = src/router.o
objpacketio = src/packetio.o
objsender = src/sender.o
objreceiver = src/receiver.o
objs = src/utils.o src/device.o src/packetio.o src/ip.o src/tcp.o src/socket.o src/sender.o src/receiver.o src/router.o

all: $(objs)
	gcc $(objutils) $(objdevice) $(objpacketio) $(objip) $(objtcp) $(objsocket) $(objsender) -o $(sender) -lpcap -lpthread
	gcc $(objutils) $(objdevice) $(objpacketio) $(objip) $(objtcp) $(objsocket) $(objreceiver) -o $(receiver) -lpcap -lpthread
	gcc $(objutils) $(objdevice) $(objpacketio) $(objip) $(objrouter) -o $(router) -lpcap -lpthread
ip_test: $(sender) $(receiver) $(router)
	
clean:
	rm -f src/*.o $(receiver) $(sender) $(router)

$(objdevice): src/device.c
	gcc -c src/device.c -o $(objdevice)
$(objpacketio): src/packetio.c
	gcc -c src/packetio.c -o $(objpacketio)
$(objutils): src/utils.c
	gcc -c src/utils.c -o $(objutils)
$(objip): src/ip.c
	gcc -c src/ip.c -o $(objip)
$(objtcp): src/tcp.c
	gcc -c src/tcp.c -o $(objtcp)
$(objsocket): src/socket.c
	gcc -c src/socket.c -o $(objsocket)
$(objrouter): src/router.c
	gcc -c src/router.c -o $(objrouter)
$(objsender): src/sender.c
	gcc -c src/sender.c -o $(objsender)
$(objreceiver): src/receiver.c
	gcc -c src/receiver.c -o $(objreceiver)