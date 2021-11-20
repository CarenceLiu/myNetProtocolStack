host = src/host
router = src/router
objdevice = src/device.o
objip = src/ip.o
objutils = src/utils.o
objhost = src/host.o
objrouter = src/router.o
objpacketio = src/packetio.o
objs = src/utils.o src/device.o src/packetio.o src/ip.o src/host.o src/router.o

all: $(objs)
	gcc $(objutils) $(objdevice) $(objpacketio) $(objip) $(objhost) -o $(host) -lpcap -lpthread
	gcc $(objutils) $(objdevice) $(objpacketio) $(objip) $(objrouter) -o $(router) -lpcap -lpthread
ip_test: $(host) $(router)
	
clean:
	rm -f src/*.o $(host) $(router)

$(objdevice): src/device.c
	gcc -c src/device.c -o $(objdevice)
$(objpacketio): src/packetio.c
	gcc -c src/packetio.c -o $(objpacketio)
$(objutils): src/utils.c
	gcc -c src/utils.c -o $(objutils)
$(objip): src/ip.c
	gcc -c src/ip.c -o $(objip)
$(objhost): src/host.c
	gcc -c src/host.c -o $(objhost)
$(objrouter): src/router.c
	gcc -c src/router.c -o $(objrouter)