# The Network Stack

The main purpose of this project is to explore and
implement the inner workings of the internet on our
computers. The goal is to have a complete stack working up
to TCP over both IPv4 and IPv6. I run this in a simple
Ubuntu 24.04 docker container with only the essentials for
c++ development installed (found in Dockerfile-cppbase),
and the rest of the packages listed in the other Dockerfile.
I do not recommend running this elsewhere as it will stop
every other process from accessing the internet. 

## How does this work

The main idea behind how this works is to hijack the linux 
vm using a packet socket. A packet socket works over a
certain network interface. By using the ```ioctl()```
syscall, we can get this interface and give it to the 
packet socket. Next, we convince the kernel to not use its 
own network interface by changing the IP address and MAC
address using these commands.

```bash
ip link set dev eth0 address 02:42:ac:00:00:00
ip address flush dev eth0
```

Importantly, when running in the docker environment, the 
kernel makes use of checksum offloading, an optimization
that happens on real hardware. In the VM, this means that 
it often will send packets with incorrect checksums in the
L3 protocols like UDP and TCP. To remedy this, we disable
the optimization using the ```ethtool``` command. This 
needs to be installed, and in docker containers, 
```CAP_ADMIN``` or something like that must be enabled. 

```bash
ethtool --offload eth0 rx off tx off
```

Substitute eth0 with the name of your network device. 

### In the code
The critical class is ```NetworkDevice``` and in this class
the Listen method is where the magic happens. It should be 
fairly easy to follow the logic from there. The main API for
accessing the data that is received from our socket is 
```NetworkBuffer```. The basic idea is that it allows for
generic layer-by-layer extension of the data. In essence,
it allows us to access the stack in an easy way. This allows
for it to be generic over IPv4/6 or WiFi/ethernet. 

Many of the classes are hold-overs from previous versions of
this project. Anything ending in Buffer other than 
NetworkBuffer is not meant to be used, and most of 
```main.cpp``` is not used at all. 