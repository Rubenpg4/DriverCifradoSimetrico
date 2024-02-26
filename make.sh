#!/bin/bash
make clean
make
rmmod DriverCifradoDescifrado
insmod DriverCifradoDescifrado.ko
chmod 666 /dev/DriverCifradoDescifrado*
dmesg | tail -n 10
