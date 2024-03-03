#!/bin/bash
cat /dev/DriverCifradoDescifrado0
echo -n "Este mensaje se cifrara correctamente" > /dev/DriverCifradoDescifrado1
dmesg | tail -n 50

