#!/bin/bash

# Remove the wrong modules
lsmod | grep vbox
rmmod vboxnetflt
rmmod vboxnetadp
rmmod vboxdrv

# Install and  load the correct one
# vboxdrv module number to adapt
lsmod | grep vbox
insmod /lib/modules/6.17.10+kali-amd64/misc/vboxdrv.ko
modprobe vboxnetadp
modprobe vboxnetflt
