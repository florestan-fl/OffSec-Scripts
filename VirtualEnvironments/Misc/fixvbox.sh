lsmod | grep vbox
rmmod vboxnetflt
rmmod vboxnetadp
rmmod vboxdrv

lsmod | grep vbox
insmod /lib/modules/6.17.10+kali-amd64/misc/vboxdrv.ko
modprobe vboxnetadp
modprobe vboxnetflt
