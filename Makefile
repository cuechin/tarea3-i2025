obj-m += rootkit.o

KERNEL_VERSION = 4.4.0-22-generic
KERNEL_DIR = /lib/modules/$(KERNEL_VERSION)/build
PWD = $(shell pwd)

all:
	make -C $(KERNEL_DIR) M=$(PWD) modules

clean:
	make -C $(KERNEL_DIR) M=$(PWD) clean

install:
	sudo insmod rootkit.ko

remove:
	sudo rmmod rootkit

client:
	gcc -o client client.c

test:
	./client --help

.PHONY: all clean install remove client test
