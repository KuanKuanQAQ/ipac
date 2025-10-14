obj-m += ipac_watchpoint.o
PWD = $(shell pwd)

CC=gcc

all:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	
clean:
	$(MAKE) clean
