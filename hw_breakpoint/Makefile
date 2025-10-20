hw_break-y := hw_breakpoint.o \
              hw_breakpoint_manage.o \
              hw_breakpoint_proc.o \
              hw_breakpoint_smp.o \
              hw_breakpoint_until.o

obj-m += hw_break.o dbg_dump.o
PWD = $(shell pwd)

CC=gcc

all:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	
clean:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
