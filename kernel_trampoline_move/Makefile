obj-m += kernel_trampoline_move.o
kernel_trampoline_move-objs := ktm_core.o ktm_func.o ktm_move.o ktm_die.o
PWD = $(shell pwd)

ccflags-y += -fpass-plugin=/home/lrk/CRR/samples/log_time/FuncTimeLogger.so

# KBUILD_CFLAGS += -Xclang -load -Xclang /home/lrk/CRR/samples/log_time/FuncTimeLogger.so

CC=clang

all:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	
clean:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
