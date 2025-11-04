obj-m += log_time.o
PWD = $(shell pwd)

all:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules LLVM=1 LLVM_IAS=1 CC=clang
	
clean:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
