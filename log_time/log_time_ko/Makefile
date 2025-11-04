# clang++ -fPIC -shared -o /home/lrk/CRR/samples/log_time/FuncTimeLogger.so /home/lrk/CRR/samples/log_time/FuncTimeLogger.cpp `llvm-config --cxxflags --ldflags --system-libs --libs core passes`



obj-m += log_time.o
PWD = $(shell pwd)

CC=clang

all:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	
clean:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
