#define _GNU_SOURCE
#include <sched.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

// Define the custom ioctl command
#define IOCTL_SET_WATCHPOINT _IO('k', 1)
#define IOCTL_SHOW_WATCHPOINT _IO('k', 2)
#define MAP_SIZE (1UL << 20)

typedef unsigned int __u32;
typedef unsigned long long __u64;

struct watchpoint_set_request {
    __u64	addr;
    __u32	ctrl;
    __u32	id;
};

void print_watchpoint(struct watchpoint_set_request *ptr) {
    printf("id = %d\naddr = %p\nctrl = %x\n\n", ptr->id, (void*)ptr->addr, ptr->ctrl);
}

static void sigalrm(int sig)
{
    printf("sigalrm is called!\n");
}

void init_signial_handler() {
    struct sigaction act;
    act.sa_handler = sigalrm;
	sigemptyset(&act.sa_mask);
	act.sa_flags = 0;
	sigaction(SIGALRM, &act, NULL);
}

void pin_to_core(int core_id) {
    cpu_set_t mask;
    CPU_ZERO(&mask);          // Clear CPU set
    CPU_SET(core_id, &mask);  // Set CPU core to bind to

    // Apply CPU affinity to the current thread
    if (sched_setaffinity(0, sizeof(mask), &mask) == -1) {
        perror("sched_setaffinity failed");
    }
}

int main()
{
    int ret;
    struct watchpoint_set_request state = {0};
    init_signial_handler();

    // uint64_t daif = 0;
    // asm volatile("mrs %x0, DAIF\n\t" : "=r"(daif));
    // printf("daif of pstate: %lx\n", daif);

    volatile int *ptr = (int*)mmap(NULL, MAP_SIZE /** 2*/, PROT_WRITE /*| PROT_MTE */, MAP_PRIVATE /* | MAP_SHARED*/ | MAP_ANONYMOUS, -1, 0);
    // int *ptr = (int*)mmap(NULL, SIZE /** 2*/, PROT_READ | PROT_WRITE /*| PROT_MTE */, MAP_PRIVATE /* | MAP_SHARED*/ | MAP_ANONYMOUS, -1, 0);
    if (ptr == MAP_FAILED) {
        perror("mmap");
        return 1;
    }
    else {
        printf("ptr = %p\n", ptr);
    }

    int fd = open("/dev/ipac_watchpoint", O_RDWR);
    if (fd < 0) {
        perror("Failed to open the device");
        return -1;
    }

    pin_to_core(1);
    printf("[core1] display watchpoint\n");
    ret = ioctl(fd, IOCTL_SHOW_WATCHPOINT, &state);
    if (ret < 0) {
        goto ioctl_fail;
    }
    print_watchpoint(&state);

    pin_to_core(2);
    printf("[core2] set watchpoint\n");
    state.addr = (__u64)ptr;
    state.ctrl = (__u32)(/*MASK*/(0x1fUL << 24) | /*BAS*/ (0xffUL << 5) | /*LSC*/(0x3UL << 3) | /*PAC*/(0x2UL << 1) | /*Enable*/0x1);
    ret = ioctl(fd, IOCTL_SET_WATCHPOINT, &state);
    if (ret < 0) {
        goto ioctl_fail;
    }

    // pin_to_core(1);
    printf("[core2] display watchpoint\n");
    ret = ioctl(fd, IOCTL_SHOW_WATCHPOINT, &state);
    if (ret < 0) {
        goto ioctl_fail;
    }
    print_watchpoint(&state);

    pin_to_core(1);
    printf("[core1] display watchpoint\n");
    ret = ioctl(fd, IOCTL_SHOW_WATCHPOINT, &state);
    if (ret < 0) {
        goto ioctl_fail;
    }
    print_watchpoint(&state);

    printf("[core2] display watchpoint\n");
    ret = ioctl(fd, IOCTL_SHOW_WATCHPOINT, &state);
    if (ret < 0) {
        goto ioctl_fail;
    }
    print_watchpoint(&state);

    printf("try to memset mmap region\n");
    memset((void*)ptr, 'A', MAP_SIZE);
    printf("try to read mmap region:\nptr[1024] = ");
    printf("0x%x\n", ptr[1024]);

    printf("try to read mmap region:\nptr[0] = ");
    printf("0x%x\n", ptr[0]);

    close(fd);
    return 0;

ioctl_fail:
    perror("ioctl failed");
    close(fd);
    return -1;
}
