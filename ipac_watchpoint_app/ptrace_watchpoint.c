#define _GNU_SOURCE
#include <sched.h>
#include <unistd.h>
#include <asm/ptrace.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/uio.h>
#include <string.h>
#include <stddef.h>
#include <elf.h>
#include <errno.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <fcntl.h>

#define SIZE (1UL << 31)
#define IOCTL_SET_WATCHPOINT _IO('k', 1)
#define IOCTL_SHOW_WATCHPOINT _IO('k', 2)

struct watchpoint_set_request {
    __u64	addr;
    __u32	ctrl;
    __u32	id;
};

void print_watchpoint(struct watchpoint_set_request *ptr) {
    printf("id = %d\naddr = %p\nctrl = %x\n", ptr->id, (void*)ptr->addr, ptr->ctrl);
}

static bool set_watchpoint(pid_t pid, int size, uint8_t* addr)
{
	const int offset = (uintptr_t)addr % 8;
	const unsigned int byte_mask = ((1 << size) - 1) << offset;
	// const unsigned int type = 2; /* Write */
    const unsigned int type = 1; /* Load */
	const unsigned int enable = 1;
	const unsigned int control = (0x1fU << 24) | byte_mask << 5 | type << 3 | enable;
	struct user_hwdebug_state dreg_state;
	struct iovec iov;

	memset(&dreg_state, 0, sizeof(dreg_state));
	dreg_state.dbg_regs[0].addr = (uintptr_t)(addr - offset);
	dreg_state.dbg_regs[0].ctrl = control;
	iov.iov_base = &dreg_state;
	iov.iov_len = offsetof(struct user_hwdebug_state, dbg_regs) +
				sizeof(dreg_state.dbg_regs[0]);
	if (ptrace(PTRACE_SETREGSET, pid, NT_ARM_HW_WATCH, &iov) == 0) {
        memset(&dreg_state, 0, sizeof(dreg_state));
        ptrace(PTRACE_GETREGSET, pid, NT_ARM_HW_WATCH, &iov);
        printf("control: 0x%x\n", control);
        printf("dregs[0].addr: 0x%llx\n", dreg_state.dbg_regs[0].addr);
        printf("dregs[0].ctrl: 0x%x\n", dreg_state.dbg_regs[0].ctrl);
    	return true;
    }

	if (errno == EIO)
		printf("ptrace(PTRACE_SETREGSET, NT_ARM_HW_WATCH) not supported on this hardware: %s\n",
			strerror(errno));

	printf("ptrace(PTRACE_SETREGSET, NT_ARM_HW_WATCH) failed: %s\n",
		strerror(errno));
	return false;
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

int main() {
    int status;
    pid_t wpid;
    siginfo_t siginfo;
    
    volatile char *ptr = (char*)mmap((void*)(SIZE), SIZE /** 2*/, PROT_WRITE /*| PROT_MTE */, MAP_PRIVATE /* | MAP_SHARED*/ | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (ptr == MAP_FAILED) {
        perror("mmap");
        return 1;
    }
    else {
        printf("ptr = %p\n", ptr);
    }
    pid_t child = fork();
    if (child == 0) {
        pin_to_core(3);
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) != 0) {
            printf("ptrace(PTRACE_TRACEME) failed: %s\n", strerror(errno));
            _exit(1);
        }
        if (raise(SIGSTOP) != 0) {
            printf("raise(SIGSTOP) failed: %s\n", strerror(errno));
            _exit(1);
        }
        memset((void*)ptr, 'A', SIZE);
        // *ptr = 0xAC;
        
        int fd = open("/dev/ipac_watchpoint", O_RDWR);
        if (fd < 0) {
            perror("Failed to open the device");
            return -1;
        }

        printf("display watchpoint\n");
        struct watchpoint_set_request state = {0};
        int ret = ioctl(fd, IOCTL_SHOW_WATCHPOINT, &state);
        if (ret < 0) {
            perror("ioctl failed");
            close(fd);
            return -1;
        }
        print_watchpoint(&state);

        // state.ctrl |= (0x1fUL << 24);
        // state.ctrl |= (0xcUL << 24);
        // ret = ioctl(fd, IOCTL_SET_WATCHPOINT, &state);
        // if (ret < 0) {
        //     perror("ioctl failed");
        //     close(fd);
        //     return -1;
        // }
        // printf("\n!!!!!!!!!!!!!\n");
        
        // ret = ioctl(fd, IOCTL_SHOW_WATCHPOINT, &state);
        // if (ret < 0) {
        //     perror("ioctl failed");
        //     close(fd);
        //     return -1;
        // }
        // print_watchpoint(&state);

        printf("write successfully!\n");
        printf("try to read:\n");
        // munmap((void*)ptr, SIZE);

        // pin_to_core(1);
        __u32 orig_ctrl = state.ctrl;
        for (int mask_bits = 2; mask_bits <= 5; mask_bits++) {
            int mask = (1UL << mask_bits) - 1;
            state.ctrl = orig_ctrl | (mask << 24);
            ret = ioctl(fd, IOCTL_SET_WATCHPOINT, &state);
            if (ret < 0) {
                perror("ioctl failed");
                close(fd);
                return -1;
            }
            ret = ioctl(fd, IOCTL_SHOW_WATCHPOINT, &state);
            if (ret < 0) {
                perror("ioctl failed");
                close(fd);
                return -1;
            }

            print_watchpoint(&state);
            printf("ptr[%x]:\n", SIZE - 1);
            printf("0x%x\n", ptr[SIZE - 1]);
            printf("\n");
        }
        
        printf("ptr[0]:\n");
        printf("0x%x\n", ptr[0]);
        exit(1);
    }
    
	wpid = waitpid(child, &status, __WALL);
	if (wpid != child) {
		printf("waitpid() failed: %s\n", strerror(errno));
		return false;
	}
	if (!WIFSTOPPED(status)) {
		printf("child did not stop: %s\n", strerror(errno));
		return false;
	}
	if (WSTOPSIG(status) != SIGSTOP) {
		printf("child did not stop with SIGSTOP\n");
		return false;
	}

	if (!set_watchpoint(child, /*SIZE*/ 8, (void*)ptr))
		return false;

	if (ptrace(PTRACE_CONT, child, NULL, NULL) < 0) {
		printf("ptrace(PTRACE_CONT) failed: %s\n", strerror(errno));
		return false;
	}
    
    return 0;
}
