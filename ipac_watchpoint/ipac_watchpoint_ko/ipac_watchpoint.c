// this driver works for arm platform.

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/platform_device.h>
#include <linux/gpio.h>
#include <linux/fs.h>
#include <linux/errno.h>
#include <asm/uaccess.h>
#include <linux/version.h>
#include <linux/types.h>
#include <linux/kdev_t.h>
#include <linux/device.h>
#include <linux/cdev.h>
#include <linux/kallsyms.h>
#include <linux/tty.h>
#include <linux/file.h>
#include <linux/notifier.h>
#include <linux/kdebug.h>
#include <asm/esr.h> 

#define GPIO_NUMBER    149     // User LED 0. GPIO number 149. Page 71 of BB-xM Sys Ref Manual.
#define IOCTL_SET_WATCHPOINT _IO('k', 1)
#define IOCTL_SHOW_WATCHPOINT _IO('k', 2)

static dev_t first;             // Global variable for the first device number
static struct cdev c_dev;       // Global variable for the character device structure
static struct class *cl;        // Global variable for the device class

typedef unsigned int __u32;
typedef unsigned long long __u64;

struct watchpoint_set_request {
    __u64	addr;
    __u32	ctrl;
    __u32	id;
};

static char *set_devnode(const struct device *dev, umode_t *mode)
{
    if (!mode) return NULL;
    *mode = 0666;
    return NULL;
}

/* Accessor macros for the debug registers. */
#define ARM_DBG_READ(N, M, OP2, VAL) do {\
	asm volatile("mrc p14, 0, %0, " #N "," #M ", " #OP2 : "=r" (VAL));\
} while (0)

#define ARM_DBG_WRITE(N, M, OP2, VAL) do {\
	asm volatile("mcr p14, 0, %0, " #N "," #M ", " #OP2 : : "r" (VAL));\
} while (0)


static int wp_die_handler(struct notifier_block *nb,
                          unsigned long val, void *data)
{
    struct die_args *args = data;
    unsigned int ec;

    ec = ESRC_ELx_EC(args->err);  // 从 ESR_EL1 提取 EC 字段

    // ARM64 Watchpoint from lower EL
    if (ec == ESR_ELx_EC_WATCHPT_EL1) {  // 0x34
        pr_info("Watchpoint hit at PC=0x%lx\n", args->regs->pc);
        return NOTIFY_STOP;
    }

    return NOTIFY_DONE;
}

static struct notifier_block wp_nb = {
    .notifier_call = wp_die_handler,
    .priority = INT_MAX,
};


static void set_wp_each_cpu(void* info)
{
    struct watchpoint_set_request *state = info;
    uint64_t mdscr_el1_val, oslsr_el1_val, oslar_el1_val, osdlr_el1_val, daif_val;
    pr_info("set wp on CPU %d\n", smp_processor_id());

    // set mdscr_el1.mde
    asm volatile("mrs %x0, mdscr_el1" : "=r"(mdscr_el1_val));
    printk("orig mdscr_el1: 0x%llx", mdscr_el1_val);
    mdscr_el1_val |= (1UL << 15);
    asm volatile("msr mdscr_el1, %x0" :: "r"(mdscr_el1_val));
    // asm volatile("mrs %x0, mdscr_el1" : "=r"(mdscr_el1_val));
    // printk("new mdscr_el1: 0x%llx", mdscr_el1_val);

    // clear process state D mask
    asm volatile("mrs %x0, daif" : "=r"(daif_val));
    printk("orig daif: 0x%llx", daif_val);
    // daif_val &= (~(1UL << 9));
    // asm volatile("msr daif, %x0" :: "r"(daif_val));

    asm volatile("mrs %x0, oslsr_el1" : "=r"(oslsr_el1_val));
    printk("orig oslsr_el1: 0x%llx", oslsr_el1_val);

    // oslar_el1 is write-only, cannot be read!
    oslar_el1_val = 0;
    asm volatile("msr oslar_el1, %x0\n\t" :: "r"(oslar_el1_val));
    osdlr_el1_val = 0;
    asm volatile("msr osdlr_el1, %x0\n\t" :: "r"(osdlr_el1_val));

    printk("watchpoint addr: 0x%llx, ctrl: %x", state->addr, state->ctrl);
    asm volatile("msr dbgwvr0_el1, %x0\n\t" :: "r"(state->addr));
    asm volatile("msr dbgwcr0_el1, %x0\n\t" :: "r"(state->ctrl));

    state->addr = 0;
    state->ctrl = 0;
    asm volatile("mrs %x0, dbgwvr0_el1\n\t" : "=r"(state->addr));
    asm volatile("mrs %x0, dbgwcr0_el1\n\t" : "=r"(state->ctrl));
    printk("watchpoint addr: 0x%llx, ctrl: %x", state->addr, state->ctrl);

    asm volatile("isb\n\t");
    
}



static void show_wp_each_cpu(void* info)
{
    int res;
    struct watchpoint_set_request state;
    asm volatile("mrs %x0, dbgwvr0_el1\n\t" : "=r"(state.addr));
    asm volatile("mrs %x0, dbgwcr0_el1\n\t" : "=r"(state.ctrl));
    state.id = 0;
    res = copy_to_user(info, &state, sizeof(state));
}

// ioctl handler
long ioctl_handler(struct file *file, unsigned int cmd, unsigned long arg)
{
    int res;
    struct watchpoint_set_request state;
    // Handle the ioctl command
    if (cmd == IOCTL_SET_WATCHPOINT) {
        res = copy_from_user(&state, (void*)arg, sizeof(state));
        if (res) {
            printk("copy_from_user(%p) failed!", (void*)arg);
            return -1;
        }
        on_each_cpu(set_wp_each_cpu, &state, 1);
    }
    else if (cmd == IOCTL_SHOW_WATCHPOINT) {
        on_each_cpu(show_wp_each_cpu, (void*)arg, 1);

    }

    return 0;
}

// File operations structure
static const struct file_operations fops = {
    .unlocked_ioctl = ioctl_handler,
};
 
static int __init ipac_watchpoint_init(void)
{
    int init_result = alloc_chrdev_region(&first, 0, 1, "ipac_watchpoint");
 
    if (init_result > 0)
    {
        printk(KERN_ALERT "Device(ipac_watchpoint) Registration failed\n");
        return -1;
    }
 
    if ((cl = class_create("chardev")) == NULL)
    {
        printk(KERN_ALERT "Class creation failed\n");
        unregister_chrdev_region(first, 1);
        return -1;
    }
    cl->devnode = set_devnode;
    if (device_create(cl, NULL, first, NULL, "ipac_watchpoint") == NULL)
    {
        printk(KERN_ALERT "Device(ipac_watchpoint) creation failed\n");
        class_destroy(cl);
        unregister_chrdev_region(first, 1);
        return -1;
    }
 
    cdev_init(&c_dev, &fops);
 
    if (cdev_add(&c_dev, first, 1) == -1)
    {
        printk(KERN_ALERT "Device(ipac_watchpoint) addition failed\n");
        device_destroy(cl, first);
        class_destroy(cl);
        unregister_chrdev_region(first, 1);
        return -1;
    }
    int res2 = register_die_notifier(&wp_nb);
    return 0;
}
 
static void __exit ipac_watchpoint_exit(void)
{
    cdev_del(&c_dev);
    device_destroy(cl, first);
    class_destroy(cl);
    unregister_chrdev_region(first, 1);
 
    printk(KERN_ALERT "Device(ipac_watchpoint) unregistered\n");
}
 
module_init(ipac_watchpoint_init);
module_exit(ipac_watchpoint_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Peng mingfan");
MODULE_DESCRIPTION("ipac watchpoint-ioctl driver");
