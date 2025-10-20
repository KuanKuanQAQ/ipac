// file: dbg_dump.c
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/smp.h>
#include <linux/seq_file.h>

#define PROC_NAME "dbg_dump"
#define CMD_BUF_SZ 64

// 假设 dbgwvr 和 dbgwcr 各有 4 个！
struct dump_req {
	int idx;    /* 0..3 */
	int cpu;    /* -1 表示 all CPU，否则指定 CPU */
};

static inline u64 read_dbgwvr_n(int idx)
{
	u64 val = 0;

	switch (idx) {
	case 0: asm volatile("mrs %0, dbgwvr0_el1" : "=r"(val)); break;
	case 1: asm volatile("mrs %0, dbgwvr1_el1" : "=r"(val)); break;
	case 2: asm volatile("mrs %0, dbgwvr2_el1" : "=r"(val)); break;
	case 3: asm volatile("mrs %0, dbgwvr3_el1" : "=r"(val)); break;
	default: val = 0; break;
	}
	return val;
}

static inline u64 read_dbgwcr_n(int idx)
{
	u64 val = 0;

	switch (idx) {
	case 0: asm volatile("mrs %0, dbgwcr0_el1" : "=r"(val)); break;
	case 1: asm volatile("mrs %0, dbgwcr1_el1" : "=r"(val)); break;
	case 2: asm volatile("mrs %0, dbgwcr2_el1" : "=r"(val)); break;
	case 3: asm volatile("mrs %0, dbgwcr3_el1" : "=r"(val)); break;
	default: val = 0; break;
	}
	return val;
}

static void print_dbgregs_oncpu(void *arg)
{
	struct dump_req *req = arg;
	u64 wvr, wcr;
	int idx = req->idx;
	int cpu = smp_processor_id();

	preempt_disable();

	if (idx < 0 || idx > 3) {
		pr_info("CPU%d: invalid index %d\n", cpu, idx);
		goto out;
	}

	wvr = read_dbgwvr_n(idx);
	wcr = read_dbgwcr_n(idx);

	pr_info("CPU%d: DBGWVR%d_EL1 = 0x%016llx, DBGWCR%d_EL1 = 0x%016llx\n",
		cpu, idx, (unsigned long long)wvr, idx, (unsigned long long)wcr);

out:
	preempt_enable();
}

static ssize_t dbg_proc_write(struct file *file, const char __user *buffer,
			      size_t count, loff_t *ppos)
{
	char cmd[CMD_BUF_SZ];
	int idx = 0;
	int cpu = -1;
	int ret;
	struct dump_req req;

	if (count == 0 || count >= CMD_BUF_SZ)
		return -EINVAL;

	if (copy_from_user(cmd, buffer, count))
		return -EFAULT;
	cmd[count] = '\0';

	/*  dump all
	 *  dump <idx>
	 *  dump <idx> <cpu>
	 */
	if (sscanf(cmd, "dump all") == 0) {
		if (strncmp(cmd, "dump all", 8) == 0) {
			idx = 0;
			cpu = -1;
		}
	} 

	ret = sscanf(cmd, "dump %d %d", &idx, &cpu);
	if (ret == 2) {
		/* parsed idx and cpu */
	} else {
		ret = sscanf(cmd, "dump %d", &idx);
		if (ret == 1)
			cpu = -1;
		else {
			if (strncmp(cmd, "dump all", 8) == 0) {
				idx = 0;
				cpu = -1;
			} else {
				pr_info("dbg_dump: invalid command: '%s'\n", cmd);
				return -EINVAL;
			}
		}
	}

	if (idx < 0 || idx > 3) {
		pr_info("dbg_dump: idx out of range (0..3): %d\n", idx);
		return -EINVAL;
	}

	req.idx = idx;
	req.cpu = cpu;

	if (cpu == -1) {
		on_each_cpu(print_dbgregs_oncpu, &req, 1);
	} else {
		if (!cpu_online(cpu)) {
			pr_info("dbg_dump: cpu %d not online\n", cpu);
			return -EINVAL;
		}
		smp_call_function_single(cpu, print_dbgregs_oncpu, &req, 1);
	}

	return count;
}

static const struct proc_ops dbg_proc_ops = {
	.proc_write = dbg_proc_write,
};

static int __init dbg_dump_init(void)
{
	if (!proc_create(PROC_NAME, 0220, NULL, &dbg_proc_ops)) {
		pr_err("dbg_dump: failed to create /proc/%s\n", PROC_NAME);
		return -ENOMEM;
	}

	pr_info("dbg_dump module loaded. Use: echo 'dump <idx> [cpu]' > /proc/%s\n", PROC_NAME);
	pr_info("Examples: echo 'dump 0' > /proc/%s ; echo 'dump 1 2' > /proc/%s ; echo 'dump all' > /proc/%s\n",
		PROC_NAME, PROC_NAME, PROC_NAME);
	return 0;
}

static void __exit dbg_dump_exit(void)
{
	remove_proc_entry(PROC_NAME, NULL);
	pr_info("dbg_dump module unloaded.\n");
}

module_init(dbg_dump_init);
module_exit(dbg_dump_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Runkuan Li");
MODULE_DESCRIPTION("On-demand per-CPU DBGWVR/DBGWCR dumper (arm64)");