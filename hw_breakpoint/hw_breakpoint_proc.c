#include <linux/errno.h>
#include <linux/version.h>
#include <linux/delay.h>
#include <linux/mii.h>
#include <linux/mdio.h>
#include <linux/proc_fs.h>
#include <linux/spinlock.h>
#include "linux/printk.h"
#include <linux/random.h>
#include "ext_hw_breakpoint.h"
#include "hw_breakpoint_until.h"

#define PROC_FILE "breakpoint"
#define PROC_FILE_LOG "breakpoint_log"

#define LOG_BUF_SIZE 4096

static char log_buf[LOG_BUF_SIZE];
static size_t log_pos;
static spinlock_t log_lock;

/*proc_file handle*/
static struct proc_dir_entry *proc_file = NULL;
static struct proc_dir_entry *proc_log = NULL;

/* 每个 CPU 的日志缓冲区 */
struct hw_bp_log_cpu {
	char buf[LOG_BUF_SIZE];
	unsigned int pos;
};

static struct proc_dir_entry *proc_log;
static DEFINE_PER_CPU(struct hw_bp_log_cpu, cpu_logs);

/*help*/
char *hw_proc_write_usag = {
	"Usage:\n"
	"\thw_break support cmd type: \n"
	"\t\t1: echo add <type> <len> <symbol>/<addr> > /proc/breakpoint, add a breakpoint\n"
	"\t\t\t[type]:\n"
	"\t\t\t\t[wp1]: HW_BREAKPOINT_R\n"
	"\t\t\t\t[wp2]: HW_BREAKPOINT_W\n"
	"\t\t\t\t[wp3]: HW_BREAKPOINT_R|HW_BREAKPOINT_W\n"
	"\t\t\t\t[bp]:  HW_BREAKPOINT_X\n"
	"\t\t\t[len]:[0,8] (2^3,2^31]\n"
	"\t\t2: echo del <symbol> > /proc/breakpoint, del a breakpoint\n"
	"\t\t3: echo get ptr/val <symbol> > /proc/breakpoint, search &symbol/*(&symbol)\n"
	"\t\t4: echo iophy <ioaddr> > /proc/breakpoint, search all of ioaddr map virt\n"
};
/*example
echo add wp1 17272832 0xffff800080010000 > /proc/breakpoint
*/
char *hw_proc_write_example = {
	"Example:\n"
	"\tThe first step:\n"
	"\t\techo add wp3 4 hw_test_value0 > /proc/breakpoint, add a watchpoint at "
	"&hw_test_value0\n"
	"\tThe second step:\n"
	"\t\techo write 0 0 > /proc/breakpoint, write hw_test_value0\n"
	"\tThe third step:\n"
	"\t\techo read 0 0 > /proc/breakpoint, read hw_test_value0\n"
	"\tThe forth step:\n"
	"\t\techo del hw_test_value0 > /proc/breakpoint, del wawtchpoint at "
	"&hw_test_value0\n"
};

/*seq show*/
static int hw_proc_show(struct seq_file *m, void *v)
{
	hw_bp_info_list *info = NULL, *node = NULL;
	int i = 0, index = 0;

	/*get info*/
	info = hw_get_bp_infos();
	if (info) {
		list_for_each_entry(node, &info->list, list) {
			for (i = 0; i < node->cpu_num; i++) {
				if (node->cpu_mask & (1 << i)) {
					break;
				}
			}
			seq_printf(m, "----------------[%d]----------------\n",
				   index++);
			seq_printf(m, "type: \t0x%x\n", node->attr[i].type);
			seq_printf(m, "addr: \t0x%llx\n", node->attr[i].addr);
			seq_printf(m, "len: \t0x%llx\n", node->attr[i].len);
			seq_printf(m, "mask: \t0x%x\n", node->attr[i].mask);
			for (i = 0; i < node->cpu_num; i++) {
				if (!(node->cpu_mask & (1 << i))) {
					continue;
				}
				seq_printf(m, "cpu[%d] trigger times:\n", i);
				seq_printf(
					m,
					"\tread: %llu, write: %llu, exec: %llu\n",
					node->attr[i].times.read,
					node->attr[i].times.write,
					node->attr[i].times.exec);
			}
		}
		hw_free_bp_infos(info);
	}
	return 0;
}

static int hw_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, hw_proc_show, inode->i_private);
}

u32 hw_test_value3[32] = { 0 };
u32 hw_test_value2[32] = { 0 };
u32 hw_test_value1[32] = { 0 };
u32 hw_test_value0[32] = { 0 };

/*show vm info*/
static void hw_show_vm(struct vm_struct *area, u64 phy_addr)
{
	pr_info("--------------------------------------------------\n");
	if (area->phys_addr) {
		pr_info("\tphy addr:\t0x%llx\n", area->phys_addr);
	}
	if (area->addr) {
		pr_info("\tvirt addr:\t0x%llx\n", (u64)area->addr);
	}
	if (area->size) {
		pr_info("\tsize:\t\t0x%lx\n", area->size);
	}
	if (area->addr && area->phys_addr) {
		pr_info("0x%llx to virt: 0x%llx\n", phy_addr,
			(u64)area->addr + phy_addr - area->phys_addr);
	}
	pr_info("\n");
}

/*proc get virt of iophys*/
static void hw_iophy_to_virt(char *addr_buf)
{
	u64 io_addr = 0;
	iophys_info *iophys = NULL, *node = NULL;

	io_addr = simple_strtol(addr_buf, NULL, 0);
	iophys = get_iophys_info(io_addr);

	if (iophys) {
		list_for_each_entry(node, &iophys->list, list) {
			hw_show_vm(&node->area, io_addr);
		}
	}
	free_iophys_info(iophys);
}

/*proc get handler*/
static int hw_proc_get(char *type_buf, char *name_buf)
{
	u64 addr = 0;

	/*get symbol addr*/
	addr = HW_SYMS_FUNC(kallsyms_lookup_name)(name_buf);
	if (!addr || addr < TASK_SIZE) {
		pr_info("can not find symbol %s\n", name_buf);
		return -1;
	}
	if (strcmp("ptr", type_buf) == 0) {
		pr_info("&%s = 0x%llx\n", name_buf, addr);
	} else if (strcmp("val", type_buf) == 0) {
		pr_info("*(%s) = 0x%llx\n", name_buf, *((u64 *)addr));
	} else {
		return -1;
	}
	return 0;
}

/*proc del bp*/
static void hw_proc_del(char *name_buf)
{
	u64 uninstall_addr = 0;

	if (name_buf[0] == '0' && name_buf[1] == 'x') {
		uninstall_addr = simple_strtol(name_buf, 0, 0);
	}
	if (uninstall_addr) {
		pr_info("will uninstall at 0x%llx\n", uninstall_addr);
		hw_bp_uninstall_from_addr(uninstall_addr);
	} else {
		pr_info("will uninstall at &%s\n", name_buf);
		hw_bp_uninstall_from_symbol(name_buf);
	}
}

/*proc add bp*/
static int hw_proc_add(char *type_buf, char *len_buf, char *name_buf)
{
	char *name = NULL;
	int len = HW_BREAKPOINT_LEN_4, type = 0;
	u64 install_addr = 0;

	/*check bp type*/
	switch (strlen(type_buf)) {
	/*The length is 2 for the bp*/
	case 2: {
		type = HW_BREAKPOINT_X;
		name = name_buf;
		break;
	}
	/*The length is 3 for the wp, and the third character is the breakpoint type*/
	case 3: {
		type = type_buf[2] - '0';
		len = (int)simple_strtoul(len_buf, NULL, 0);
		name = name_buf;
		break;
	}
	default: {
		return -1;
	}
	}
	/*check type if valid*/
	if (type < 1 || type > 4) {
		return -1;
	}

	if (name_buf[0] == '0' && name_buf[1] == 'x') {
		install_addr = simple_strtol(name_buf, 0, 0);
	}
	if (install_addr) {
		pr_info("will install at 0x%llx\n", install_addr);
		hw_bp_install_from_addr(install_addr, len, type, NULL);
	} else {
		pr_info("will install at &%s\n", name);
		hw_bp_install_from_symbol(name, len, type, NULL);
	}
	return 0;
}

/*test write*/
static void hw_proc_rw_test(char *cmd, char *index_of_buf, char *index_in_buf)
{
	int index = (int)simple_strtol(index_of_buf, NULL, 0);
	int index1 = (int)simple_strtol(index_in_buf, NULL, 0);
	u32 *tmpbuf;
	switch (index) {
	case 0: {
		tmpbuf = hw_test_value0;
		break;
	}
	case 1: {
		tmpbuf = hw_test_value1;
		break;
	}
	case 2: {
		tmpbuf = hw_test_value2;
		break;
	}
	case 3:
	default: {
		tmpbuf = hw_test_value3;
		break;
	}
	}
	if (strcmp("write", cmd) == 0) {
		pr_info("will write hw_test_value%d[%d], addr = %llx\n", index,
			index1, (u64)&tmpbuf[index1]);
		tmpbuf[index1] = get_random_u32();
	} else if (strcmp("read", cmd) == 0) {
		pr_info("will read hw_test_value%d[%d], addr = %llx\n", index,
			index1, (u64)&tmpbuf[index1]);
		pr_info("hw_test_value%d[%d] = %d\n", index, index1,
			tmpbuf[index1]);
	}
}

static ssize_t hw_proc_write(struct file *file, const char __user *p_buf,
			     size_t count, loff_t *pPos)
{
	size_t ret;
	char cmd_buf[128] = { 0 };
	int argc = 0;
	char *argv[10] = { NULL };

	// pr_info("hw_proc_write\n");

	if ((count > sizeof(cmd_buf)) || (count == 0)) {
		pr_info("test proc write, count is error!\n");
		return (ssize_t)count;
	}

	memset(cmd_buf, 0, sizeof(cmd_buf));
	ret = copy_from_user(cmd_buf, p_buf, count);
	if (0 != ret) {
		pr_info("fail to copy data from user!\n");
		return (ssize_t)count;
	}

	cmd_buf[count - 1] = '\0';
	memset(argv, 0, sizeof(argv));
	process_cmd_string(cmd_buf, &argc, argv);

	if (strcmp("write", argv[0]) == 0 || strcmp("read", argv[0]) == 0) {
		if (argc != 3) {
			goto cmdErr;
		}
		hw_proc_rw_test(argv[0], argv[1], argv[2]);
		return (ssize_t)count;
	} else if (strcmp("show", argv[0]) == 0) {
		hw_bp_show_all();
		return (ssize_t)count;
	} else if (strcmp("help", argv[0]) == 0) {
		pr_info("%s", hw_proc_write_usag);
		pr_info("%s", hw_proc_write_example);
		return (ssize_t)count;
	}

	if (strcmp("add", argv[0]) == 0) {
		if (argc != 4) {
			// pr_info("argc = %d\n",argc);
			goto cmdErr;
		}
		if (hw_proc_add(argv[1], argv[2], argv[3])) {
			goto cmdErr;
		}
	} else if (strcmp("del", argv[0]) == 0) {
		if (argc != 2) {
			// pr_info("argc = %d\n",argc);
			goto cmdErr;
		}
		hw_proc_del(argv[1]);
	} else if (strcmp("get", argv[0]) == 0) {
		if (argc != 3) {
			// pr_info("argc = %d\n",argc);
			goto cmdErr;
		}
		if (hw_proc_get(argv[1], argv[2])) {
			goto cmdErr;
		}
	} else if (strcmp("iophy", argv[0]) == 0) {
		if (argc != 2) {
			// pr_info("argc = %d\n",argc);
			goto cmdErr;
		}
		hw_iophy_to_virt(argv[1]);
	} else {
		goto cmdErr;
	}

	return (ssize_t)count;
cmdErr:
	pr_info("cmd error, echo help > /proc/breakpoint\n");
	return (ssize_t)count;
}

/* 汇总所有 CPU buffer */
static int hw_bp_log_show(struct seq_file *m, void *v)
{
	int cpu;

	for_each_online_cpu(cpu) {
		struct hw_bp_log_cpu *log = per_cpu_ptr(&cpu_logs, cpu);
		unsigned long flags;
		local_irq_save(flags);
		if (log->pos > 0)
			seq_write(m, log->buf, log->pos);
		local_irq_restore(flags);
	}
	return 0;
}

static int hw_bp_log_open(struct inode *inode, struct file *file)
{
    return single_open(file, hw_bp_log_show, NULL);
}

/* 写入日志到本 CPU buffer */
void hw_bp_log(const char *fmt, ...)
{
	va_list args;
	unsigned long flags;
	struct hw_bp_log_cpu *log;

	log = this_cpu_ptr(&cpu_logs);

	va_start(args, fmt);
	local_irq_save(flags); // 仅保护本 CPU
	int len = vscnprintf(log->buf + log->pos, LOG_BUF_SIZE - log->pos, fmt, args);
	log->pos += len;
	if (log->pos >= LOG_BUF_SIZE - 1)
		log->pos = 0; // 覆盖写
	local_irq_restore(flags);
	va_end(args);
}

static const struct proc_ops hw_proc_fops = {
	.proc_open = hw_proc_open,
	.proc_write = hw_proc_write,
	.proc_read = seq_read,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
};

static const struct proc_ops hw_bp_log_fops = {
    .proc_open    = hw_bp_log_open,
    .proc_read    = seq_read,
    .proc_lseek   = seq_lseek,
    .proc_release = single_release,
};

int hw_proc_init(void)
{
	int cpu;
	
	for_each_online_cpu(cpu) {
		struct hw_bp_log_cpu *log = per_cpu_ptr(&cpu_logs, cpu);
		log->pos = 0;
	}
	
	proc_file = proc_create(PROC_FILE, 0666, NULL,
				&hw_proc_fops);
	
	if (NULL == proc_file) {
		pr_info("hw proc init, Create %s proc file failed!\n",
			PROC_FILE);
		return -ENOMEM;
	}
	
	proc_log = proc_create(PROC_FILE_LOG, 0444, NULL, &hw_bp_log_fops);
	if (NULL == proc_log) {
		pr_info("hw proc init, Create %s proc file failed!\n",
			PROC_FILE_LOG);
		return -ENOMEM;
	}

	// pr_info(hw_proc_write_usag);
	// pr_info(hw_proc_write_example);
	return 0;
}

void hw_proc_exit(void)
{
	if (NULL != proc_file) {
		remove_proc_entry(PROC_FILE, NULL);
	}
	if (NULL != proc_log) {
		remove_proc_entry(PROC_FILE_LOG, NULL);
	}
}
