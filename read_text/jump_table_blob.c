// jump_table_blob.c
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/seq_file.h>
#include <linux/smp.h>
#include <linux/slab.h>
#include <linux/types.h>

#define PROC_NAME "jump_exec"
#define PROC_BUF  128

MODULE_LICENSE("GPL");
MODULE_AUTHOR("assistant");
MODULE_DESCRIPTION("Demo: jump_table + asm blob in .text and runtime read/call control");

static struct proc_dir_entry *proc_entry;

/* ------------------------------
 * 1) a few simple functions to be used in the jump table
 * ------------------------------ */
static void jt_func0(void) { pr_info("jt_func0 called\n"); }
static void jt_func1(void) { pr_info("jt_func1 called\n"); }
static void jt_func2(void) { pr_info("jt_func2 called\n"); }
static void jt_func3(void) { pr_info("jt_func3 called\n"); }

typedef void (*jt_fn_t)(void);

/* ------------------------------
 * 2) jump table: an array of function pointers
 *    (non-const so it is likely placed in .data; change to const to put in .rodata)
 * ------------------------------ */
#define JT_SIZE 4

/* helper to create/init the jump table */
static void create_jump_table(void)
{
    jt_fn_t jump_table[JT_SIZE];
    jump_table[0] = jt_func0;
    jump_table[1] = jt_func1;
    jump_table[2] = jt_func2;
    jump_table[3] = jt_func3;

    pr_info("jump_table created at %p, entries:\n", (void *)jump_table);
    for (int i = 0; i < JT_SIZE; ++i)
        pr_info("  jump_table[%d] = %p\n", i, (void *)jump_table[i]);
}

/* ------------------------------
 * 3) assembly blob placed explicitly into .text section
 *
 * We define a symbol asm_blob_start and asm_blob_data (the data label).
 * We put some 8-byte constants (for 64-bit). For 32-bit it will still be assembled,
 * but values are 64-bit sized.
 * ------------------------------ */

extern const char asm_blob_start[];  /* symbol defined in asm below */
extern const char asm_blob_data[];   /* start of data in the blob */
extern const char asm_blob_end[];

__asm__(
    ".pushsection .text\n"
    ".global asm_blob_start\n"
    "asm_blob_start:\n"
    "    /* a small instruction; keep it a valid function prologue neutral */\n"
    "    nop\n"
    "    /* data block follows: placed in .text deliberately */\n"
    ".global asm_blob_data\n"
    "asm_blob_data:\n"
#ifdef __x86_64__
    "    .quad 0x1122334455667788ULL\n"
    "    .quad 0x8877665544332211ULL\n"
#elif defined(__aarch64__)
    "    .8byte 0x1122334455667788\n"
    "    .8byte 0x8877665544332211\n"
#else
    "    .quad 0x1122334455667788ULL\n"
    "    .quad 0x8877665544332211ULL\n"
#endif
    ".global asm_blob_end\n"
    "asm_blob_end:\n"
    "    nop\n"
    ".popsection\n"
);

/* ------------------------------
 * 4) function that reads jump_table and the asm blob data
 *    This performs read accesses to both the table and the code-embedded data.
 *    Optionally calls one entry from jump_table.
 * ------------------------------ */
static void do_read_table_and_blob(int do_call)
{
    /* read the jump_table entries (data access) */
    pr_info("do_read_table_and_blob: reading jump_table at %p\n", (void *)jump_table);
    for (int i = 0; i < JT_SIZE; ++i) {
        jt_fn_t f = READ_ONCE(jump_table[i]); /* ensure read memory */
        pr_info("  read jump_table[%d] -> %p\n", i, (void *)f);
        if (do_call && f)
            f();
    }

    /* read the asm blob data (located in .text) */
    {
        const u64 *p = (const u64 *)asm_blob_data;
        size_t n = ((const char *)asm_blob_end - (const char *)asm_blob_data) / sizeof(u64);
        pr_info("asm_blob_data at %p, contains %zu 8-byte values:\n", p, n);
        for (size_t i = 0; i < n; ++i) {
            u64 v = READ_ONCE(p[i]); /* read as data */
            pr_info("  blob[%zu] = 0x%llx\n", i, (unsigned long long)v);
        }
    }
}

/* ------------------------------
 * 5) proc interface to control execution
 *    write "run 1" to call do_read_table_and_blob(1)
 * ------------------------------ */
static char proc_buf[PROC_BUF];
static int run_flag = 0;

static ssize_t proc_write(struct file *file, const char __user *buf, size_t count, loff_t *ppos)
{
    int ret;
    if (count >= PROC_BUF) return -EINVAL;
    if (copy_from_user(proc_buf, buf, count)) return -EFAULT;
    proc_buf[count] = '\0';

    /* simple parse: "run 0" or "run 1" or "status" */
    if (sscanf(proc_buf, "run %d", &run_flag) == 1) {
        pr_info("proc: set run_flag=%d\n", run_flag);
        if (run_flag)
            do_read_table_and_blob(1);
        return count;
    } else if (strncmp(proc_buf, "do", 2) == 0) {
        /* do immediate read & print without setting persistent flag */
        do_read_table_and_blob(1);
        return count;
    } else {
        pr_info("proc: unknown cmd '%s'\n", proc_buf);
        return -EINVAL;
    }
}

static int proc_show(struct seq_file *m, void *v)
{
    seq_printf(m, "run_flag = %d\n", run_flag);
    seq_printf(m, "jump_table at %p (size=%d)\n", (void *)jump_table, JT_SIZE);
    seq_printf(m, "asm_blob_start = %p\n", (void *)asm_blob_start);
    seq_printf(m, "asm_blob_data  = %p\n", (void *)asm_blob_data);
    seq_printf(m, "asm_blob_end   = %p\n", (void *)asm_blob_end);
    return 0;
}

static int proc_open(struct inode *inode, struct file *file)
{
    return single_open(file, proc_show, NULL);
}

static const struct proc_ops proc_fops = {
    .proc_open    = proc_open,
    .proc_read    = seq_read,
    .proc_write   = proc_write,
    .proc_lseek   = seq_lseek,
    .proc_release = single_release,
};

/* ------------------------------
 * module init / exit
 * ------------------------------ */
static int __init jtbl_init(void)
{
    pr_info("jump_table_blob module init\n");

    create_jump_table();

    pr_info("Addresses (printed at init):\n");
    pr_info("  &jt_func0 = %p\n", (void *)jt_func0);
    pr_info("  &jt_func1 = %p\n", (void *)jt_func1);
    pr_info("  &jt_func2 = %p\n", (void *)jt_func2);
    pr_info("  &jt_func3 = %p\n", (void *)jt_func3);
    pr_info("  jump_table = %p\n", (void *)jump_table);
    pr_info("  asm_blob_start = %p\n", (void *)asm_blob_start);
    pr_info("  asm_blob_data  = %p\n", (void *)asm_blob_data);
    pr_info("  asm_blob_end   = %p\n", (void *)asm_blob_end);

    proc_entry = proc_create(PROC_NAME, 0666, NULL, &proc_fops);
    if (!proc_entry) {
        pr_err("failed to create /proc/%s\n", PROC_NAME);
        return -ENOMEM;
    }

    return 0;
}

static void __exit jtbl_exit(void)
{
    pr_info("jump_table_blob module exit\n");
    if (proc_entry)
        proc_remove(proc_entry);
}

module_init(jtbl_init);
module_exit(jtbl_exit);