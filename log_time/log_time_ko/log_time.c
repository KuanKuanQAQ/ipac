#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/atomic.h>
#include <linux/uaccess.h>
#include <linux/proc_fs.h>

#define LOG_ENTRIES 10000000

struct trace_entry {
    u64 time_ns;
    const char *func;
    u8 type; // 0=entry, 1=exit
};

static struct trace_entry *trace_buf;
static atomic64_t trace_index = ATOMIC64_INIT(0);

static inline u64 read_cntvct(void)
{
    u64 cnt;
    asm volatile("mrs %0, cntvct_el0" : "=r"(cnt));
    return cnt;
}

static inline u64 read_cntfrq(void)
{
    u64 freq;
    asm volatile("mrs %0, cntfrq_el0" : "=r"(freq));
    return freq;
}

static inline u64 cntvct_to_ns(u64 cnt)
{
    static u64 freq;
    if (unlikely(!freq))
        freq = read_cntfrq();
    return (cnt * 1000000000ULL) / freq;
}

void log_time(const char *func, bool is_exit)
{
    u64 idx = atomic64_fetch_add(1, &trace_index);
    if (idx < LOG_ENTRIES) {
        struct trace_entry *e = &trace_buf[idx];
        e->time_ns = cntvct_to_ns(read_cntvct());
        e->func = func;
        e->type = is_exit;
    }
}
EXPORT_SYMBOL(log_time);

static ssize_t trace_read(struct file *file, char __user *buf,
                          size_t count, loff_t *ppos)
{
    u64 n = atomic64_read(&trace_index);
    size_t size = n * sizeof(struct trace_entry);
    return simple_read_from_buffer(buf, count, ppos,
                                   trace_buf, size);
}

static const struct proc_ops trace_proc_ops = {
    .proc_read = trace_read,
};

static int __init log_time_init(void)
{
    trace_buf = kvzalloc(LOG_ENTRIES * sizeof(struct trace_entry), GFP_KERNEL);
    if (!trace_buf)
        return -ENOMEM;
    proc_create("timelog", 0444, NULL, &trace_proc_ops);
    pr_info("log_time: initialized, buffer size=%lu entries\n",
            LOG_ENTRIES);
    return 0;
}

static void __exit log_time_exit(void)
{
    remove_proc_entry("timelog", NULL);
    kvfree(trace_buf);
    pr_info("log_time: exited\n");
}

module_init(log_time_init);
module_exit(log_time_exit);

MODULE_LICENSE("GPL");
