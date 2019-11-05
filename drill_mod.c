/*
 * The module for kernel exploiting experiments
 */

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/debugfs.h>
#include <linux/uaccess.h>

#define NELEMS(x)  (sizeof(x) / sizeof((x)[0]))
#define ACT_SIZE 5

enum drill_act_t {
    DRILL_ACT_NONE = 0,
    DRILL_ACT_ALLOC = 1,
    DRILL_ACT_CALLBACK = 2,
    DRILL_ACT_FREE = 3,
    DRILL_ACT_RESET = 4
};


struct dentry *drill_dir;

#define DRILL_ITEM_SIZE 3300

struct drill_act_item_t {
    u32 foo;
    void (*callback)(void);
    char bar[1];
};

struct drill_act_item_t *drill_act_item;

static void drill_act_callback(void) {
    pr_notice("normal drill_act_callback %lx!\n",
              (unsigned long)drill_act_callback);
}

static int drill_act_exec(long act)
{
    int ret = 0;

    switch (act) {
    case DRILL_ACT_ALLOC:
        drill_act_item = kmalloc(DRILL_ITEM_SIZE, GFP_KERNEL);
        if (drill_act_item == NULL) {
            pr_err("drill: not enough memory for item\n");
            ret = -ENOMEM;
            break;
        }

        pr_notice("drill: kmalloc'ed item at %lx (size %d)\n",
                  (unsigned long)drill_act_item, DRILL_ITEM_SIZE);

        drill_act_item->callback = drill_act_callback;
        break;

    case DRILL_ACT_CALLBACK:
        pr_notice("drill: exec callback %lx for item %lx\n",
                  (unsigned long)drill_act_item->callback,
                  (unsigned long)drill_act_item);
        drill_act_item->callback(); /* No check, BAD BAD BAD */
        break;

    case DRILL_ACT_FREE:
        pr_notice("drill: free item at %lx\n",
                  (unsigned long)drill_act_item);
        kfree(drill_act_item);
        break;

    case DRILL_ACT_RESET:
        drill_act_item = NULL;
        pr_notice("drill: set item ptr to NULL\n");
        break;

    default:
        pr_err("drill: invalid act %ld\n", act);
        ret = -EINVAL;
        break;
    }

    return ret;
}

static ssize_t drill_act_write(struct file *file, const char __user *user_buf,
                               size_t count, loff_t *ppos)
{
    ssize_t ret = 0;
    char buf[ACT_SIZE] = { 0 };
    size_t size = ACT_SIZE - 1;
    long new_act = 0;

    BUG_ON(*ppos != 0);

    if (count < size)
        size = count;

    if (copy_from_user(&buf, user_buf, size)) {
        pr_err("drill: act_write: copy_from_user failed\n");
        return -EFAULT;
    }

    buf[size] = '\0';
    new_act = simple_strtol(buf, NULL, 0);

    ret = drill_act_exec(new_act);
    if (ret == 0)
        ret = count; /* success, claim we got the whole input */

    return ret;
}

static const struct file_operations drill_act_fops = {
    .write = drill_act_write,
};

///////////////////////////////////////////////////////
//////////////////////////////////////////////////////

struct drill_bof_s {
    int pointer;
    unsigned long long int drill_bof_stack[64];
    ssize_t (*drill_bof_read)(struct file *f, char __user *buf, size_t len, loff_t *off);
};

static struct drill_bof_s drill_bof;

static int drill_bof_open(struct inode *i, struct file *f)
{
    printk(KERN_INFO "drill_bof: open()\n");
    return 0;
}

static int drill_bof_close(struct inode *i, struct file *f)
{
    printk(KERN_INFO "drill_bof: close()\n");
    return 0;
}

static ssize_t drill_bof_read(struct file *f, char __user *buf, size_t len, loff_t *off)
{
    printk(KERN_INFO "drill_bof: read()\n");
    return(drill_bof.drill_bof_read)(f, buf, len, off);
}

static ssize_t drill_bof_read_hexa(struct file *f, char __user *buf, size_t len, loff_t *off)
{
    printk(KERN_INFO "drill_bof: read_hexa()\n");
    if (drill_bof.pointer > 0)
        return(snprintf(buf,len,"%16llx\n",drill_bof.drill_bof_stack[--drill_bof.pointer]));
    else return(0);
}

static ssize_t drill_bof_read_dec(struct file *f, char __user *buf, size_t len, loff_t *off)
{
    printk(KERN_INFO "drill_bof: read_dec()\n");
    if (drill_bof.pointer > 0)
        return(snprintf(buf,len,"%lld\n",drill_bof.drill_bof_stack[--drill_bof.pointer]));
    else return(0);
}

static ssize_t drill_bof_write(struct file *f, const char __user *buf,size_t len, loff_t *off)
{
    char *bufk;
    printk(KERN_INFO "drill_bof: write()\n");
    bufk = kmalloc(len + 1, GFP_DMA);
    if (bufk) {
        if (copy_from_user(bufk, buf, len))
            return -EFAULT;
        bufk[len] = '\0';
        if (bufk[0]=='M') {
            if (bufk[1]=='H') drill_bof.drill_bof_read = drill_bof_read_hexa;
            else if (bufk[1]=='D') drill_bof.drill_bof_read = drill_bof_read_dec;
        }
        else {
            printk("drill_bof: insertion %d\n",*((int *) bufk));
            drill_bof.drill_bof_stack[drill_bof.pointer++] = *((long long int *) bufk);;
        }
    }
    kfree(bufk);
    return len;
}

static const struct file_operations drill_bof_fops =
{
    .owner = THIS_MODULE,
    .open = drill_bof_open,
    .release = drill_bof_close,
    .read = drill_bof_read,
    .write = drill_bof_write
};

////////////////////////////////////////////////////
////////////////////////////////////////////////////

#define IOCTL_DRILL_COPY -0xff

struct drill_copy_request {
    void * src;
    void * dest;
    unsigned short cnt;
};

static int drill_copy_open(struct inode *i, struct file *f)
{
    printk(KERN_INFO "drill_copy: open()\n");
    return 0;
}

static long drill_copy_ioctl(struct file *file, unsigned int cmd,
                             unsigned long arg) {
    int nbytes;
    struct drill_copy_request s;
    switch (cmd) {
    case IOCTL_DRILL_COPY:
        if ((nbytes = copy_from_user(&s, (void *) arg, sizeof s)) != 0)
            return -EFAULT;
        memcpy(s.dest, s.src, s.cnt);
        break;
    default:
        break;
    }
    return 0;
}

static int drill_copy_close(struct inode *i, struct file *f)
{
    printk(KERN_INFO "drill_copy: close()\n");
    return 0;
}

static const struct file_operations drill_copy_fops = {
    .owner          = THIS_MODULE,
    .open           = drill_copy_open,
    .unlocked_ioctl = drill_copy_ioctl,
    .release        = drill_copy_close,
};

////////////////////////////////////////////////////
////////////////////////////////////////////////////

#define IOCTL_DRILL_CALL -0x100

static int drill_call_open(struct inode *i, struct file *f)
{
    printk(KERN_INFO "drill_call: open()\n");
    return 0;
}

static int drill_call_close(struct inode *i, struct file *f)
{
    printk(KERN_INFO "drill_call: close()\n");
    return 0;
}

struct drill_call_request {
    void * addr;
    long int arg1;
    long int arg2;
    long int arg3;
};

static long drill_call_ioctl(struct file *file, unsigned int cmd,
                             unsigned long arg) {
    int nbytes;
    struct drill_call_request s;
    switch (cmd) {
    case IOCTL_DRILL_CALL:
        if ((nbytes = copy_from_user(&s, (void *) arg, sizeof s)) != 0)
            return -EFAULT;
        int (*arbitrary_call)(long int, long int, long int) = (int(*)(long int, long int, long int))s.addr;
        printk(KERN_INFO "drill_call: Executing %p with 3 args: %lx %lx %lx\n", s.addr, s.arg1, s.arg2, s.arg3);
        return arbitrary_call(s.arg1, s.arg2, s.arg3);
        break;
    default:
        break;
    }
    return 0;
}

static const struct file_operations drill_call_fops = {
    .owner          = THIS_MODULE,
    .open           = drill_call_open,
    .unlocked_ioctl = drill_call_ioctl,
    .release        = drill_call_close,
};

////////////////////////////////////////////////////
////////////////////////////////////////////////////


struct drill_module {
    char * name;
    const struct file_operations * fops_ptr;
    int perm;
};

struct drill_module drill_modules[]= {
    { .name = "drill_act", .fops_ptr = &drill_act_fops, .perm = S_IWUGO},
    { .name = "drill_bof", .fops_ptr = &drill_bof_fops, .perm = S_IWUGO | S_IRUGO},
    { .name = "drill_copy", .fops_ptr = &drill_copy_fops, .perm = S_IWUGO | S_IRUGO},
    { .name = "drill_call", .fops_ptr = &drill_copy_fops, .perm = S_IWUGO | S_IRUGO},
};

static int __init drill_init(void)
{
    struct dentry *cur_file = NULL;

    pr_notice("drill: start hacking\n");

    drill_dir = debugfs_create_dir("drill", NULL);
    if (drill_dir == ERR_PTR(-ENODEV) || drill_dir == NULL) {
        pr_err("creating drill dir failed\n");
        return -ENOMEM;
    }

    for (int i=0; i < NELEMS(drill_modules); i++)
    {
        cur_file = debugfs_create_file(drill_modules[i].name, S_IWUGO,
                                       drill_dir, NULL, drill_modules[i].fops_ptr);
        if (cur_file == ERR_PTR(-ENODEV) || cur_file == NULL) {
            pr_err("creating %s file failed\n", drill_modules[i].name);
            debugfs_remove_recursive(drill_dir);
            return -ENOMEM;
        }
    }

    return 0;
}

static void __exit drill_exit(void)
{
    pr_notice("drill: stop hacking\n");
    debugfs_remove_recursive(drill_dir);
}

module_init(drill_init)
module_exit(drill_exit)

MODULE_AUTHOR("Alexander Popov <alex.popov@linux.com>");
MODULE_DESCRIPTION("The module for kernel exploiting experiments");
MODULE_LICENSE("GPL v2");
