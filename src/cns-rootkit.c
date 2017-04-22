#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>

MODULE_LICENSE("MIT");
MODULE_AUTHOR("SAV");


static int cns_rootkit_init(void) {
  printk(KERN_INFO "cns-rootkit: Init\n");
  return 0;
}

static void cns_rootkit_exit(void) {
  printk(KERN_INFO "cns-rootkit: Exit\n");
}

module_init(cns_rootkit_init);
module_exit(cns_rootkit_exit);
