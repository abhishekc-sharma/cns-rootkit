#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>

MODULE_LICENSE("MIT");
MODULE_AUTHOR("SAV");


static int cns_rootkit_init(void) {
  printk(KERN_INFO "Init cns-rootkit\n");
  return 0;
}

static void cns_rootkit_exit(void) {
  printk(KERN_INFO "Exit cns-rootkit\n");
}

module_init(cns_rootkit_init);
module_exit(cns_rootkit_exit);
