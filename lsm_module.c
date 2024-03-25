#include <linux/security.h>
#include <linux/module.h>
#include <linux/lsm_hooks.h>
#include <linux/fs.h>
#include <linux/errno.h>
#include <linux/err.h>
#include <linux/string.h>
#include <linux/sched.h>
#include <linux/dcache.h>
#include <asm/fcntl.h>
#include <asm/processor.h>
#include <asm/uaccess.h>
#include <linux/uidgid.h>
#include <linux/cred.h>

#define RBAC_CONFIG_PATH "/etc/config/"
#define RBAC_USER_CONFIG "/etc/config/user_config"
#define RBAC_ROLE_CONFIG "/etc/config/role_config"

#define SYSCALL_MKDIR 1
#define SYSCALL_RENAME 2
#define SYSCALL_RMDIR 4

char role_list[3][10] = {"MKDIR\0", "RENAME\0", "RMDIR\0"};

static int lsm_init(void){
    printk(KERN_WARNING "[LSM_INIT]\n");
    return 0;
}

static void lsm_exit(void){
    printk(KERN_WARNING "[LSM_EXIT]\n");
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("peiwithhao");
MODULE_DESCRIPTION("My practice LSM based RBAC...");

module_init(lsm_init);
module_exit(lsm_exit);
