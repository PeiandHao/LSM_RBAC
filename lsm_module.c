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

size_t mkdir_hook();
size_t rmdir_hook();
size_t rename_hook();

size_t lsm_enabled();

size_t mkdir_auth();
size_t rmdir_auth();
size_t rename_hook();

size_t get_user_config();

size_t get_user_config(void){
    printk(KERN_WARNING "[Get the current user]");
    struct user_struct *user = get_current_user();
    int cur_uid = user->uid.val;
    printk("[Current uid is %d\n]", cur_uid);

    char buf[0x400], cur_role[0x100] = {0};
    struct file *f = filp_open(RBAC_USER_CONFIG, O_RDONLY, 0);
    if(IS_ERR(f) || (f == NULL)){
        printk(KERN_WARNING "get user config error. \n");
        return 0;
    }


    

}
size_t mkdir_hook(struct inode *dir, stct dentry *dentry){
    size_t gate = lsm_enabled();
    if(!gate){
        return 0;
    }
    printk("[Hook mkdir successfully!]");
    
}

/*
 * Path:include/linux/lsm_hooks.h
 * Description:Security module hook list structure
 *             For use with generic list macros for common operations
 * 
 * */
struct security_hook_list hooks[] = {
    /* Desc:Initializeing a security_hook_list structure takes 
     * up a lot of space in a source file. This macro takes 
     * care of the common case and reduces the amount of 
     * text incolved
     * */
    LSM_HOOK_INIT(inode_mkdir, mkdir_hook);
    LSM_HOOK_INIT(inode_rmdir, rmdir_hook);
    LSM_HOOK_INIT(inode_rename, rename_hook);
};

static int lsm_init(void){
    printk(KERN_WARNING "[LSM_INIT]\n");
    security_add_hooks(hooks,ARRAY_SIZE(hooks));
    return 0;
}

static void lsm_exit(void){
    printk(KERN_WARNING "[LSM_EXIT]\n");
    int i, count=ARRAY_SIZE(hooks);
    for(int i = 0; i < count; i++){
        list_del_rcu(&hooks[i].list);
    }
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("peiwithhao");
MODULE_DESCRIPTION("My practice LSM based RBAC...");

module_init(lsm_init);
module_exit(lsm_exit);
