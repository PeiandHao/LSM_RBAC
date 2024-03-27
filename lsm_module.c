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
#define RBAC_GATE_CONFIG "/etc/config/gate_config"

#define LSM_GATE "T"
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
size_t read_line(struct file *f, char *buf, size_t size, size_t *f_pos);
void split_string(char *vuln, char dilever);

size_t get_user_config();

size_t read_line(struct file *f, char *buf, size_t *f_pos){
    size_t read_bytes = 0;
    char byte;
    while(1){
        if(f->ops->read(f, &byte, 1, f_pos) <= 0){
            break;
        }
        if(!strcmp(byte, "\n")){
            break;
        }
        buf[read_bytes++] = byte;
    }
    return read_bytes;
}

int str2int(char *str){
    int result;
    if(kstrtol(str, 10, &result) != 0){
        return -EINVAL;
    }
    return result;
}

size_t get_user_config(void){
    
    size_t user_cap = 0;
    char *token;

    printk(KERN_WARNING "[Get the current user]");
    struct user_struct *user = get_current_user();
    int cur_uid = user->uid.val;
    printk("[Current uid is %d\n]", cur_uid);

    char buf[0x400], cur_role[0x100] = {0};

    /* Get user config and the  */
    struct file *f = filp_open(RBAC_USER_CONFIG, O_RDONLY, 0);
    if(IS_ERR(f) || (f == NULL)){
        printk(KERN_WARNING "get user config error. \n");
        goto GET_CONFIG_ERR;
    }
    if(!f->ops || !f->ops->read){
        printk(KERN_WARNING "read failed...\n");
        goto GET_CONFIG_ERR;
    }
    while(read_line(f, buf, 0)){
        if(!(token=strsep(&buf, ':'))){
            goto GET_CONFIG_ERR;
        }
        if(str2int(token) == cur_uid){
            token = strsep(&buf, ':');
            break;
        }
    }
    /* Get the capability by token */

GET_CONFIG_ERR:
    filp_close(f);
    return 0;
}

/*
 * lsm_enabled():Judge the lsm_module if it has been opened by root
 * return: 1 for open, 0 for close
 * */
size_t lsm_enabled(){
    void buf[0x400] = {0};
    size_t count = 0;
    size_t f_pos = 0;
    struct file *f = filp_open(RBAC_GATE_CONFIG, O_RDONLY, 0);
    if(IS_ERR(f) || (f == NULL)){
        printk(KERN_WARNING "get gate config error. \n");
        goto ERROR_FILE;
    }
    if( !f->ops || f->ops->read){
        printk(KERN_WARNING "the file ops has wrong config!:(");
        goto ERROR_FILE;
    } 

    count = f->ops->read(f, buf, sizeof(buf), &f_pos);
    if(count < 0){
        printk(KERN_WARNING "read failed...");
        goto ERROR_FILE;
    }

    filp_close(f);
    return !strcmp(buf,LSM_GATE);        

ERROR_FILE:
    filp_close(f);
    return 0;
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
