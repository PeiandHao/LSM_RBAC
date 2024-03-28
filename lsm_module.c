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
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/types.h>

#define RBAC_CONFIG_PATH "/etc/config/"
#define RBAC_USER_CONFIG "/etc/config/user_config"
#define RBAC_ROLE_CONFIG "/etc/config/role_config"
#define RBAC_GATE_CONFIG "/etc/config/gate_config"

#define LSM_GATE_OPEN "T"
#define LSM_GATE_CLOSE "F"
#define SYSCALL_MKDIR 1
#define SYSCALL_RENAME 2
#define SYSCALL_RMDIR 4

#define PASS 0
#define NOPASS EINVAL

char role_list[3][10] = {"MKDIR\0", "RENAME\0", "RMDIR\0"};

int get_user_config(void);

int read_line(struct file *f, char *buf, int *f_pos){
    int read_bytes = 0;
    char byte;
    while(1){
        if(vfs_read(f, &byte, 1, &f->f_pos) <= 0){
            break;
        }
        if(!strcmp(&byte, "\n")){
            break;
        }
        buf[read_bytes++] = byte;
    }
    return read_bytes;
}

int str2int(char *str){
    long tmp;
    if(kstrtol(str, 10, &tmp) != 0){
        return -EINVAL;
    }
    return (int)tmp;
}

int get_user_config(void){
    
    int user_cap = 0;
    char *token;
    int i, flag = 0;

    printk(KERN_WARNING "[Get the current user]");
    struct user_struct *user = get_current_user();
    int cur_uid = user->uid.val;
    printk("[Current uid is %d\n]", cur_uid);

    char buf[0x400], cur_role[0x30] = {0};

    /* Get user config and the  */
    struct file *f = filp_open(RBAC_USER_CONFIG, O_RDONLY, 0);
    if(IS_ERR(f) || (f == NULL)){
        printk(KERN_WARNING "get user config error. \n");
        goto GET_CONFIG_ERR;
    }
    /* u16 oldfs; */
    /* /1* 獲取當前地址空間類型 *1/ */
    /* oldfs = get_fs(); */
    /* set_fs(KERNEL_DS); */
    token = buf;
    i = 0;
    while(vfs_read(f, buf+i, 1, &f->f_pos) == 1){
        if(buf[i] == ':'){
            buf[i] = '\0';
            if(str2int(token) == cur_uid){
                flag = 1;
                token = buf+i+1;
            }
        }else if(buf[i] == ';'){
            if(flag){
                buf[i-1] = '\0'; 
                printk("cur_role: %s\n", token);
                strcpy(cur_role, token);
            }
        }
        i++;
    }

    /* failed for finding the user */
    filp_close(f, 0);
    if(flag == 0) return 0;
    
    /* Get the capability by token */
    token = buf;
    i = 0;
    f= filep_open(RBAC_ROLE_CONFIG, O_RDONLY, 0);   
    if(IS_ERR(f)){
        goto GET_CONFIG_ERR; 
    }
    flag= 0;
    while(vfs_read(f, buf+i, 1, &f->f_pos) == 1){
        if(buf[i] == ':'){
            buf[i] = '\0';
            if(!strcmp(token, cur_role)){
                flag = 1;
            }
            token = buf+i+1;
        }else if(buf[i] == ',' || buf[i] == ';'){
            buf[i] = '\0';
            if(flag){
                if(!strcmp("RMDIR", token)) user_cap |= RMDIR;
                else if(!strcmp("RENAME", token)) user_cap |= RENAME;
                else if(!strcmp("MKDIR", token)) user_cap |= MKDIR;
                else printk(KERN_WARNING "invalid capability");
            }
            token = buf+i+1;
        }else if(buf[i] == '\n'){
            if(flag){
                break;
            }
            token = buf+i+1;
        }
        i++;
    }
    if(!flag) return 0;
    filp_close(f, 0);
    return user_cap;

GET_CONFIG_ERR:
    filp_close(f, 0);
    return 0;
}

/*
 * lsm_enabled():Judge the lsm_module if it has been opened by root
 * return: 1 for open, 0 for close
 * */
int lsm_enabled(){
    void buf[0x400] = {0};
    int count = 0;
    int f_pos = 0;
    struct file *f = filp_open(RBAC_GATE_CONFIG, O_RDONLY, 0);
    if(IS_ERR(f) || (f == NULL)){
        printk(KERN_WARNING "get gate config error. \n");
        goto ERROR_FILE;
    }
    count = vfs_read(f, buf, sizeof(buf), &f->f_pos);
    if(count < 0){
        printk(KERN_WARNING "read failed...");
        goto ERROR_FILE;
    }

    filp_close(f, 0);
    return !strcmp(buf,LSM_GATE);        

ERROR_FILE:
    filp_close(f, 0);
    return 0;
}

int check_rename_auth(int cur_role){
    if(cur_role && RENAME){  
        return 1;
    }else
        return 0;
}
int rename_hook(struct inode *dir, stct dentry *dentry){
    int gate = lsm_enabled();
    int cur_cap;
    int flag;
    if(!gate){
        return 0;
    }
    printk("[Hook rename successfully!]");
    cur_cap = get_user_config();
    flag = check_rename_auth(cur_cap);
    if(flag){
        return PASS;
    }else{
        return NOPASS;
    }
}
int check_rmdir_auth(int cur_role){
    if(cur_role && RMDIR){  
        return 1;
    }else
        return 0;
}
int rmdir_hook(struct inode *dir, stct dentry *dentry){
    int gate = lsm_enabled();
    int cur_cap;
    int flag;
    if(!gate){
        return 0;
    }
    printk("[Hook rmdir successfully!]");
    cur_cap = get_user_config();
    flag = check_rmdir_auth(cur_cap);
    if(flag){
        return PASS;
    }else{
        return NOPASS;
    }
}

int check_mkdir_auth(int cur_role){
    if(cur_role && MKDIR){  
        return 1;
    }else
        return 0;
}
int mkdir_hook(struct inode *dir, stct dentry *dentry){
    int gate = lsm_enabled();
    int cur_cap;
    int flag;
    if(!gate){
        return 0;
    }
    printk("[Hook mkdir successfully!]");
    cur_cap = get_user_config();
    flag = check_mkdir_auth(cur_cap);
    if(flag){
        return PASS;
    }else{
        return NOPASS;
    }
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
