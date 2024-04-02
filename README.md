# LSM_RBAC
## 1.LSM框架模块编写
在linux-2.6.x版本之后,已经不允许在内核运行过程中动态添加模块,我们需要将写好的模块放入linux内核源码当中
然后调整`Kconfig`和`Makefile`,然后重新编译内核
## 2.RBAC设计
### 1.相关配置文件
这里采用一个权限文件`role_config`,该文件记录了所有权限对象的集合,他存放在`/etc/rbac/role_config`中
```c
role_mouse:RMDIR,RENAME,MKDIR;
role_cow:RENAME,RMDIR;
role_tiger:RMDIR,MKDIR;
role_rabbit:RENAME,MKDIR;
role_dragon:MKDIR;
role_snake:RENAME;
role_horse:RMDIR;
```
然后有一个用户对应的`user_config`,该文件记录了适用该RBAC模式的用户以及其对应的不同种类的权限,它存放在`/etc/rbac/user_config当中`
```c
1001:role_tiger
1002:role_cow:
1003:role_tiger:
```

最后还有一个文件用来控制LSM模块的启动/关闭,`/etc/rbac/gate_config`,该文件内容若为`T`则表示开启,`F`表示关闭

### 2.LSM模块
这里本来最开始是打算动态加载LKM,但是实现过程中查找网上资料发现位于内核源码中的`security_add_hooks`这个函数
需要修改内核源码`security/security.c`,在源码当中填入`EXPORT_SYMBOL(security_add_hooks);`
但是我查看当前内核的`/proc/kallsyms`文件时发现该文件已经经过导出,但是在加载我整个模块的时候调用`security_add_hooks`
函数时直接失败了,因此我将程序重写,通过添加到内核源码的方式进行编写

这里主要是添加了三种钩子`mkdir,rmdir,rename`

```c
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
    LSM_HOOK_INIT(inode_mkdir, mkdir_hook),
    LSM_HOOK_INIT(inode_rmdir, rmdir_hook),
    LSM_HOOK_INIT(inode_rename, rename_hook)
};
```


