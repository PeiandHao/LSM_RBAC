# LSM_RBAC
## 1.权限相关设计
这里采用一个权限文件`role_config`,该文件记录了所有权限的集合
```c
role_mouse:RMDIR,RENAME,MKDIR;
role_cow:RENAME,RMDIR;
role_tiger:RMDIR,MKDIR;
role_rabbit:RENAME,MKDIR;
role_dragon:MKDIR;
role_snake:RENAME;
role_horse:RMDIR;
```

```c
1001:role_tiger:
1002:role_cow:
1003:role_tiger:
```
