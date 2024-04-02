#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#define USERCONFIG "etc/config/user_config"
#define ROLECONFIG "etc/config/role_config"
#define GATECONFIG "etc/config/gate_config"
#define LSM_ENABLED  "T"
#define LSM_DISABLED "F"
#define MKDIR  1
#define RENAME 2
#define RMDIR 4
#define SYS_MKDIR "MKDIR"
#define SYS_RENAME  "RENAME"
#define SYS_RMDIR   "RMDIR"

void menu(){
    printf("\033[31;1m[1] OPEN THE LSM BASED RBAC\033[0m\n");
    printf("\033[32;2m[2] CLOSE THE LSM BASED RBAC\033[0m\n");
    printf("\033[33;3m[3] SHOW THE HOLE ROLE SET\033[0m\n");
    printf("\033[34;4m[4] BIND THE USER WITH ROLE\033[0m\n");
    printf("\033[35;5m[5] SET THE USER-ROLE MAPPING\033[0m\n");
    printf("\033[36;6m[6] ADD THE ROLE TYPE\033[0m\n");
    printf("Please Input your choice >");
}

struct rbac_role {
    char name[0x10];
    int role_cap;
};

struct rbac_role * get_role(){
    int fd = open(ROLECONFIG, O_RDONLY);
    struct rbac_role *role_arr = (struct rbac_role *)malloc(sizeof(struct rbac_role)*0x10);
    if(fd < 0){
        printf("[x]Open role_config failed\n");
        return 0;
    }
    char buf[0x50] = {0};
    char *token;
    token = buf;
    int i = 0;
    int role_num = 0;
    while(read(fd, buf+i, 1) == 1){
        if(buf[i] == ':'){
            buf[i] = '\0';
            memcpy(role_arr[role_num++].name, token, sizeof(token));
            token = buf + i + 1;
        }else if(buf[i] == ','){
            buf[i] = '\0';
            if(strcmp(token, SYS_MKDIR))
                role_arr[role_num].role_cap |= MKDIR;
            else if(strcmp(token, SYS_RENAME))
                role_arr[role_num].role_cap |= RENAME;
            else if(strcmp(token, SYS_RMDIR))
                role_arr[role_num].role_cap |= RMDIR;
            token = buf+i+1;
        }else if(buf[i] == '\n'){
            token = buf+i+1;
        }
        i++;
    }
    return role_arr;
}

void show_role(){
    int fd = open(ROLECONFIG, O_RDONLY);
    if(fd < 0){
        printf("[x]Open Failed\n");
        return ;
    }
    char buf[0x50] = {0};
    int read_bytes = read(fd, buf, sizeof(buf));
    if(read_bytes < 0){
        printf("[x]read failed\n");
        return;
    }
    write(1, buf, sizeof(buf));
    return;
}

int bind_role(void){
    int fd = open(USERCONFIG, O_RDWR);
    int m_uid = -1;
    char buf[0x50] = {0};
    char *token;
    if(fd < 0){
        printf("[x]you have no permission!");
        return 0;
    }
    printf("give me the uid:\n");
    scanf("%d", &m_uid);
    if(m_uid <= 0){
        printf("[x]Wrong uid!\n");
        return 0;
    }
    token = buf; 
    int i = 0;
    int flag = 0;
    while(read(fd, buf+i, 1) == 1){
        if(buf[i] == ':'){
            buf[i] = '\0';
            if(m_uid == atoi(token)){
                flag = 1;
                break;
            }
            token = buf+i+1;
        }else if(buf[i] == '\n'){
            buf[i] = '\0';
            token = buf+i+1;
        }
        i++;
    }
    if(!flag){
        printf("[x]No such user...\n");
        close(fd);
        return 0;
    }
    /* 获取全局的role */
    struct rbac_role * role_ptr = get_role();
    show_role();
    printf("[+]Choose your role for binding:");
    int choice; 
    scanf("%d", &choice);
    if(write(fd, role_ptr[choice].name, sizeof(role_ptr[choice].name))) 
        printf("[+]Write successfully..");
    close(fd);
    return 0;
}

void user_role_map(){
    show_role();
    printf("[*]Nice Try,You can add the map by <uid:role_type>");
}

void add_role_type(){
    printf("[*]Nice Try,You can add the new type by <role_name:MKDIR/RMDIR/RENAME with ',' for split>");
}

int main()
{
    int choice = 0;
    int fd = 0;
    while(1){
        menu();
        scanf("%d", &choice);
        switch(choice){
            case 1:{
                       if((fd = open(GATECONFIG, O_RDWR)) > 0){
                           lseek(fd, 0, SEEK_SET);
                           if(write(fd, LSM_ENABLED, 1) < 0){
                               close(fd);
                               perror("write faild");
                               exit(1);
                           } 
                           close(fd);
                       }else{
                           printf("[x]You have no permission!\n");
                           return 0;
                       }
                       break;
                    }
            case 2:{
                       if((fd = open(GATECONFIG, O_RDWR)) > 0){
                           lseek(fd, 0, SEEK_SET);
                           if(write(fd, LSM_DISABLED, 1) < 0){
                               close(fd);
                               perror("write faild");
                               exit(1);
                           }
                           close(fd);
                       }else{
                           printf("[x]You have no permission!\n");
                           return 0;
                       }
                       break;
                   }
            case 3:{
                       show_role();
                       break;
                   }
            case 4:{
                       bind_role();
                       break;
                   }
            case 5:{
                       user_role_map();
                       break;
                   }
            case 6:{
                       add_role_type();
                       break;
                   }

        }
    } 
    return 0;
}

