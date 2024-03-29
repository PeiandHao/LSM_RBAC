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
    printf("\033[33;3m[3] MODIFY THE USER FOR CHECKING\033[0m\n");
    printf("\033[34;4m[4] DELETE THE USER FROM USER_CONFIG\033[0m\n");
    printf("\033[35;5m[5] MODIFY THE ROLE FOR CHECKING\033[0m\n");
    printf("\033[36;6m[6] DELETE THE ROLE FROM ROLE_CONFIG\033[0m\n");
    printf("Please Input your choice >");
}

struct rbac_role {
    char name[0x10];
    int role_cap;
};

struct rbac_role * get_role(){
    int fd = open(ROLECONFIG, O_RDONLY);
    struct rbac_role *role_arr = (struct rbac_role *)zalloc(sizeof(struct rbac_role)*0x10);
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

int modify_user(void){
    int fd = open(USERCONFIG, O_RDWR);
    int m_uid = -1;
    char buf[0x50] = {0};
    char *token;
    if(fd < 0){
        printf("[x]you have no permission!");
        return 0;
    }
    printf("give me the uid\n");
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
                           write(fd, LSM_ENABLED, 1);
                           close(fd);
                       }else{
                           printf("[x]You have no permission!\n");
                           return 0;
                       }
                    }
            case 2:{
                       if((fd = open(GATECONFIG, O_RDWR)) > 0){
                           lseek(fd, 0, SEEK_SET);
                           write(fd, LSM_DISABLED, 1);
                           close(fd);
                       }else{
                           printf("[x]You have no permission!\n");
                           return 0;
                       }
                   }
            case 3:{
                       modify_user();
                   }
        }
        break;
    } 
    return 0;
}

