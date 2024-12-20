#include <stdio.h>
#include <sys/utsname.h>

int main() {
    struct utsname sys_info;

    // 获取操作系统信息
    if (uname(&sys_info) == 0) {
        printf("System name: %s\n", sys_info.sysname);    // 操作系统名称
        printf("Node name: %s\n", sys_info.nodename);    // 主机名
        printf("Release: %s\n", sys_info.release);        // 操作系统版本
        printf("Version: %s\n", sys_info.version);        // 内核版本
        printf("Machine: %s\n", sys_info.machine);        // 机器架构
    } else {
        perror("uname failed");
    }

    return 0;
}
