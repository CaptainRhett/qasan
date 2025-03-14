#include <stdio.h>
#include <string.h>
#include<stdlib.h>

void vulnerable_function() {
    char buffer[16];  // 小缓冲区
    char *a;
    a = (char*)malloc(sizeof(char));
    printf("输入数据: ");
    gets(buffer);     // 危险函数：不检查输入长度
    *a = buffer[1];
    printf("输入内容: %c\n", *a);
    free(a);
    
    a = (char*)malloc(sizeof(char));
    printf("输入数据: ");
    gets(buffer);     // 危险函数：不检查输入长度
    *a = buffer[1];
    printf("输入内容: %c\n", *a);
    free(a);

    a = (char*)malloc(sizeof(char));
    printf("输入数据: ");
    gets(buffer);     // 危险函数：不检查输入长度
    *a = buffer[1];
    printf("输入内容: %c\n", *a);
    // free(a);
}

int main() {
    vulnerable_function();
    return 0;
}