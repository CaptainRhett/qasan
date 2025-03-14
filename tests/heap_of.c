#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    char buffer[16];  // 固定大小的缓冲区
    void (*func)();   // 函数指针
} HeapStruct;

void hacked() {
    printf("Buffer Overflow Exploited! Code Execution Achieved!\n");
}

int main() {
    HeapStruct *ptr = (HeapStruct *)malloc(sizeof(HeapStruct));
    ptr->func = NULL;  // 初始化函数指针

    printf("Enter input: ");
    gets(ptr->buffer);  // gets() 不检查输入长度，容易导致溢出

    if (ptr->func) {
        ptr->func();  // 如果攻击成功，覆盖的地址会被执行
    } else {
        printf("No exploit detected!\n");
    }

    free(ptr);
    return 0;
}
