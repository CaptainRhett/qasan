// bypass_fcgi_accept.c
#include <stdio.h>
int FCGI_Accept() {
    printf("[HOOK] Skipping FCGI_Accept() and returning directly.\n");
    return 0;
}