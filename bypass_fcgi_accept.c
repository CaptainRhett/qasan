// bypass_fcgi_accept.c
#include <stdio.h>
int FCGI_Accept() {
    fprintf(stderr,"[HOOK] Skipping FCGI_Accept() and returning directly.\n");
    return 0;
}