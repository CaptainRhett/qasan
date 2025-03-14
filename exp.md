# qemu build指令
./build.py --cross=arm-linux-gnueabi-gcc --arch=arm --debug

# 使用qasan检测spx_restservice软件
指令
./qasan-qemu -L /home/wuhuang/fuzz/qasan/cramfs-root -E LD_PRELOAD=/home/wuhuang/fuzz/qasan/libqasan/libqasan.so ./spx_restservice
 报错
 ./spx_restservice: /lib/arm-linux-gnueabi/libc.so.6: version `GLIBC_2.34' not found (required by /home/wuhuang/fuzz/qasan/host-libs/libqasan.so)
 ./spx_restservice: /lib/arm-linux-gnueabi/libc.so.6: version `GLIBC_2.38' not found (required by /home/wuhuang/fuzz/qasan/host-libs/libqasan.so)

指令
./qasan-qemu -E LD_PRELOAD=/home/wuhuang/fuzz/qasan/host-libs/libqasan.so ./spx_restservice 
 报错
 ./spx_restservice: error while loading shared libraries: libsafesystem.so.2: cannot open shared object file: No such file or directory

指令
./qasan-qemu -E LD_PRELOAD=/home/wuhuang/fuzz/qasan/libqasn/libqasan.so -L /home/wuhuang/fuzz/qasan/cramfs-root ./spx_restservice
 报错
 ./spx_restservice: /lib/arm-linux-gnueabi/libc.so.6: version `GLIBC_2.34' not found (required by /home/wuhuang/fuzz/qasan/host-libs/libqasan.so)
 ./spx_restservice: /lib/arm-linux-gnueabi/libc.so.6: version `GLIBC_2.38' not found (required by /home/wuhuang/fuzz/qasan/host-libs/libqasan.so)

指令
./qasan-qemu -E LD_PRELOAD=/usr/local/lib/afl/libqasan.so -L /home/wuhuang/fuzz/qasan/cramfs-root -g 1234./spx_restservice
ERROR: ld.so: object '/usr/local/lib/afl/libqasan.so' from LD_PRELOAD cannot be preloaded: ignored.
[1133996 : 1133996 CRITICAL][rest.c:1103]Error while terminating web session!
[1133996 : 1133998 INFO][Info]: InspurWebMonitorTask Is Created Sucessfully!

content-type: text/html

./qasan-qemu -E LD_PRELOAD=/home/wuhuang/fuzz/qasan/libqasan/libqasan.so -L /home/wuhuang/fuzz/qasan/cramfs-root ./spx_restservice
/home/wuhuang/fuzz/qasan/libqasan/libqasan.so
# 尝试解决
## 使用更早期的编译器
我在linaro上找到路更早的版本（是该网站提供的最早的版本），并使用其编译libqasan：
指令：
/home/wuhuang/fuzz/qasan/gcc-linaro-4.9-2016.02-x86_64_arm-linux-gnueabi/bin/arm-linux-gnueabi-gcc -fPIC -shared -I ../include/ libqasan.c hooks.c malloc.c string.c uninstrument.c 
报错：
patch.c dlmalloc.c -o libqasan.so -ldl -pthread
patch.c: In function 'find_libc':
patch.c:159:20: warning: cast to pointer from integer of different size [-Wint-to-pointer-cast]
       libc_start = (void*)min;
                    ^
patch.c:160:18: warning: cast to pointer from integer of different size [-Wint-to-pointer-cast]
       libc_end = (void*)max;
                  ^
patch.c: In function '__libqasan_hotpatch':
patch.c:212:12: error: 'explicit_bzero' undeclared (first use in this function)
   HOTPATCH(explicit_bzero)
            ^
patch.c:197:57: note: in definition of macro 'HOTPATCH'
   if (p_##fn) __libqasan_patch_jump(p_##fn, (uint8_t*)&(fn));
                                                         ^
patch.c:212:12: note: each undeclared identifier is reported only once for each function it appears in
   HOTPATCH(explicit_bzero)
            ^
patch.c:197:57: note: in definition of macro 'HOTPATCH'
   if (p_##fn) __libqasan_patch_jump(p_##fn, (uint8_t*)&(fn));


arm-linux-gnueabi-gcc -std=c11 -fPIC -shared -Wint-to-pointer-cast -I../include -I/home/wuhuang/fuzz/qasan/glibc-2.13/include  -Wl,--rpath=/home/wuhuang/fuzz/qasan/glibc-2.13/lib -Wl,--dynamic-linker=/home/wuhuang/fuzz/qasan/glibc-2.13/lib/ld-linux.so.2 libqasan.c hooks.c malloc.c string.c uninstrument.c patch.c dlmalloc.c -o libqasan.so -ldl -pthread
## 使用LD_LIB环境参数变异
LD_LIBRARY_PATH=/home/wuhuang/fuzz/qasan/cramfs-root/lib/arm-linux-gnueabi arm-linux-gnueabi-gcc  -fPIC -shared -I ../include libqasan.c hooks.c malloc.c string.c uninstrument.c patch.c dlmalloc.c -o libqasan.so -ldl -pthread
无效
LD_LIBRARY_PATH=/home/wuhuang/fuzz/qasan/cramfs-root/lib/arm-linux-gnueabi arm-linux-gnueabi-gcc  -L /home/wuhuang/fuzz/qasan/cramfs-root/lib/arm-linux-gnueabi -Wl,--dynamic-linker=/home/wuhuang/fuzz/qasan/cramfs-root/lib/arm-linux-gnueabi/ld-2.13.so  -Wl,-rpath=/home/wuhuang/fuzz/qasan/cramfs-root/lib/arm-linux-gnueabi -fPIC -shared -I ../include libqasan.c hooks.c malloc.c string.c uninstrument.c patch.c dlmalloc.c -o libqasan.so -ldl -pthread
无效


## 下载了glibc2.13
LD_LIBRARY_PATH=/home/wuhuang/fuzz/qasan/cramfs-root/lib/arm-linux-gnueabi arm-linux-gnueabi-gcc -fPIC -shared -I /home/wuhuang/fuzz/qasan/glibc-2.13/include -I /home/wuhuang/fuzz/qasan/glibc-2.13 -L /home/wuhuang/fuzz/qasan/cramfs-root/lib/arm-linux-gnueabi -Wl,--dynamic-linker=/home/wuhuang/fuzz/qasan/cramfs-root/lib/arm-linux-gnueabi/ld-2.13.so  -Wl,-rpath=/home/wuhuang/fuzz/qasan/cramfs-root/lib/arm-linux-gnueabi libqasan.c hooks.c malloc.c string.c uninstrument.c patch.c dlmalloc.c -o libqasan.so -ldl -pthread
报错

LD_LIBRARY_PATH=/home/wuhuang/fuzz/qasan/cramfs-root/lib/arm-linux-gnueabi arm-linux-gnueabi-gcc -fPIC -shared -I /home/wuhuang/fuzz/qasan/glibc-2.13/include -L /home/wuhuang/fuzz/qasan/cramfs-root/lib/arm-linux-gnueabi -Wl,--dynamic-linker=/home/wuhuang/fuzz/qasan/cramfs-root/lib/arm-linux-gnueabi/ld-2.13.so  -Wl,-rpath=/home/wuhuang/fuzz/qasan/cramfs-root/lib/arm-linux-gnueabi libqasan.c hooks.c malloc.c string.c uninstrument.c patch.c dlmalloc.c -o libqasan.so -ldl -pthread

## 调整编译参数，使用固件环境编译libqasan:

修改makefile
CC := arm-linux-gnueabi-gcc
CFLAGS += -Wno-int-to-void-pointer-cast -ggdb --sysroot=/home/wuhuang/fuzz/qasan/cramfs-root
LDFLAGS += -ldl -pthread --sysroot=/home/wuhuang/fuzz/qasan/cramfs-root 

SRC := libqasan.c hooks.c malloc.c string.c uninstrument.c patch.c dlmalloc.c
HDR := libqasan.h

all: $(HDR) $(SRC)
	$(CC) $(CFLAGS) -fPIC -shared -I ../include $(SRC) -o libqasan.so $(LDFLAGS)

debug: $(HDR) $(SRC)
	$(CC) $(CFLAGS) -DDEBUG=1 -fPIC -shared -I ../include $(SRC) -o libqasan.so $(LDFLAGS)

无效

## 调整编译参数，静态编译libqasan：
修改makefile
CC := arm-linux-gnueabi-gcc
CFLAGS += -Wno-int-to-void-pointer-cast -ggdb -static
LDFLAGS += -ldl -pthread

SRC := libqasan.c hooks.c malloc.c string.c uninstrument.c patch.c dlmalloc.c
HDR := libqasan.h

all: $(HDR) $(SRC)
	$(CC) $(CFLAGS) -fPIC -shared -I ../include $(SRC) -o libqasan.so $(LDFLAGS)

debug: $(HDR) $(SRC)
	$(CC) $(CFLAGS) -DDEBUG=1 -fPIC -shared -I ../include $(SRC) -o libqasan.so $(LDFLAGS)

报错：
arm-linux-gnueabi-gcc -static -Wno-int-to-void-pointer-cast -ggdb  -fPIC -shared -I ../include libqasan.c hooks.c malloc.c string.c uninstrument.c patch.c dlmalloc.c -o libqasan.so -ldl -pthread
patch.c: In function ‘find_libc’:
patch.c:159:20: warning: cast to pointer from integer of different size [-Wint-to-pointer-cast]
  159 |       libc_start = (void*)min;
      |                    ^
patch.c:160:18: warning: cast to pointer from integer of different size [-Wint-to-pointer-cast]
  160 |       libc_end = (void*)max;
      |                  ^
At top level:
cc1: note: unrecognized command-line option ‘-Wno-int-to-void-pointer-cast’ may have been intended to silence earlier diagnostics
/usr/lib/gcc-cross/arm-linux-gnueabi/13/../../../../arm-linux-gnueabi/bin/ld: /usr/lib/gcc-cross/arm-linux-gnueabi/13/../../../../arm-linux-gnueabi/lib/libc.a(libc-start.o): in function `__libc_start_main_impl':
(.text+0xdc): multiple definition of `__libc_start_main'; /tmp/ccguE3Qn.o:/home/wuhuang/fuzz/qasan/libqasan/libqasan.c:84: first defined here
/usr/lib/gcc-cross/arm-linux-gnueabi/13/../../../../arm-linux-gnueabi/bin/ld: /tmp/ccro3W2s.o: in function `__libqasan_hotpatch':
/home/wuhuang/fuzz/qasan/libqasan/patch.c:193:(.text+0x3e4): warning: Using 'dlopen' in statically linked applications requires at runtime the shared libraries from the glibc version used for linking
/usr/lib/gcc-cross/arm-linux-gnueabi/13/../../../../arm-linux-gnueabi/bin/ld: /usr/lib/gcc-cross/arm-linux-gnueabi/13/../../../../arm-linux-gnueabi/lib/libc.a(libc-start.o): in function `call_fini':
(.text+0x38): undefined reference to `__fini_array_end'
/usr/lib/gcc-cross/arm-linux-gnueabi/13/../../../../arm-linux-gnueabi/bin/ld: (.text+0x3c): undefined reference to `__fini_array_start'
/usr/lib/gcc-cross/arm-linux-gnueabi/13/../../../../arm-linux-gnueabi/bin/ld: /usr/lib/gcc-cross/arm-linux-gnueabi/13/../../../../arm-linux-gnueabi/lib/libc.a(libc-start.o): in function `__libc_start_main_impl':
(.text+0x37c): undefined reference to `__preinit_array_end'
/usr/lib/gcc-cross/arm-linux-gnueabi/13/../../../../arm-linux-gnueabi/bin/ld: (.text+0x380): undefined reference to `__preinit_array_start'
/usr/lib/gcc-cross/arm-linux-gnueabi/13/../../../../arm-linux-gnueabi/bin/ld: (.text+0x388): undefined reference to `__init_array_end'
/usr/lib/gcc-cross/arm-linux-gnueabi/13/../../../../arm-linux-gnueabi/bin/ld: (.text+0x38c): undefined reference to `__init_array_start'
/usr/lib/gcc-cross/arm-linux-gnueabi/13/../../../../arm-linux-gnueabi/bin/ld: /usr/lib/gcc-cross/arm-linux-gnueabi/13/../../../../arm-linux-gnueabi/lib/libc.a(dl-support.o): in function `_dl_aux_init':
(.text+0x174): undefined reference to `_start'
/usr/lib/gcc-cross/arm-linux-gnueabi/13/../../../../arm-linux-gnueabi/bin/ld: libqasan.so: hidden symbol `__fini_array_end' isn't defined
/usr/lib/gcc-cross/arm-linux-gnueabi/13/../../../../arm-linux-gnueabi/bin/ld: final link failed: bad value
collect2: error: ld returned 1 exit status
make: *** [Makefile:9: all] Error 1

解析：如果你要生成一个动态库（.so），不应该使用 -static。移除 CFLAGS 中的 -static 选项
## 使用 -static-libgcc重新编译
CC := arm-linux-gnueabi-gcc
CFLAGS +=  -static-libgcc
LDFLAGS += -ldl -pthread
SRC := libqasan.c hooks.c malloc.c string.c uninstrument.c patch.c dlmalloc.c
HDR := libqasan.h

all: $(HDR) $(SRC)
	$(CC) $(CFLAGS) -fPIC -shared -I ../include $(SRC) -o libqasan.so $(LDFLAGS)

debug: $(HDR) $(SRC)
	$(CC) $(CFLAGS) -DDEBUG=1 -fPIC -shared -I ../include $(SRC) -o libqasan.so $(LDFLAGS)

./qasan-qemu -E LD_PRELOAD=/home/wuhuang/fuzz/qasan/libqasan/libqasan.so -L /home/wuhuang/fuzz/qasan/cramfs-root ./spx_restservice
 ./spx_restservice: /lib/arm-linux-gnueabi/libc.so.6: version `GLIBC_2.34' not found (required by /home/wuhuang/fuzz/qasan/libqasan/libqasan.so)
 ./spx_restservice: /lib/arm-linux-gnueabi/libc.so.6: version `GLIBC_2.38' not found (required by /home/wuhuang/fuzz/qasan/libqasan/libqasan.so)

## 使用patchelf

## 分析
### qemu运行参数设定
./qemu-arm -L /usr/arm-linux-gnueabi/ ./test/vuln
其中-L参数用于指定vuln程序依赖的动态运行库目录
./qasan-qemu -L /home/wuhuang/fuzz/qasan/cramfs-root -E LD_PRELOAD=/home/wuhuang/fuzz/qasan/host-libs/libqasan.so ./spx_restservice

运行qemu时，用 `-E LD_PRELOAD=/home/wuhuang/fuzz/qasan/host-libs/libqasan.so` 
qemu会解析`-E`选项，调用`handle_arg_set_env()`函数 
```
// qemu/linux-user/main.c
static void handle_arg_set_env(const char *arg)
{
    char *r, *p, *token;
    r = p = strdup(arg);
    while ((token = strsep(&p, ",")) != NULL) {
        if (envlist_setenv(envlist, token) != 0) {
            usage(EXIT_FAILURE);
        }
    }
    free(r);
}
```
解析`-E LD_PRELOAD=libqasan.so`时，调用`envlist_setenv()`函数，将`LD_PRELOAD=libqasan.so`存入`envlist`
```
// qemu/util/envlist.c
/*
 * Sets environment value to envlist in similar manner
 * than putenv(3).
 *
 * Returns 0 in success, errno otherwise.
 */
int
envlist_setenv(envlist_t *envlist, const char *env)
{
	struct envlist_entry *entry = NULL;
	const char *eq_sign;
	size_t envname_len;

	if ((envlist == NULL) || (env == NULL))
		return (EINVAL);

	/* find out first equals sign in given env */
	if ((eq_sign = strchr(env, '=')) == NULL)
		return (EINVAL);
	envname_len = eq_sign - env + 1;

	/*
	 * If there already exists variable with given name
	 * we remove and release it before allocating a whole
	 * new entry.
	 */
	for (entry = envlist->el_entries.lh_first; entry != NULL;
	    entry = entry->ev_link.le_next) {
		if (strncmp(entry->ev_var, env, envname_len) == 0)
			break;
	}

	if (entry != NULL) {
		QLIST_REMOVE(entry, ev_link);
		g_free((char *)entry->ev_var);
		g_free(entry);
	} else {
		envlist->el_count++;
	}

	entry = g_malloc(sizeof(*entry));
	entry->ev_var = g_strdup(env);
	QLIST_INSERT_HEAD(&envlist->el_entries, entry, ev_link);

	return (0);
}
```

在主函数中，用`envlist_to_environ()`函数加载`envlist`中的内容到`target_environ`中，再用`loader_exec()`加载程序
当 loader_exec 加载目标程序时，目标程序的动态链接器（如 ld-linux.so）会解析 target_environ 中的 LD_PRELOAD 变量。
如果 target_environ 包含 LD_PRELOAD=libqasan.so，动态链接器会自动加载该库到目标程序的地址空间。


### 读取spx_restservice所需的glibc版本
arm-linux-gnueabi-readelf -s spx_restservice | grep GLIB
    63: 00026f3c     0 FUNC    GLOBAL DEFAULT  UND lo[...]@GLIBC_2.4 (2)
   110: 00026f9c     0 FUNC    GLOBAL DEFAULT  UND rand@GLIBC_2.4 (2)
   156: 00027020     0 FUNC    GLOBAL DEFAULT  UND dlerror@GLIBC_2.4 (3)
   255: 00027110     0 FUNC    GLOBAL DEFAULT  UND st[...]@GLIBC_2.4 (2)
   260: 0002711c     0 FUNC    GLOBAL DEFAULT  UND strnlen@GLIBC_2.4 (2)
   295: 00027170     0 FUNC    GLOBAL DEFAULT  UND strtol@GLIBC_2.4 (2)
   309: 000271a0     0 FUNC    GLOBAL DEFAULT  UND free@GLIBC_2.4 (2)
   329: 000271dc     0 FUNC    GLOBAL DEFAULT  UND in[...]@GLIBC_2.4 (2)
   339: 00027218     0 FUNC    GLOBAL DEFAULT  UND readdir@GLIBC_2.4 (2)
   353: 00027248     0 FUNC    GLOBAL DEFAULT  UND ge[...]@GLIBC_2.4 (2)
   446: 00027314     0 FUNC    GLOBAL DEFAULT  UND strncmp@GLIBC_2.4 (2)
   448: 00027320     0 FUNC    GLOBAL DEFAULT  UND regcomp@GLIBC_2.4 (2)
   509: 00027398     0 FUNC    GLOBAL DEFAULT  UND asctime@GLIBC_2.4 (2)
   558: 00027428     0 FUNC    GLOBAL DEFAULT  UND cl[...]@GLIBC_2.4 (2)
   563: 00027440     0 FUNC    GLOBAL DEFAULT  UND in[...]@GLIBC_2.4 (2)
   569: 0002744c     0 FUNC    GLOBAL DEFAULT  UND in[...]@GLIBC_2.4 (2)
   624: 000274d0     0 FUNC    GLOBAL DEFAULT  UND st[...]@GLIBC_2.4 (2)
   671: 00027554     0 FUNC    GLOBAL DEFAULT  UND dlclose@GLIBC_2.4 (3)
   710: 000275b4     0 FUNC    GLOBAL DEFAULT  UND regfree@GLIBC_2.4 (2)
   728: 000275c0     0 FUNC    GLOBAL DEFAULT  UND strtok@GLIBC_2.4 (2)
   757: 00027620     0 FUNC    GLOBAL DEFAULT  UND flock@GLIBC_2.4 (2)
   766: 00027644     0 FUNC    GLOBAL DEFAULT  UND ge[...]@GLIBC_2.4 (2)
   772: 00027650     0 FUNC    GLOBAL DEFAULT  UND al[...]@GLIBC_2.4 (2)
   787: 00027674     0 FUNC    GLOBAL DEFAULT  UND regexec@GLIBC_2.4 (2)
   843: 00027728     0 FUNC    GLOBAL DEFAULT  UND prctl@GLIBC_2.4 (2)
   871: 00027770     0 FUNC    GLOBAL DEFAULT  UND strtoul@GLIBC_2.4 (2)
   885: 000277a0     0 FUNC    GLOBAL DEFAULT  UND st[...]@GLIBC_2.4 (2)
   897: 000277c4     0 FUNC    GLOBAL DEFAULT  UND memset@GLIBC_2.4 (2)
   906: 000277e8     0 FUNC    GLOBAL DEFAULT  UND opendir@GLIBC_2.4 (2)
   932: 0002780c     0 FUNC    GLOBAL DEFAULT  UND remove@GLIBC_2.4 (2)
   978: 000278a8     0 FUNC    GLOBAL DEFAULT  UND sn[...]@GLIBC_2.4 (2)
   985: 000278cc     0 FUNC    GLOBAL DEFAULT  UND __[...]@GLIBC_2.4 (2)
   999: 000278e4     0 FUNC    GLOBAL DEFAULT  UND close@GLIBC_2.4 (4)
  1017: 00027920     0 FUNC    GLOBAL DEFAULT  UND gmtime@GLIBC_2.4 (2)
  1034: 00027968     0 FUNC    GLOBAL DEFAULT  UND fopen@GLIBC_2.4 (2)
  1054: 000279a4     0 FUNC    GLOBAL DEFAULT  UND read@GLIBC_2.4 (4)
  1074: 000279ec     0 FUNC    GLOBAL DEFAULT  UND abort@GLIBC_2.4 (2)
  1148: 00027ab8     0 FUNC    GLOBAL DEFAULT  UND log10@GLIBC_2.4 (5)
  1156: 00027adc     0 FUNC    GLOBAL DEFAULT  UND mkfifo@GLIBC_2.4 (2)
  1162: 00027ae8     0 FUNC    GLOBAL DEFAULT  UND ctime@GLIBC_2.4 (2)
  1179: 00027b30     0 FUNC    GLOBAL DEFAULT  UND unlink@GLIBC_2.4 (2)
  1215: 00027b48     0 FUNC    GLOBAL DEFAULT  UND dlopen@GLIBC_2.4 (3)
  1220: 00027b54     0 FUNC    GLOBAL DEFAULT  UND ioctl@GLIBC_2.4 (2)
  1229: 00027b6c     0 FUNC    GLOBAL DEFAULT  UND lo[...]@GLIBC_2.4 (2)
  1230: 00027b78     0 FUNC    GLOBAL DEFAULT  UND gm[...]@GLIBC_2.4 (2)
  1238: 00027b90     0 FUNC    GLOBAL DEFAULT  UND system@GLIBC_2.4 (4)
  1249: 00027ba8     0 FUNC    GLOBAL DEFAULT  UND realloc@GLIBC_2.4 (2)
  1251: 00027bb4     0 FUNC    GLOBAL DEFAULT  UND strcpy@GLIBC_2.4 (2)
  1319: 00027c80     0 FUNC    GLOBAL DEFAULT  UND __[...]@GLIBC_2.7 (6)
  1381: 00027ce0     0 FUNC    GLOBAL DEFAULT  UND open@GLIBC_2.4 (4)
  1401: 00027d04     0 FUNC    GLOBAL DEFAULT  UND chmod@GLIBC_2.4 (2)
  1420: 00027d28     0 FUNC    GLOBAL DEFAULT  UND strcat@GLIBC_2.4 (2)
  1492: 00027db8     0 FUNC    GLOBAL DEFAULT  UND sysinfo@GLIBC_2.4 (2)
  1521: 00027e18     0 FUNC    GLOBAL DEFAULT  UND socket@GLIBC_2.4 (2)
  1547: 00027e60     0 FUNC    GLOBAL DEFAULT  UND access@GLIBC_2.4 (2)
  1555: 00027e6c     0 FUNC    GLOBAL DEFAULT  UND setenv@GLIBC_2.4 (2)
  1592: 00027eb4     0 FUNC    GLOBAL DEFAULT  UND mkdir@GLIBC_2.4 (2)
  1611: 00027ef0     0 FUNC    GLOBAL DEFAULT  UND strstr@GLIBC_2.4 (2)
  1617: 00027f08     0 FUNC    GLOBAL DEFAULT  UND scandir@GLIBC_2.4 (2)
  1674: 00027fbc     0 FUNC    GLOBAL DEFAULT  UND st[...]@GLIBC_2.4 (2)
  1729: 00028034     0 FUNC    GLOBAL DEFAULT  UND sleep@GLIBC_2.4 (2)
  1736: 00028040     0 FUNC    GLOBAL DEFAULT  UND lseek@GLIBC_2.4 (4)
  1737: 0002804c     0 FUNC    GLOBAL DEFAULT  UND symlink@GLIBC_2.4 (2)
  1745: 0002807c     0 FUNC    GLOBAL DEFAULT  UND raise@GLIBC_2.4 (4)
  1753: 00028094     0 FUNC    GLOBAL DEFAULT  UND __[...]@GLIBC_2.4 (2)
  1791: 000280e8     0 FUNC    GLOBAL DEFAULT  UND connect@GLIBC_2.4 (4)
  1828: 00028118     0 FUNC    GLOBAL DEFAULT  UND strncat@GLIBC_2.4 (2)
  1872: 00028178     0 FUNC    GLOBAL DEFAULT  UND statvfs@GLIBC_2.4 (2)
  1944: 00028220     0 FUNC    GLOBAL DEFAULT  UND memcpy@GLIBC_2.4 (2)
  1969: 0002825c     0 FUNC    GLOBAL DEFAULT  UND malloc@GLIBC_2.4 (2)
  1986: 00028298     0 FUNC    GLOBAL DEFAULT  UND strlen@GLIBC_2.4 (2)
  2034: 00028310     0 FUNC    GLOBAL DEFAULT  UND fclose@GLIBC_2.4 (2)
  2038: 0002831c     0 FUNC    GLOBAL DEFAULT  UND write@GLIBC_2.4 (4)
  2079: 00028358     0 FUNC    GLOBAL DEFAULT  UND sprintf@GLIBC_2.4 (2)
  2118: 000283d0     0 FUNC    GLOBAL DEFAULT  UND __xstat@GLIBC_2.4 (2)
  2150: 00028424     0 FUNC    GLOBAL DEFAULT  UND __[...]@GLIBC_2.4 (2)
  2206: 000284b4     0 FUNC    GLOBAL DEFAULT  UND pt[...]@GLIBC_2.4 (4)
  2208: 000284c0     0 FUNC    GLOBAL DEFAULT  UND strcmp@GLIBC_2.4 (2)
  2235: 00028514     0 FUNC    GLOBAL DEFAULT  UND time@GLIBC_2.4 (2)
  2252: 00028538     0 FUNC    GLOBAL DEFAULT  UND __[...]@GLIBC_2.4 (4)
  2278: 00028568     0 FUNC    GLOBAL DEFAULT  UND strncpy@GLIBC_2.4 (2)
  2303: 00028598     0 FUNC    GLOBAL DEFAULT  UND memcmp@GLIBC_2.4 (2)
  2385: 00028640     0 FUNC    GLOBAL DEFAULT  UND __[...]@GLIBC_2.7 (6)
  2417: 000286a0     0 FUNC    GLOBAL DEFAULT  UND mktime@GLIBC_2.4 (2)
  2447: 000286d0     0 FUNC    GLOBAL DEFAULT  UND getenv@GLIBC_2.4 (2)
  2449: 000286dc     0 FUNC    GLOBAL DEFAULT  UND __[...]@GLIBC_2.4 (2)
  2451: 000286e8     0 FUNC    GLOBAL DEFAULT  UND dlsym@GLIBC_2.4 (3)
  2463: 0002870c     0 FUNC    GLOBAL DEFAULT  UND vs[...]@GLIBC_2.4 (2)
  2473: 00028748     0 FUNC    GLOBAL DEFAULT  UND __[...]@GLIBC_2.4 (2)
  2478: 0002876c     0 FUNC    GLOBAL DEFAULT  UND rename@GLIBC_2.4 (2)
  2492: 000287c0     0 FUNC    GLOBAL DEFAULT  UND srand@GLIBC_2.4 (2)
  2513: 000287f0     0 FUNC    GLOBAL DEFAULT  UND strchr@GLIBC_2.4 (2)
  2600: 000288bc     0 FUNC    GLOBAL DEFAULT  UND floor@GLIBC_2.4 (5)
### 读取libqasan.so 所需的glibc版本
arm-linux-gnueabi-readelf -s libqasan.so | grep GLIBC
     3: 00000000     0 FUNC    GLOBAL DEFAULT  UND raise@GLIBC_2.4 (2)
     4: 00000000     0 FUNC    WEAK   DEFAULT  UND __[...]@GLIBC_2.4 (2)
     6: 00000000     0 FUNC    GLOBAL DEFAULT  UND read@GLIBC_2.4 (2)

     7: 00000000     0 FUNC    GLOBAL DEFAULT  UND _[...]@GLIBC_2.38 (3)
     
     8: 00000000     0 FUNC    GLOBAL DEFAULT  UND mp[...]@GLIBC_2.4 (2)
     9: 00000000     0 OBJECT  GLOBAL DEFAULT  UND __[...]@GLIBC_2.4 (4)
    10: 00000000     0 FUNC    GLOBAL DEFAULT  UND tolower@GLIBC_2.4 (2)
    11: 00000000     0 FUNC    GLOBAL DEFAULT  UND __[...]@GLIBC_2.4 (2)
    12: 00000000     0 FUNC    GLOBAL DEFAULT  UND sysconf@GLIBC_2.4 (2)
    13: 00000000     0 OBJECT  GLOBAL DEFAULT  UND stderr@GLIBC_2.4 (2)
    14: 00000000     0 FUNC    GLOBAL DEFAULT  UND fwrite@GLIBC_2.4 (2)
    15: 00000000     0 FUNC    GLOBAL DEFAULT  UND open64@GLIBC_2.4 (2)
    16: 00000000     0 FUNC    GLOBAL DEFAULT  UND p[...]@GLIBC_2.34 (5)
    17: 00000000     0 FUNC    GLOBAL DEFAULT  UND dlopen@GLIBC_2.34 (5)
    18: 00000000     0 FUNC    GLOBAL DEFAULT  UND p[...]@GLIBC_2.34 (5)
    20: 00000000     0 FUNC    GLOBAL DEFAULT  UND getpid@GLIBC_2.4 (2)
    21: 00000000     0 FUNC    GLOBAL DEFAULT  UND syscall@GLIBC_2.4 (2)
    22: 00000000     0 FUNC    GLOBAL DEFAULT  UND fprintf@GLIBC_2.4 (2)
    23: 00000000     0 FUNC    GLOBAL DEFAULT  UND fclose@GLIBC_2.4 (2)
    24: 00000000     0 FUNC    GLOBAL DEFAULT  UND fputc@GLIBC_2.4 (2)
    25: 00000000     0 FUNC    GLOBAL DEFAULT  UND dlsym@GLIBC_2.34 (5)
    26: 00000000     0 FUNC    GLOBAL DEFAULT  UND fopen64@GLIBC_2.4 (2)

    27: 00000000     0 FUNC    GLOBAL DEFAULT  UND p[...]@GLIBC_2.34 (5)

    29: 00000000     0 FUNC    GLOBAL DEFAULT  UND getline@GLIBC_2.4 (2)
    30: 00000000     0 FUNC    GLOBAL DEFAULT  UND abort@GLIBC_2.4 (2)
    31: 00000000     0 FUNC    GLOBAL DEFAULT  UND close@GLIBC_2.4 (2)
   204: 00000000     0 FUNC    GLOBAL DEFAULT  UND raise@GLIBC_2.4
   216: 00000000     0 FUNC    GLOBAL DEFAULT  UND read@GLIBC_2.4
   221: 00000000     0 FUNC    GLOBAL DEFAULT  UND mprotect@GLIBC_2.4
   238: 00000000     0 FUNC    GLOBAL DEFAULT  UND tolower@GLIBC_2.4
   246: 00000000     0 FUNC    GLOBAL DEFAULT  UND sysconf@GLIBC_2.4
   258: 00000000     0 OBJECT  GLOBAL DEFAULT  UND stderr@GLIBC_2.4
   259: 00000000     0 FUNC    GLOBAL DEFAULT  UND fwrite@GLIBC_2.4
   264: 00000000     0 FUNC    GLOBAL DEFAULT  UND open64@GLIBC_2.4
   268: 00000000     0 FUNC    GLOBAL DEFAULT  UND dlopen@GLIBC_2.34
   272: 00000000     0 FUNC    GLOBAL DEFAULT  UND getpid@GLIBC_2.4
   273: 00000000     0 FUNC    GLOBAL DEFAULT  UND syscall@GLIBC_2.4
   280: 00000000     0 FUNC    GLOBAL DEFAULT  UND fprintf@GLIBC_2.4
   290: 00000000     0 FUNC    GLOBAL DEFAULT  UND fclose@GLIBC_2.4
   303: 00000000     0 FUNC    GLOBAL DEFAULT  UND fputc@GLIBC_2.4
   305: 00000000     0 FUNC    GLOBAL DEFAULT  UND dlsym@GLIBC_2.34
   307: 00000000     0 FUNC    GLOBAL DEFAULT  UND fopen64@GLIBC_2.4
   314: 00000000     0 FUNC    GLOBAL DEFAULT  UND getline@GLIBC_2.4
   317: 00000000     0 FUNC    GLOBAL DEFAULT  UND abort@GLIBC_2.4
   319: 00000000     0 FUNC    GLOBAL DEFAULT  UND close@GLIBC_2.4
   

file /home/wuhuang/fuzz/qasan/cramfs-root/lib/arm-linux-gnueabi/libc.so.6
/home/wuhuang/fuzz/qasan/cramfs-root/lib/arm-linux-gnueabi/libc.so.6: symbolic link to libc-2.13.so

file /home/wuhuang/fuzz/qasan/cramfs-root/lib/arm-linux-gnueabi/libc-2.13.so
/home/wuhuang/fuzz/qasan/cramfs-root/lib/arm-linux-gnueabi/libc-2.13.so: ELF 32-bit LSB shared object, ARM, EABI5 version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.3, BuildID[sha1]=1dde31309272b7cf7366082a84e01aa23825bbfa, for GNU/Linux 2.6.26, stripped

arm官网上能找到的最旧的arm-linux-guneabi工具链支持的使用的glibc版本是2.28 但是环境中的glibc版本是2.13




arm-linux-gnueabi-gcc -fPIC -shared -I ../include libqasan.c hooks.c malloc.c string.c uninstrument.c patch.c dlmalloc.c -o libqasan.so -ldl -pthread  -L/home/wuhuang/fuzz/qasan/cramfs-root/lib/arm-linux-gnueabi -Wl,--dynamic-linker=/home/wuhuang/fuzz/qasan/cramfs-root/lib/arm-linux-gnueabi/ld-2.13.so  -Wl,-rpath=/home/wuhuang/fuzz/qasan/cramfs-root/lib/arm-linux-gnueabi


# 最新的编译：
./build.py --arch=arm --debug --cross=/home/wuhuang/fuzz/qasan/gcc-linaro-4.9-2016.02-x86_64_arm-linux-gnueabi/bin/arm-linux-gnueabi-gcc

# 使用qasan 测试 ./spx_restservice

指令：
    echo -e "GET / HTTP/1.1\nHost: localhost\n" | ./qasan-qemu -E LD_PRELOAD=/home/wuhuang/fuzz/qasan/libqasan/libqasan.so -L /home/wuhuang/fuzz/qasan/cramfs-root ./spx_restservice 
输出：
    using ASAN_GIOVESE
    [1266555 : 1266557 INFO][Info]: InspurWebMonitorTask Is Created Sucessfully!

    [1266555 : 1266555 CRITICAL][rest.c:1103]Error while terminating web session!
    content-type: text/html

    error: NULL path_info
    [Y]:Exiting target program...
分析：
    缺少变量path_info
## 使用testbash进行实验：直接通过设置环境变量通spx_restservice交互
1. 设置-E LD_PRELOAD和-L
```
export REQUEST_METHOD="GET"
export HTTP_AUTHORIZATION="Basic dXNlcjpwYXNz"  # user:pass
export PATH_INFO="/api/endpoint"       # 根据实际接口路径填写
export QUERY_STRING="param1=value1"    # 根据实际参数填写
export REMOTE_ADDR="127.0.0.1"         # 模拟客户端IP
export SERVER_NAME="localhost"         # 服务器名
export SERVER_PORT="80"                # 服务器端口
export GATEWAY_INTERFACE="CGI/1.1"     # CGI 版本
export SERVER_PROTOCOL="HTTP/1.1"      # HTTP 版本
export CONTENT_TYPE=""                 # GET 请求通常不需要
export CONTENT_LENGTH=""               # GET 请求通常没有请求体

env | grep HTTP_
env | grep PATH_INFO
env | grep QUERY_STRING

# 执行 CGI 程序
./qasan-qemu -E LD_PRELOAD=/home/wuhuang/fuzz/qasan/libqasan/libqasan.so -L /home/wuhuang/fuzz/qasan/cramfs-root ./spx_restservice
```
输出：
    HTTP_AUTHORIZATION=Basic dXNlcjpwYXNz
    PATH_INFO=/api/endpoint
    QUERY_STRING=param1=value1
    using ASAN_GIOVESE
    [1266699 : 1266699 CRITICAL][rest.c:1103]Error while terminating web session!
    [1266699 : 1266701 INFO][Info]: InspurWebMonitorTask Is Created Sucessfully!

    QEMU-AddressSanitizer:DEADLYSIGNAL
    =================================================================
    ==1266699==ERROR: QEMU-AddressSanitizer: SEGV on unknown address 0x000000000000 (pc 0x0000ff7b4578 bp 0x0000fffee9c4 sp 0x0000fffee8c0 T1266699)
        #0 0x0000ff7b4578 in __libqasan_strlen /home/wuhuang/fuzz/qasan/libqasan/string.c:100 (discriminator 1)
        #1 0x0000ff7b399c in strstr /home/wuhuang/fuzz/qasan/libqasan/hooks.c:549
        #2 0x0000ff77c62c in dispatch (/home/wuhuang/fuzz/qasan/cramfs-root/usr/local/lib/libraphters.so.2.17.0+0x162c)
        #3 0x0000ff7b2f24 in __libc_start_main /home/wuhuang/fuzz/qasan/libqasan/libqasan.c:91

    QEMU-AddressSanitizer can not provide additional info.
    SUMMARY: QEMU-AddressSanitizer:  in __libqasan_strlen /home/wuhuang/fuzz/qasan/libqasan/string.c:100 (discriminator 1)
    ==1266699==ABORTING
    qemu: uncaught target signal 11 (Segmentation fault) - core dumped
    ./testbash.sh: line 18: 1266699 Segmentation fault      ./qasan-qemu -E LD_PRELOAD=/home/wuhuang/fuzz/qasan/libqasan/libqasan.so -L /home/wuhuang/fuzz/qasan/cramfs-root ./spx_restservice

2. 不设置-E LD_PRELOAD
```
export REQUEST_METHOD="GET"
export HTTP_AUTHORIZATION="Basic dXNlcjpwYXNz"  # user:pass
export PATH_INFO="/api/endpoint"       # 根据实际接口路径填写
export QUERY_STRING="param1=value1"    # 根据实际参数填写
export REMOTE_ADDR="127.0.0.1"         # 模拟客户端IP
export SERVER_NAME="localhost"         # 服务器名
export SERVER_PORT="80"                # 服务器端口
export GATEWAY_INTERFACE="CGI/1.1"     # CGI 版本
export SERVER_PROTOCOL="HTTP/1.1"      # HTTP 版本
export CONTENT_TYPE=""                 # GET 请求通常不需要
export CONTENT_LENGTH=""               # GET 请求通常没有请求体

env | grep HTTP_
env | grep PATH_INFO
env | grep QUERY_STRING

# 执行 CGI 程序
./qasan-qemu -L /home/wuhuang/fuzz/qasan/cramfs-root ./spx_restservice

```
输出：
    HTTP_AUTHORIZATION=Basic dXNlcjpwYXNz
    PATH_INFO=/api/endpoint
    QUERY_STRING=param1=value1
    using ASAN_GIOVESE
    [1266815 : 1266817 INFO][Info]: InspurWebMonitorTask Is Created Sucessfully!

    [1266815 : 1266815 CRITICAL][rest.c:1103]Error while terminating web session!
    QEMU-AddressSanitizer:DEADLYSIGNAL
    =================================================================
    ==1266815==ERROR: QEMU-AddressSanitizer: SEGV on unknown address 0x000000000000 (pc 0x0000ff0f3e60 bp 0x0000fffeea2c sp 0x0000fffee944 T1266815)
        #0 0x0000ff0f3e60 in strstr (/home/wuhuang/fuzz/qasan/cramfs-root/lib/arm-linux-gnueabi/libc-2.13.so+0x76e60)
        #1 0x0000ff79262c in dispatch (/home/wuhuang/fuzz/qasan/cramfs-root/usr/local/lib/libraphters.so.2.17.0+0x162c)

    QEMU-AddressSanitizer can not provide additional info.
    SUMMARY: QEMU-AddressSanitizer:  in strstr (/home/wuhuang/fuzz/qasan/cramfs-root/lib/arm-linux-gnueabi/libc-2.13.so+0x76e60)
    ==1266815==ABORTING
    qemu: uncaught target signal 11 (Segmentation fault) - core dumped
    ./testbash.sh: line 18: 1266815 Segmentation fault      ./qasan-qemu -L /home/wuhuang/fuzz/qasan/cramfs-root ./spx_restservice

疑问：
为什么不指定libqasan时会出现QEMU-AddressSanitizer的信息
    因为qemu经过修改，调用了asan-giovese中的函数，打印的调试信息：
    ```
    int asan_giovese_deadly_signal(int signum, target_ulong addr, target_ulong pc, target_ulong bp, target_ulong sp) {
        struct call_context ctx;
        asan_giovese_populate_context(&ctx, pc);
        const char* error_type = singal_to_string[signum];

        fprintf(stderr,
                ASAN_NAME_STR ":DEADLYSIGNAL\n"
                "================================================================="
                "\n" ANSI_COLOR_HRED "==%d==ERROR: " ASAN_NAME_STR
                ": %s on unknown address 0x%012" PRIxPTR " (pc 0x%012" PRIxPTR
                " bp 0x%012" PRIxPTR " sp 0x%012" PRIxPTR " T%d)" ANSI_COLOR_RESET "\n",
                getpid(), error_type, addr, pc, bp, sp, ctx.tid);

        size_t i;
        for (i = 0; i < ctx.size; ++i) {

            char* printable = asan_giovese_printaddr(ctx.addresses[i]);
            if (printable)
            fprintf(stderr, "    #%lu 0x%012" PRIxPTR "%s\n", i, ctx.addresses[i],
                    printable);
            else
            fprintf(stderr, "    #%lu 0x%012" PRIxPTR "\n", i, ctx.addresses[i]);

        }
        
        fputc('\n', stderr);
        fprintf(stderr, ASAN_NAME_STR " can not provide additional info.\n");
        ·
        const char* printable_pc = asan_giovese_printaddr(pc);
        if (!printable_pc) printable_pc = "";
        fprintf(stderr,
                "SUMMARY: " ASAN_NAME_STR
                ": %s\n", printable_pc);

        fprintf(stderr, "==%d==ABORTING\n", getpid());
        return signum;
        }
    ``` 

# 分析qasan在代码上是如何维护shadow memory的
## qasan的能力分析
堆缓冲区溢出	    通过影子内存标记堆块边界，越界访问时触发影子内存状态异常。
栈缓冲区溢出	    利用影子栈校验返回地址，检测栈空间越界写入。
使用未初始化内存     标记新分配内存为「未初始化」，首次访问前检查初始化状态。
双重释放            在 free 时检查影子内存状态，若内存已释放则报错。
内存泄漏	        跟踪未释放的堆块（需结合QASan的泄漏检测模式）。


## 基本原理
### malloc和free等函数的拦截
设计了一对新的内存分配函数和内存释放函数__libqasan_malloc和__libqasan_free

/home/wuhuang/fuzz/qasan/libqasan/malloc.c：
  void* __libqasan_malloc(size_t size) {
    // fprintf(stderr,"[Y]Calling malloc from qasan.\n");

    if (!__libqasan_malloc_initialized) {
    
        __libqasan_init_malloc();

    #ifdef __GLIBC__
        void* r = &__tmp_alloc_zone[__tmp_alloc_zone_idx];

        if (size & (ALLOC_ALIGN_SIZE - 1))
        __tmp_alloc_zone_idx +=
            (size & ~(ALLOC_ALIGN_SIZE - 1)) + ALLOC_ALIGN_SIZE;
        else
        __tmp_alloc_zone_idx += size;

        return r;
    #endif

    }

    int state = QASAN_SWAP(QASAN_DISABLED);  // disable qasan for this thread


    struct chunk_begin* p = backend_malloc(sizeof(struct chunk_struct) + size);

    QASAN_SWAP(state);

    if (!p) return NULL;

    QASAN_UNPOISON(p, sizeof(struct chunk_struct) + size);

    p->requested_size = size;
    p->aligned_orig = NULL;
    p->next = p->prev = NULL;

    QASAN_ALLOC(&p[1], (char*)&p[1] + size);
    QASAN_POISON(p->redzone, REDZONE_SIZE, ASAN_HEAP_LEFT_RZ);
    if (size & (ALLOC_ALIGN_SIZE - 1))
        QASAN_POISON((char*)&p[1] + size,
                    (size & ~(ALLOC_ALIGN_SIZE - 1)) + 8 - size + REDZONE_SIZE,
                    ASAN_HEAP_RIGHT_RZ);
    else
        QASAN_POISON((char*)&p[1] + size, REDZONE_SIZE, ASAN_HEAP_RIGHT_RZ);

    __builtin_memset(&p[1], 0xff, size);

    return &p[1];

    }

/home/wuhuang/fuzz/qasan/qemu/linux-user/syscall.c:
  abi_long do_syscall(void *cpu_env, int num, abi_long arg1,
                      abi_long arg2, abi_long arg3, abi_long arg4,
                      abi_long arg5, abi_long arg6, abi_long arg7,
                      abi_long arg8)
  {
      CPUState *cpu = ENV_GET_CPU(cpu_env);
      abi_long ret;

  #ifdef DEBUG_ERESTARTSYS
      /* Debug-only code for exercising the syscall-restart code paths
      * in the per-architecture cpu main loops: restart every syscall
      * the guest makes once before letting it through.
      */
      {
          static bool flag;
          flag = !flag;
          if (flag) {
              return -TARGET_ERESTARTSYS;
          }
      }
  #endif

      trace_guest_user_syscall(cpu, num, arg1, arg2, arg3, arg4,
                              arg5, arg6, arg7, arg8);

      if (unlikely(do_strace)) {
          print_syscall(num, arg1, arg2, arg3, arg4, arg5, arg6);
          ret = do_syscall1(cpu_env, num, arg1, arg2, arg3, arg4,
                            arg5, arg6, arg7, arg8);
          print_syscall_ret(num, ret);
      } else {
          ret = do_syscall1(cpu_env, num, arg1, arg2, arg3, arg4,
                            arg5, arg6, arg7, arg8);
      }

      trace_guest_user_syscall_ret(cpu, num, ret);
      return ret;
  }


### asan_giovese_load1
// k=0则全有效，返回false，没有越界
// (h&7)取h的低三位，+1取当前位置，如果大于k则表示超出范围，返回true表示存在越界
// asan-giovese-inl.h
int asan_giovese_load1(void* ptr) {

  uintptr_t h = (uintptr_t)ptr;
  int8_t*   shadow_addr = (int8_t*)(h >> 3) + SHADOW_OFFSET;
  int8_t    k = *shadow_addr;
  return k != 0 && (intptr_t)((h & 7) + 1) > k;

}
将待加载的地址（ptr）右移三位，映射到影子内存的偏移量，加上影子内存区域的基地址偏移量SHADOW_OFFSET得到地址ptr对应的影子内存地址shadow_addr。可以通过该地址访问ptr对应的影子内存信息。

有效性验证：
从影子内存中读取1字节的值k，该值表示对应的8字节应用内存中第一个不可访问的字节位置。若k = 0，表示这8个字节全部可访问；若k > 0，则前k个字节可访问，后续字节不可访问（如k=3表示前3字节可访问，后5字节不可访问）。

偏移量计算与边界检查：
h & 7获取指针在8字节块内的偏移量（0~7），例如地址0x123A的偏移量为0xA % 8 = 2。
检查(h & 7) + 1（访问的1字节内存的结束位置）是否超过k。若超过，说明访问越界。

示例分析：
若k = 3（前3字节可访问）
访问偏移量2的1字节：结束位置为3（2+1），等于k，合法。
访问偏移量3的1字节：结束位置为4，超过k，触发非法访问.
返回值逻辑：
当k != 0且(h & 7) + 1 > k时返回true，表示检测到无效内存访问；否则返回false。


// 对于8字节的加载和存储操作，仅检查地址对应的影子内存条目是否为零
int asan_giovese_load8(void* ptr) {

  uintptr_t h = (uintptr_t)ptr;
  int8_t*   shadow_addr = (int8_t*)(h >> 3) + SHADOW_OFFSET;
  return (*shadow_addr);

}
#### asan_giovese_load1的调用链分析
/home/wuhuang/fuzz/qasan/asan-giovese/asan-giovese-inl.h:
    int asan_giovese_load1(void* ptr) {
        uintptr_t h = (uintptr_t)ptr;
        int8_t*   shadow_addr = (int8_t*)(h >> 3) + SHADOW_OFFSET;
        int8_t    k = *shadow_addr;
        return k != 0 && (intptr_t)((h & 7) + 1) > k;
        }

/home/wuhuang/fuzz/qasan/qemu/accel/tcg/tcg-runtime.c:
    void HELPER(qasan_load1)(CPUArchState *env, target_ulong addr) 
/home/wuhuang/fuzz/qasan/qemu/include/exec/helper-head.h:
    #define HELPER(name) glue(helper_, name)
    生成 helper_qasan_load1()函数，调用asan_giovese_load1()

/home/wuhuang/fuzz/qasan/qemu/accel/tcg/tcg-runtime.h:
    DEF_HELPER_FLAGS_2(qasan_load1, TCG_CALL_NO_RWG, void, env, tl)

/home/wuhuang/fuzz/qasan/qemu/include/exec/helper-gen.h:
    #define DEF_HELPER_FLAGS_2(name, flags, ret, t1, t2)                    \
    static inline void glue(gen_helper_, name)(dh_retvar_decl(ret)          \
        dh_arg_decl(t1, 1), dh_arg_decl(t2, 2))                             \
    {                                                                       \
    TCGTemp *args[2] = { dh_arg(t1, 1), dh_arg(t2, 2) };                  \
    tcg_gen_callN(HELPER(name), dh_retvar(ret), 2, args);                 \
    }
    生成gen_helper_qasan_load1()函数，并使用tcg_gen_callN函数调用helper_qasan_load1()函数

/home/wuhuang/fuzz/qasan/qemu/tcg/tcg-op.c:
    void tcg_gen_qemu_ld_i32(TCGv_i32 val, TCGv addr, TCGArg idx, TCGMemOp memop)
    {
        tcg_gen_req_mo(TCG_MO_LD_LD | TCG_MO_ST_LD);
        memop = tcg_canonicalize_memop(memop, 0, 0);
        trace_guest_mem_before_tcg(tcg_ctx->cpu, cpu_env,
                                addr, trace_mem_get_info(memop, 0));
                                
        gen_ldst_i32(INDEX_op_qemu_ld_i32, val, addr, memop, idx);
        switch (memop & MO_SIZE) {
            case MO_64: qasan_gen_load8(addr, idx); break;
            case MO_32: qasan_gen_load4(addr, idx); break;
            case MO_16: qasan_gen_load2(addr, idx); break;
            case MO_8:  qasan_gen_load1(addr, idx); break;
            default: qasan_gen_load4(addr, idx); break;
        }
    }
    // 根据内存操作的大小（MO_SIZE），调用对应的QASan检查函数

    #define GEN_QASAN_OP(OP) \
    void qasan_gen_##OP(TCGv addr, int off) { \
    \
    (void*)off; \
    if (cur_block_is_good) \
        gen_helper_qasan_##OP(cpu_env, addr); \
    \
    }
    宏GEN_QASAN_OP(OP)动态生成一个名为 qasan_gen_##OP 的函数，其中 ## 是宏的拼接符，会将传入的 OP 参数拼接到函数名中。
    
    GEN_QASAN_OP(load1)
    实例化宏生成函数 qasan_gen_load1，对应1字节内存加载操作（如 ldrb 指令）。

    qasan_gen_load1(addr, idx)调用gen_helper_qasan_load1()函数

tcg_gen_qemu_ld_i32()
    -> qasan_gen_load1(addr, idx)
        -> gen_helper_qasan_load1
            -> helper_qasan_load1()
                -> asan_giovese_load1()



问题1：qemu是在哪里调用了asan_giovese_load函数？
//----------------------------------
// Usermode helpers
//----------------------------------
void HELPER(qasan_load1)(CPUArchState *env, target_ulong addr) {

  if (qasan_disabled) return;
  
  void* ptr = (void*)g2h(addr);

#ifdef ASAN_GIOVESE
  if (asan_giovese_load1(ptr)) {
    asan_giovese_report_and_crash(ACCESS_TYPE_LOAD, addr, 1, PC_GET(env), BP_GET(env), SP_GET(env));
  }
#else
  __asan_load1(ptr);
#endif

}

qasan_load1的调用：
//helper-tcg.h
#define DEF_HELPER_FLAGS_2(NAME, FLAGS, ret, t1, t2) \
  { .func = HELPER(NAME), .name = str(NAME), .flags = FLAGS, \
    .sizemask = dh_sizemask(ret, 0) | dh_sizemask(t1, 1) \
    | dh_sizemask(t2, 2) },

//helper-proto.h
#define DEF_HELPER_FLAGS_2(name, flags, ret, t1, t2) \
dh_ctype(ret) HELPER(name) (dh_ctype(t1), dh_ctype(t2));
//helper-gen.h

#define DEF_HELPER_FLAGS_2(name, flags, ret, t1, t2)                    \
static inline void glue(gen_helper_, name)(dh_retvar_decl(ret)          \
    dh_arg_decl(t1, 1), dh_arg_decl(t2, 2))                             \
{                                                                       \
  TCGTemp *args[2] = { dh_arg(t1, 1), dh_arg(t2, 2) };                  \
  tcg_gen_callN(HELPER(name), dh_retvar(ret), 2, args);                 \
}

宏的作用与阶段划分
这三个宏分别属于 代码生成流程的不同阶段，通过宏重定义（Redefine）实现多态性，具体分工如下：

头文件	作用阶段	功能
helper-proto.h	函数原型声明	生成Helper函数的原型声明（如 ret helper_name(t1, t2)）
helper-tcg.h	Helper描述结构	定义Helper函数的元数据结构（如函数指针、参数类型、调用标志等）
helper-gen.h	调用代码生成	生成调用Helper函数的TCG中间代码（如 tcg_gen_callN 操作）

在大型项目（如QEMU）中，多个同名宏 `DEF_HELPER_FLAGS_2` 的存在是为了实现 **分阶段代码生成**。虽然宏名称相同，但它们在不同的上下文中被定义和展开，服务于不同的代码生成阶段，通过条件编译或包含顺序避免冲突。以下是具体分析：

---

**2. 具体展开过程**
**(1) `helper-proto.h`：生成函数原型**
```c
// 定义原型声明宏
#define DEF_HELPER_FLAGS_2(name, flags, ret, t1, t2) \
dh_ctype(ret) HELPER(name) (dh_ctype(t1), dh_ctype(t2));
```
- **作用**：  
  将 `DEF_HELPER_FLAGS_2(foo, 0, i32, i32, i32)` 展开为：  
  ```c
  uint32_t helper_foo(uint32_t, uint32_t);  // 函数原型
  ```
- **意义**：  
  在编译时声明Helper函数的原型，供其他代码调用。

---

**(2) `helper-tcg.h`：生成元数据结构**
```c
// 定义Helper描述宏
#define DEF_HELPER_FLAGS_2(NAME, FLAGS, ret, t1, t2) \
  { .func = HELPER(NAME), .name = str(NAME), .flags = FLAGS, \
    .sizemask = dh_sizemask(ret, 0) | dh_sizemask(t1, 1) | dh_sizemask(t2, 2) },
```
- **作用**：  
  将 `DEF_HELPER_FLAGS_2(foo, 0, i32, i32, i32)` 展开为：  
  ```c
  { .func = helper_foo, .name = "foo", .flags = 0, 
    .sizemask = ... },  // 描述Helper函数的结构体
  ```
- **意义**：  
  构建一个全局的Helper函数描述表，记录函数指针、名称、参数类型等信息，供动态代码生成（如TCG）使用。

---

**(3) `helper-gen.h`：生成调用代码**
```c
// 定义调用生成宏
#define DEF_HELPER_FLAGS_2(name, flags, ret, t1, t2) \
static inline void gen_helper_##name(...) { \
  tcg_gen_callN(helper_##name, ...); \
}
```
- **作用**：  
  将 `DEF_HELPER_FLAGS_2(foo, 0, i32, i32, i32)` 展开为：  
  ```c
  static inline void gen_helper_foo(...) { 
    tcg_gen_callN(helper_foo, ...);  // 生成调用helper_foo的TCG代码
  }
  ```
- **意义**：  
  生成静态内联函数 `gen_helper_foo`，用于在翻译ARM指令时插入对 `helper_foo` 的调用。

---

**3. 为何不冲突？**
**(1) 分阶段包含**
项目通过 **控制头文件包含顺序** 和 **条件编译**，确保每个阶段只展开对应的宏定义：
1. 在需要生成原型时包含 `helper-proto.h`，此时宏定义为原型声明。
2. 在需要构建Helper表时包含 `helper-tcg.h`，此时宏被重定义为结构体初始化。
3. 在需要生成调用代码时包含 `helper-gen.h`，此时宏被重定义为中间代码生成。

**(2) 宏的覆盖性**
C语言的宏遵循 **后定义覆盖前定义** 的规则。通过合理组织头文件包含顺序，确保每个阶段使用正确的宏定义：
```c
// 第一阶段：生成原型
#include "helper-proto.h"
DEF_HELPER_FLAGS_2(foo, ...);  // 展开为原型声明

// 第二阶段：生成结构体
#undef DEF_HELPER_FLAGS_2       // 取消之前的定义
#include "helper-tcg.h"
DEF_HELPER_FLAGS_2(foo, ...);  // 展开为结构体初始化

// 第三阶段：生成调用代码
#undef DEF_HELPER_FLAGS_2
#include "helper-gen.h"
DEF_HELPER_FLAGS_2(foo, ...);  // 展开为调用生成函数
```

---

**4. 设计优势**
这种设计模式在系统级项目（如QEMU）中非常常见，核心优势在于：
1. **代码复用**：通过宏模板统一管理不同阶段的代码生成，减少重复代码。
2. **扩展性**：新增一个Helper函数只需在单个位置定义，自动生成原型、元数据和调用代码。
3. **类型安全**：通过 `dh_ctype` 等宏处理类型转换，确保参数类型正确性。

---

**总结**
这三个同名宏 `DEF_HELPER_FLAGS_2` 本质上是一个 **代码生成模板**，通过宏重定义在不同阶段生成不同的代码片段。这种设计模式在需要多阶段代码生成的场景中非常高效，尽管看起来有些“魔法”，但通过合理的工程组织确保了可维护性和扩展性。


我使用fprintf(stderr,"qasan_load1");调试时发现qemu-arm并没有调用HELPER(qasan_load1)，故不再纠结
错误：



### qasan_shadow_stack_push
进一步调试发现：
在运行过程中调用了：
void HELPER(qasan_shadow_stack_push)(target_ulong ptr) {
  fprintf(stderr,"qasan_shadow_stack_push\n");

#if defined(TARGET_ARM)
  ptr &= ~1; 
#endif

  if (unlikely(!qasan_shadow_stack.first)) {
    
    qasan_shadow_stack.first = malloc(sizeof(struct shadow_stack_block));
    qasan_shadow_stack.first->index = 0;
    qasan_shadow_stack.size = 0; // may be negative due to last pop
    qasan_shadow_stack.first->next = NULL;

  }
    
  qasan_shadow_stack.first->buf[qasan_shadow_stack.first->index++] = ptr;
  qasan_shadow_stack.size++;

  if (qasan_shadow_stack.first->index >= SHADOW_BK_SIZE) {

      struct shadow_stack_block* ns = malloc(sizeof(struct shadow_stack_block));
      ns->next = qasan_shadow_stack.first;
      ns->index = 0;
      qasan_shadow_stack.first = ns;
  }

}


#### 分析
这段代码实现了一个 **影子栈（Shadow Stack）的压入操作**，主要用于QEMU的地址消毒（QASan）功能，检测程序执行过程中的栈溢出或异常跳转。以下是逐部分解析：

qasan_shadow_stack:
```c
struct shadow_stack_block {

  int index;
  target_ulong buf[SHADOW_BK_SIZE];
  
  struct shadow_stack_block* next;

};

struct shadow_stack {

  int size;
  struct shadow_stack_block* first;

};
```

1. ARM架构地址修正
```c
#if defined(TARGET_ARM)
  ptr &= ~1; // 清除最低位（ARM/Thumb模式切换标志）
#endif
```  
  ARM架构中，指令地址的最低位用于指示Thumb模式（1表示Thumb，0表示ARM）。    
  若目标平台是ARM，清除 `ptr` 的最低位，确保地址对齐（实际指令地址是字对齐的）。

2. 影子栈初始化
```c
  if (unlikely(!qasan_shadow_stack.first)) { // 首次使用栈时初始化
    qasan_shadow_stack.first = malloc(sizeof(struct shadow_stack_block));
    qasan_shadow_stack.first->index = 0;
    qasan_shadow_stack.size = 0; // 可能因上次弹出操作变为负数
    qasan_shadow_stack.first->next = NULL;
  }
```

  - 若影子栈的 `first` 块未初始化（`NULL`），则分配一个内存块（`shadow_stack_block`）。  
  - 初始化块属性：  
    - `index=0`：当前块的空闲位置索引。  
    - `size=0`：全局栈大小（可能因异常操作变为负数，此处重置）。  
    - `next=NULL`：块链表指针。  
- **优化**：  
  `unlikely()` 提示编译器此分支很少发生（优化分支预测）。

---
3. 压入当前地址
```c
  qasan_shadow_stack.first->buf[qasan_shadow_stack.first->index++] = ptr;
  qasan_shadow_stack.size++;
```
- **操作**：  
  将 `ptr` 存入当前块的 `buf` 数组中，递增当前块的 `index` 和全局栈大小 `size`。

---

4. 栈块动态扩展
```c
  if (qasan_shadow_stack.first->index >= SHADOW_BK_SIZE) { // 当前块已满
    struct shadow_stack_block* ns = malloc(sizeof(struct shadow_stack_block));
    ns->next = qasan_shadow_stack.first; // 新块指向旧块
    ns->index = 0; // 新块索引重置
    qasan_shadow_stack.first = ns; // 更新栈顶为新块
  }
```
- **逻辑**：  
  - 若当前块的 `index` 达到 `SHADOW_BK_SIZE`（块容量上限），则分配新块。  
  - 新块的 `next` 指向旧块，形成链表结构。  
  - 更新栈顶指针 `first` 为新块，后续压入操作将使用新块。



问题2：在程序结束时，如何判断是否存在内存泄露？
问题3：poison机制是什么？
问题4：误报率是如何解决的？



## 内存泄露检测

可以利用 alloc_tree 维护的分配信息，并结合 shadow memory，在程序退出时检查是否仍然存在未释放的内存块。

算法思路
遍历 alloc_tree，检查所有分配的内存块

alloc_tree 维护了所有 malloc 分配的内存块信息，包括 start 和 end 地址。
在程序退出时，遍历 alloc_tree，获取所有仍然存在的分配块。
检查 shadow memory

通过 g2h(start) 计算 shadow memory 地址，并检查是否仍然标记为已分配。
如果 shadow memory 仍然标记为已分配，说明该内存块没有被释放。
记录和报告内存泄露信息

统计泄露的块数，并输出泄露的地址范围及大小。
记录相关的 alloc_ctx（调用上下文），帮助分析泄露来源。
程序退出时执行

在 __libqasan_exit() 或 qasan_finalize() 这样的退出函数中执行泄露检查逻辑。

### 子程序退出

#ifdef __NR_exit_group
        /* new thread calls */
    case TARGET_NR_exit_group:
        fprintf(stderr,"[Y]:Exiting target program...\n");
        preexit_cleanup(cpu_env, arg1);
        return get_errno(exit_group(arg1));

case TARGET_NR_exit:
        /* In old applications this may be used to implement _exit(2).
           However in threaded applictions it is used for thread termination,
           and _exit_group is used for application termination.
           Do thread termination if we have more then one thread.  */

        if (block_signals()) {
            return -TARGET_ERESTARTSYS;
        }

        cpu_list_lock();

        if (CPU_NEXT(first_cpu)) {
            TaskState *ts;

            /* Remove the CPU from the list.  */
            QTAILQ_REMOVE_RCU(&cpus, cpu, node);

            cpu_list_unlock();

            ts = cpu->opaque;
            if (ts->child_tidptr) {
                put_user_u32(0, ts->child_tidptr);
                sys_futex(g2h(ts->child_tidptr), FUTEX_WAKE, INT_MAX,
                          NULL, NULL, 0);
            }
            thread_cpu = NULL;
            object_unref(OBJECT(cpu));
            g_free(ts);
            rcu_unregister_thread();
            pthread_exit(NULL);
        }

        cpu_list_unlock();
        preexit_cleanup(cpu_env, arg1);
        _exit(arg1);
        return 0; /* avoid warning */
preexit_cleanup() 是退出前检查的核心，计划在preexit_cleanup()函数中增加检查内存泄露的逻辑



### 获取环境变量
在/home/wuhuang/fuzz/qasan/asan-giovese/asan-giovese-inl.h中定义了qasan_check_leak获取环境变量，用于进行消融实验

void report_memory_leaks() {
  char* qasan_check_leak;
  qasan_check_leak = getenv("CHECK_LEAK");
  if(qasan_check_leak)
  fprintf(stderr, "Detected memory leaks:\n");}

(base) wuhuang@wuhuang:~/fuzz/qasan$ ./qasan-qemu -L /home/wuhuang/fuzz/qasan/cramfs-root -E LD_PRELOAD=/home/wuhuang/fuzz/qasan/libqasan/libqasan.so ./tests/heap_of
using ASAN_GIOVESE
qasan_action_testasan_giovese_test
Enter input: 111
No exploit detected!

(base) wuhuang@wuhuang:~/fuzz/qasan$ CHECK_LEAK=1 ./qasan-qemu -L /home/wuhuang/fuzz/qasan/cramfs-root -E LD_PRELOAD=/home/wuhuang/fuzz/qasan/libqasan/libqasan.so ./tests/heap_of
using ASAN_GIOVESE
qasan_action_testasan_giovese_test
Enter input: 111
No exploit detected!
Detected memory leaks:

指定环境变量 CHECK_LEAK 时，可以触发 check leak 的逻辑。
此处需要更多的完善：
  - 最好是可以通过-E 设置是否进行检查
  - 检查环境变量的逻辑不完备


# 
QASAN_ALLOC(&p[1], (char*)&p[1] + size);

#define QASAN_ALLOC(start, end) \
  QASAN_CALL2(QASAN_ACTION_ALLOC, start, end)

+---------------------------+
| struct chunk_begin        | ← p 指向这里
|   requested_size          |
|   aligned_orig            |
|   next                    |
|   prev                    |
|   redzone[REDZONE_SIZE]   | <- p->redzone LZ protection region
+---------------------------+ 
| user memory               | <- &p[1]
|                           | size = requested_size
+---------------------------+
| struct chunk_struct begin | <- (char*)&p[1] + size 
|  padding region(for align)| 
|  redzone[REDZONE_SIZE]    | <- RZ protection region
|  prev_size_padding        |
+---------------------------+

#define QASAN_POISON(ptr, len, poison_byte) \
  QASAN_CALL3(QASAN_ACTION_POISON, ptr, len, poison_byte)

case QASAN_ACTION_POISON:
        // fprintf(stderr, "POISON: %p [%p] %ld %x\n", arg1, g2h(arg1), arg2, arg3);
        asan_giovese_poison_guest_region(arg1, arg2, arg3);
        break;

int asan_giovese_poison_guest_region(target_ulong addr, size_t n,
                                     uint8_t poison_byte) {

  if (!n) return 0;
  
  target_ulong start = addr;
  target_ulong end = start + n;
  target_ulong last_8 = end & ~7;
  
  if (start & 0x7) {

    target_ulong next_8 = (start & ~7) + 8;
    size_t       first_size = next_8 - start;

    if (n < first_size) return 0;

    uintptr_t h = (uintptr_t)g2h(start);
    uint8_t*  shadow_addr = (uint8_t*)(h >> 3) + SHADOW_OFFSET;
    *shadow_addr = 8 - first_size;

    start = next_8;

  }

  while (start < last_8) {

    uintptr_t h = (uintptr_t)g2h(start);
    uint8_t*  shadow_addr = (uint8_t*)(h >> 3) + SHADOW_OFFSET;
    *shadow_addr = poison_byte;
    start += 8;

  }
  return 1;

}

int asan_giovese_unpoison_guest_region(target_ulong addr, size_t n) {

  target_ulong start = addr;
  target_ulong end = start + n;

  while (start < end) {

    uintptr_t h = (uintptr_t)g2h(start);
    uint8_t*  shadow_addr = (uint8_t*)(h >> 3) + SHADOW_OFFSET;
    *shadow_addr = 0;
    start += 8;

  }

  return 1;

}
# Juliet
TP（真正例）：实际存在内存泄漏，工具正确检测到。
FP（假正例）：实际没有内存泄漏，工具误报为有泄漏。
TN（真负例）：实际没有内存泄漏，工具正确检测到没有泄漏。
FN（假负例）：实际存在内存泄漏，工具却未能检测到。

TP（True Positive） = bad() 运行的次数（即 bad() 发生泄露并正确被检测到）。
FP（False Positive） = 0（good() 没有泄露，并且没有被误报）。
TN（True Negative） = good() 运行的次数（good() 没有泄露，并正确未被误报）。
FN（False Negative） = 0（所有 bad() 发生的泄露都被检测到了）。

True Positives (TP):  649
False Negatives (FN): 714
True Negatives (TN):  1363
False Positives (FP): 0

总测试用例: 2726
准确率: 73.81%