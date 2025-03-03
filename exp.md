# 使用qasan检测spx_restservice软件
指令
./qasan-qemu -L /home/wuhuang/fuzz/qasan/cramfs-root -E LD_PRELOAD=/home/wuhuang/fuzz/qasan/host-libs/libqasan.so ./spx_restservice
 报错
 ./spx_restservice: /lib/arm-linux-gnueabi/libc.so.6: version `GLIBC_2.34' not found (required by /home/wuhuang/fuzz/qasan/host-libs/libqasan.so)
 ./spx_restservice: /lib/arm-linux-gnueabi/libc.so.6: version `GLIBC_2.38' not found (required by /home/wuhuang/fuzz/qasan/host-libs/libqasan.so)

指令
./qasan-qemu 
    -E LD_PRELOAD=/home/wuhuang/fuzz/qasan/host-libs/libqasan.so 
    ./spx_restservice 
 报错
 ./spx_restservice: error while loading shared libraries: libsafesystem.so.2: cannot open shared object file: No such file or directory

指令
./qasan-qemu 
    -E LD_PRELOAD=/home/wuhuang/fuzz/qasan/host-libs/libqasan.so 
    -L /home/wuhuang/fuzz/qasan/cramfs-root 
    ./spx_restservice
 报错
 ./spx_restservice: /lib/arm-linux-gnueabi/libc.so.6: version `GLIBC_2.34' not found (required by /home/wuhuang/fuzz/qasan/host-libs/libqasan.so)
 ./spx_restservice: /lib/arm-linux-gnueabi/libc.so.6: version `GLIBC_2.38' not found (required by /home/wuhuang/fuzz/qasan/host-libs/libqasan.so)

# 尝试解决
## 使用固件环境编译libqasan:

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

## 静态编译libqasan：
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

## 分析
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