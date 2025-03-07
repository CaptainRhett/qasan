CC := /home/wuhuang/fuzz/qasan/gcc-linaro-4.9-2016.02-x86_64_arm-linux-gnueabi/bin/arm-linux-gnueabi-gcc
CFLAGS += -L /home/wuhuang/fuzz/qasan/gcc-linaro-4.9-2016.02-x86_64_arm-linux-gnueabi/arm-linux-gnueabi -ggdb 
LDFLAGS += -Wl,--version-script=/home/wuhuang/fuzz/qasan/libqasan/libqasan.ver -ldl -pthread 

SRC := libqasan.c hooks.c malloc.c string.c uninstrument.c patch.c dlmalloc.c
HDR := libqasan.h

all: $(HDR) $(SRC)
	$(CC) $(CFLAGS) -fPIC -shared -I ../include $(SRC) -o libqasan.so $(LDFLAGS)

debug: $(HDR) $(SRC)
	$(CC) $(CFLAGS) -DDEBUG=1 -fPIC -shared -I ../include $(SRC) -o libqasan.so $(LDFLAGS)

clean:
	rm -rf *.so