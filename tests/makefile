CC := /home/wuhuang/fuzz/qasan/gcc-linaro-4.9-2016.02-x86_64_arm-linux-gnueabi/bin/arm-linux-gnueabi-gcc
CFLAGS += -L /home/wuhuang/fuzz/qasan/gcc-linaro-4.9-2016.02-x86_64_arm-linux-gnueabi/arm-linux-gnueabi -ggdb -g -fno-stack-protector -z execstack

SRC := memLeak.c 
HDR := memLeak
all: $(HDR) $(SRC)
	$(CC) $(CFLAGS) -o $(HDR) $(SRC)