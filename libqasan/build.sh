#! /bin/bash
export CC=arm-linux-gnueabi-gcc
export CXX=arm-linux-gnueabi-g++
export CFLAGS="--sysroot=/home/wuhuang/fuzz/qasan/cramfs-root"
export LDFLAGS="--sysroot=/home/wuhuang/fuzz/qasan/cramfs-root"
make 