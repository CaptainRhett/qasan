#!/usr/bin/env python3
'''
Copyright (c) 2019-2020, Andrea Fioraldi


Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
'''

import os
import sys
import shutil
import platform
import argparse

DESCR = """QEMU-AddressSanitizer Builder
Copyright (C) 2019 Andrea Fioraldi <andreafioraldi@gmail.com>
"""

EPILOG="""Note that the ASan DSO must refer to the host arch in a coherent way
with TARGET_BITS. For example, if the target is arm32 you have to provide the
i386 ASan DSO, if teh target if x86_64 you have to provide the x86_64 DSO.
As example, on Ubuntu 18.04, it is:
/usr/lib/llvm-8/lib/clang/8.0.0/lib/linux/libclang_rt.asan-x86_64.so

"""

ARCHS = {
  "x86_64": "x86_64",
  "amd64": "x86_64",
  "x86": "i386",
  "i386": "i386",
  "arm": "arm",
  "arm64": "aarch64",
  "aarch64": "aarch64",
  #"mips": "mips",
  #"mips64": "mips64",
  #"mipsel": "mipsel",
  #"mips64el": "mips64el",
}

ARCHS_32 = ["i386", "arm", "mips", "mipsel"]
ARCHS_CROSS = list(set(ARCHS.values()))
ARCHS_CROSS.remove("i386")
ARCHS_CROSS.remove("x86_64")

dir_path = os.path.dirname(os.path.realpath(__file__))

# 接收并处理参数
opt = argparse.ArgumentParser(description=DESCR, epilog=EPILOG, formatter_class=argparse.RawTextHelpFormatter)
opt.add_argument("--arch", help="Set target architecture (default x86_64)", action='store', default="x86_64")
opt.add_argument('--asan-dso', help="Path to ASan DSO", action='store')
opt.add_argument("--clean", help="Clean builded files", action='store_true')
opt.add_argument("--debug", help="Compile debug libqasan", action='store_true')
opt.add_argument("--system", help="(eperimental) Build qemu-system", action='store_true')
opt.add_argument("--cc", help="C compiler (default clang-8)", action='store', default="clang")
opt.add_argument("--cxx", help="C++ compiler (default clang++-8)", action='store', default="clang++")
opt.add_argument("--cross", help="Cross C compiler for libqasan", action='store')

args = opt.parse_args()

def try_remove(path):
    print("Deleting", path)
    try:
        os.remove(path)
    except:
        pass

if args.clean:
    print("Cleaning...")
    try_remove(os.path.join(dir_path, "qasan-qemu"))
    try_remove(os.path.join(dir_path, "libqasan.so"))
    try_remove(os.path.join(dir_path, "libqasan", "libqasan.so"))
    # try_remove(output_dso)
    os.system("""cd '%s' ; make clean""" % (os.path.join(dir_path, "qemu")))
    print("Successful clean.")
    print("")
    exit(0)

if args.arch not in ARCHS:
    print("ERROR:", args.arch, "is not a supported architecture.")
    print("Supported architectures are", ", ".join(ARCHS.keys()))
    print("")
    exit(1)

if shutil.which(args.cc) is None and not os.path.isfile(args.cc):
    print("ERROR:", args.cc, " not found.")
    print("Specify another C compiler with --cc")
    print("")
    exit(1)
if shutil.which(args.cxx) is None and not os.path.isfile(args.cxx):
    print("ERROR:", args.cxx, " not found.")
    print("Specify another C++ compiler with --cxx")
    print("")
    exit(1)

# 修改一个 AddressSanitizer (ASan) 动态库（DSO）的符号表，
# 通过重命名一些符号来实现对某些函数的重新绑定（或去拦截）。
# 在linux系统中，动态链接器加载程序时会解析动态库的符号

def deintercept(asan_dso, output_dso):
    global arch
    print("Patching", asan_dso)
    
    try:
        import lief
    except ImportError:
        print("ERROR: lief not installed.")
        print("   $ pip3 install lief --user")
        print("")
        exit(1)
    # 使用lief加载elf文件
    lib = lief.parse(asan_dso)

    names = []
    # 在动态库中查找所有名称以 __interceptor_ 开头的函数符号。
    # 将它们的名称存储在 names 列表中，但去掉前缀 __interceptor_
    for index, symbol in enumerate(lib.symbols):
        if symbol.type == lief.ELF.SYMBOL_TYPES.FUNC and symbol.name.startswith("__interceptor_"):
            names.append(lib.symbols[index].name[len("__interceptor_"):])

    #names = ["malloc", "calloc", "realloc", "valloc", "pvalloc", "memalign", "posix_memalign", "free"]

    # 对于库中所有绑定为弱（WEAK）的函数符号：
    # 如果其名称出现在 names 列表中，将符号重命名为 __qasan_ + 原名称。
    for index, symbol in enumerate(lib.symbols):
        if symbol.type == lief.ELF.SYMBOL_TYPES.FUNC and symbol.binding == lief.ELF.SYMBOL_BINDINGS.WEAK and symbol.name in names:
            print("Renaming ", symbol)
            lib.symbols[index].name = "__qasan_" + symbol.name

    lib.write(output_dso)

arch = ARCHS[args.arch]

extra_c_flags = ""
if args.asan_dso:
    # on Ubuntu 18.04: /usr/lib/llvm-8/lib/clang/8.0.0/lib/linux/libclang_rt.asan-x86_64.so
    if not os.path.isfile(args.asan_dso):
        print("ERROR:", args.asan_dso, "not found.")
        print("")
        exit(1)

    output_dso = os.path.join(dir_path, os.path.basename(args.asan_dso))
    lib_dso = os.path.basename(args.asan_dso)
    if lib_dso.startswith("lib"): lib_dso = lib_dso[3:]
    if lib_dso.endswith(".so"): lib_dso = lib_dso[:-3]

    extra_ld_flags = "-L %s -l%s -Wl,-rpath,.,-rpath,%s" % (dir_path, lib_dso, dir_path)
    # -L %s：指定动态库的搜索路径（即 dir_path）。
    # -l%s：使用库的基本名称（如 asan-x86_64）。
    # -Wl,-rpath：为动态链接器设置运行时搜索路径。
    deintercept(args.asan_dso, output_dso)
else:
    # if the ASan DSO is not specified, use asan-giovese
    if arch not in ("x86_64", "i386", "arm", "aarch64"):
        print("ERROR: asan-giovese is still not supported for %s." % arch)
        print("Please specify the ASan DSO with --asan-dso")
        print("")
        exit(1)
    
    print("")
    print("WARNING: QASan with asan-giovese is an experimental feature!")
    print("")
    
    extra_ld_flags = ""
    extra_c_flags = "-DASAN_GIOVESE=1 -DTARGET_ULONG=target_ulong -I " + os.path.join(dir_path, "asan-giovese", "interval-tree")

cross_cc = args.cc
if arch in ARCHS_CROSS:
    if args.cross is None:
        cross_cc = "%s-linux-gnu-gcc" % arch
        print("")
        print("WARNING: The selected arch needs a cross compiler for libqasan")
        print("We selected %s by default, use --cross to specify a custom one" % cross_cc)
        print("")
    else:
        cross_cc = args.cross
# 检查指定的交叉编译器是否存在于系统的路径中
# shutil.which会在系统的PATH环境变量中搜索指定文件的名称
if shutil.which(cross_cc) is None:
    print("ERROR:", cross_cc, " not found.")
    print("Specify another Cross C compiler with --cross")
    print("")
    exit(1)
#用于构建和配置一个定制版本的 QEMU
# 它支持两种模式的构建：用户模式和系统模式。
# 根据 args.system 参数的值，代码会执行不同的构建流程

# args.system == False 执行用户模式的构建流程，默认为true
if not args.system:
    '''if not args.asan_dso:
        print("ERROR: usermode QASan still depends on ASan.")
        print("Please specify the ASan DSO with --asan-dso")
        print("")
        exit(1)'''
    
    cpu_qemu_flag = ""
    # 如果架构是 32 位（arch 在 ARCHS_32 中），并且指定了 asan_dso，
    # 则输出警告，提醒用户需要安装 32 位的库和设置 PKG_CONFIG_PATH 环境变量。
    if arch in ARCHS_32 and args.asan_dso:
        cpu_qemu_flag = "--cpu=i386" # 
        print("")
        print("WARNING: To do a 32 bit build, you have to install i386 libraries and set PKG_CONFIG_PATH")
        print("If you haven't did it yet, on Ubuntu 18.04 it is PKG_CONFIG_PATH=/usr/lib/i386-linux-gnu/pkgconfig")
        print("")

    # 配置qemu
    # 运行 QEMU 的配置命令（./configure），为 linux-user 模式配置构建选项。
        # 参数包括：
        # target-list="%s-linux-user":  目标架构（如 x86_64-linux-user）。
        # --disable-system:             禁用系统模式构建。
        # --enable-pie:                 启用位置独立可执行文件。
        # --cc="%s", --cxx="%s":        使用指定的 C 和 C++ 编译器。
        # 其他编译选项如 extra-cflags 和 extra-ldflags 用于设置编译器的优化和链接选项。
    cmd = """cd '%s' ; ./configure --target-list="%s-linux-user" --disable-system --enable-pie \
      --cc="%s" --cxx="%s" %s --extra-cflags="-O3 -ggdb %s" --extra-ldflags="%s" \
      --enable-linux-user --disable-gtk --disable-sdl --disable-vnc --disable-strip""" \
      % (os.path.join(dir_path, "qemu"), arch, args.cc, args.cxx, cpu_qemu_flag,
   extra_c_flags, extra_ld_flags)
    print (cmd)
    assert (os.system(cmd) == 0)

    # 执行 make -j 命令来并行编译 QEMU。nproc 命令会返回当前系统上的 CPU 核心数，从而决定并行编译的任务数。
    cmd = """cd '%s' ; make -j `nproc`""" % (os.path.join(dir_path, "qemu"))
    print (cmd)
    assert (os.system(cmd) == 0)

    # 将编译后的 QEMU 可执行文件（如 qemu-x86_64）复制到 qasan-qemu，为后续使用提供可执行文件
    shutil.copy2(
      os.path.join(dir_path, "qemu", arch + "-linux-user", "qemu-" + arch),
      os.path.join(dir_path, "qasan-qemu")
    )
    
    # 设置 libqasan 的编译选项
    # 对于 32 位架构，加入 -m32 标志
    libqasan_cflags = "-Wno-int-to-void-pointer-cast -ggdb"
    if arch == "i386":
        libqasan_cflags += " -m32"

    # 根据 args.debug 判断是否编译调试版本的 libqasan
    # 执行 make 命令编译 libqasan 库
    libqasan_target = ''
    if args.debug:
        libqasan_target = 'debug'
    assert ( os.system("""cd '%s' ; make %s CC='%s' CFLAGS='%s'"""
      % (os.path.join(dir_path, "libqasan"), libqasan_target, cross_cc,
         libqasan_cflags)) == 0 )
    
    # 将编译后的 libqasan.so 复制到当前目录
    shutil.copy2(
      os.path.join(dir_path, "libqasan", "libqasan.so"),
      dir_path
    )

    print("Successful build.")
    print("Test it with ./qasan /bin/ls")
    print("")
# 系统模式
else:
    cmd = """cd '%s' ; ./configure --target-list="%s-softmmu" --enable-pie \
      --cc="%s" --cxx="%s" --extra-cflags="-O3 -ggdb %s" --extra-ldflags="%s" \
      --disable-linux-user --disable-sdl --disable-vnc --disable-strip""" \
      % (os.path.join(dir_path, "qemu"), arch, args.cc, args.cxx,
         extra_c_flags, extra_ld_flags)
    print (cmd)
    assert (os.system(cmd) == 0)
    
    cmd = """cd '%s' ; make -j `nproc`""" % (os.path.join(dir_path, "qemu"))
    print (cmd)
    assert (os.system(cmd) == 0)
    
    if os.path.exists(os.path.join(dir_path, "qasan-system")):
        os.unlink(os.path.join(dir_path, "qasan-system"))
    
    os.symlink(
      os.path.join(dir_path, "qemu", arch + "-softmmu", "qemu-system-" + arch),
      os.path.join(dir_path, "qasan-system")
    )

    print("Successful build.")
    print("")
