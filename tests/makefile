# 定义变量
SRC_FILES := double_free.c invalid_free.c oob_neg_read.c printf_oob.c strcmp.c

# 编译器和标志
CC_x86 := gcc
CC_arm := arm-linux-gnueabi-gcc
CC_aarch64 := aarch64-linux-gnu-gcc
CFLAGS := -static #需要指定静态编译

# 定义生成目录
BUILD_DIR := build
BUILD_DIR_x86 := $(BUILD_DIR)/x86
BUILD_DIR_arm := $(BUILD_DIR)/arm
BUILD_DIR_aarch64 := $(BUILD_DIR)/aarch64

# 默认目标
.PHONY: all clean cleanx86 cleanarm cleanaarch64 x86 arm aarch64

# 默认目标：构建所有架构的目标
all: x86 arm aarch64

# 编译每个源文件并生成不同架构的可执行文件

x86: $(addprefix $(BUILD_DIR_x86)/, $(SRC_FILES:.c=_x86))
	@echo "x86 build complete"

arm: $(addprefix $(BUILD_DIR_arm)/, $(SRC_FILES:.c=_arm))
	@echo "arm build complete"

aarch64: $(addprefix $(BUILD_DIR_aarch64)/, $(SRC_FILES:.c=_aarch64))
	@echo "aarch64 build complete"

# 对每个架构进行编译
$(BUILD_DIR_x86)/%_x86: %.c
	@mkdir -p $(BUILD_DIR_x86)
	$(CC_x86) $(CFLAGS) $< -o $@

$(BUILD_DIR_arm)/%_arm: %.c
	@mkdir -p $(BUILD_DIR_arm)
	$(CC_arm) $(CFLAGS) $< -o $@

$(BUILD_DIR_aarch64)/%_aarch64: %.c
	@mkdir -p $(BUILD_DIR_aarch64)
	$(CC_aarch64) $(CFLAGS) $< -o $@

# 清理目标
clean: cleanx86 cleanarm cleanaarch64

cleanx86:
	@echo "Cleaning x86 build..."
	@rm -rf $(BUILD_DIR_x86)

cleanarm:
	@echo "Cleaning arm build..."
	@rm -rf $(BUILD_DIR_arm)

cleanaarch64:
	@echo "Cleaning aarch64 build..."
	@rm -rf $(BUILD_DIR_aarch64)
