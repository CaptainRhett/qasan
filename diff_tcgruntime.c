/////////////////////////////////////////////////
//                   QASAN
/////////////////////////////////////////////////

#include "qasan-qemu.h"
#define ASAN_GIOVESE 
#define CONFIG_USER_ONLY
// options
int qasan_max_call_stack = 16; // QASAN_MAX_CALL_STACK
int qasan_symbolize = 1; // QASAN_SYMBOLIZE

#ifndef CONFIG_USER_ONLY

__thread CPUState* qasan_cpu;
#define g2h(x) \
  ({ \
    void *_a; \
    if (!qasan_addr_to_host(qasan_cpu, (x), &_a)) {\
      /* fprintf(stderr, "QASan error: virtual address translation for %p failed!\n", (x)); */ \
      return 0;\
    } \
    _a; \
  })
// # qasan_addr_to_host(CPUState* cpu, target_ulong addr, void** host_addr):
// # 将虚拟地址 addr 转换为主机上的物理内存地址，并将其存储在 host_addr 中
// # g2h(x):的值为转换后的物理地址（如果成功转换的话）

// h2g must not be defined
// #define h2g(x) (x)

#endif

int qasan_addr_to_host(CPUState* cpu, target_ulong addr, void** host_addr);

int __qasan_debug;
__thread int qasan_disabled;

__thread struct shadow_stack qasan_shadow_stack; # 每个线程维护一个影子栈区

#ifdef ASAN_GIOVESE

#include "../../asan-giovese/interval-tree/rbtree.c"
#include "../../asan-giovese/asan-giovese-inl.h"

#include <sys/types.h>
#include <sys/syscall.h>

// # asan_giovese_populate_context 的目的是填充一个 call_context 结构体 ctx，用于描述当前的调用栈信息
// # ctx: 一个指向 call_context 结构体的指针，用于保存当前的调用栈上下文
// # pc: 程序计数器（Program Counter），表示当前执行指令的地址
/*
struct call_context {

  target_ulong* addresses;
  uint32_t      tid;
  uint32_t      size;

};
*/


void asan_giovese_populate_context(struct call_context* ctx, target_ulong pc) {

  ctx->size = MIN(qasan_shadow_stack.size, qasan_max_call_stack -1) 1;
  ctx->addresses = calloc(sizeof(void*), ctx->size);

// # 这部分代码设置 ctx 中的 size 字段，表示调用栈的大小
// # 大小由 qasan_shadow_stack.size 和 qasan_max_call_stack - 1 中的较小值确定，并加上 1
// # 然后为 ctx->addresses 分配内存空间，addresses 用来存储栈中每个函数调用的返回地址。
  
// # 获取线程id
// # 根据平台不同，代码会通过系统调用或 pthread 库获取当前线程的 ID，并将其存储在 ctx->tid 中
#ifdef __NR_gettid //获取线程id的系统调用
  ctx->tid = (uint32_t)syscall(__NR_gettid);
#else
  pthread_id_np_t tid;
  pthread_t self = pthread_self();
  pthread_getunique_np(&self, &tid);
  ctx->tid = (uint32_t)tid;
#endif

// # 设置栈的第一个地址为pc
  ctx->addresses[0] = pc;
  
// # 如果 qasan_shadow_stack.size 小于或等于零，表示没有有效的栈信息，函数直接返回
// # 然后使用两个循环遍历并填充调用栈的地址：
  if (qasan_shadow_stack.size <= 0) return; //can be negative when pop does not find nothing
  
  int i, j = 1;
// # 第一个循环从 qasan_shadow_stack.first->buf 中的索引位置开始，依次填充 ctx->addresses
// # qasan_shadow_stack.first 是栈的第一个块，buf[i] 存储了栈的调用地址
  for(i = qasan_shadow_stack.first->index -1; i >= 0 && j < qasan_max_call_stack; --i)
    ctx->addresses[j] = qasan_shadow_stack.first->buf[i];

// # 遍历 qasan_shadow_stack 中的其他块，并填充它们的返回地址到 ctx->addresses 中。b->buf[i] 是每个块中存储的返回地址。
  struct shadow_stack_block* b = qasan_shadow_stack.first->next;
  while (b && j < qasan_max_call_stack) {
  
    for (i = SHADOW_BK_SIZE-1; i >= 0; --i)
      ctx->addresses[j] = b->buf[i];
  
  }

}

#ifdef CONFIG_USER_ONLY

// # addr2line_cmd函数用于将一个给定的地址（通过 lib 和 off 参数提供）转化为相应的函数名和代码行号
// # 这个转换是通过运行系统命令 addr2line 来完成的
// # param：
// #       lib:        一个指向字符串的指针，表示库文件路径（如 libc.so）。
// #       off:        表示偏移量（地址的偏移）。
// #       function:   一个指向字符串指针的指针，用于返回符号化后的函数名。
// #       line:       一个指向字符串指针的指针，用于返回符号化后的代码行号。
// # 工作流程：
// #       如果 qasan_symbolize 标志未设置，函数直接跳过
// #       使用 snprintf 构造 addr2line 命令，并通过 popen 执行它。该命令将地址符号化为函数名和行号
// #       通过 fgets 获取输出的函数名和行号，如果无法获取有效的符号信息（例如输出为 ??），则返回 NULL
static void addr2line_cmd(char* lib, uintptr_t off, char** function, char** line) {
  
  if (!qasan_symbolize) goto addr2line_cmd_skip;
  
  FILE *fp;

  size_t cmd_siz = 128  strlen(lib);
  char* cmd = malloc(cmd_siz);
  snprintf(cmd, cmd_siz, "addr2line -f -e '%s' 0x%lx", lib, off);
// # snprintf 函数来格式化并生成一个字符串 cmd，该字符串会被传递给 addr2line 工具，用于将程序中的地址（0x%lx）转换为源代码中的行号和函数名

//   fp = popen(cmd, "r");
//   free(cmd);
// # popen() 是一个标准库函数，它用来启动一个进程并建立一个管道与父进程之间的通信。
// #       它执行指定的 cmd 命令并返回一个 FILE* 类型的文件指针，该文件指针可以像操作文件一样进行读取或写入。
// # cmd 是要执行的命令，通常是一个 shell 命令（例如 "ls -l" 或 "echo Hello"）。
// # "r" 是模式参数，表示以只读模式打开管道，即读取该命令的标准输出。
  
  if (fp == NULL) goto addr2line_cmd_skip;

  *function = malloc(PATH_MAX  32);
  
  if (!fgets(*function, PATH_MAX  32, fp) || !strncmp(*function, "??", 2)) {

    free(*function);
    *function = NULL;

  } else {

    size_t l = strlen(*function);
    if (l && (*function)[l-1] == '\n')
      (*function)[l-1] = 0;
      
  }
  
  *line = malloc(PATH_MAX  32);
  
  if (!fgets(*line, PATH_MAX  32, fp) || !strncmp(*line, "??:", 3) ||
      !strncmp(*line, ":?", 2)) {

    free(*line);
    *line = NULL;

  } else {

    size_t l = strlen(*line);
    if (l && (*line)[l-1] == '\n')
      (*line)[l-1] = 0;
      
  }
  
  pclose(fp);
  
  return;

addr2line_cmd_skip:
  *line = NULL;
  *function = NULL;
  
}

// # asan_giovese_printaddr 函数用于根据给定的 guest_addr 地址查找并返回该地址对应的函数名和代码行号。
// # param：
// #       guest_addr: 客体程序中的地址
char* asan_giovese_printaddr(target_ulong guest_addr) {

  FILE *fp;
  char *line = NULL;
  size_t len = 0;
  ssize_t read;

  fp = fopen("/proc/self/maps", "r");
  if (fp == NULL)
      return NULL;
  
  uint64_t img_min = 0, img_max = 0;
  char img_path[512] = {0};

  while ((read = getline(&line, &len, fp)) != -1) {
  
    int fields, dev_maj, dev_min, inode;
    uint64_t min, max, offset;
    char flag_r, flag_w, flag_x, flag_p;
    char path[512] = "";
    fields = sscanf(line, "%"PRIx64"-%"PRIx64" %c%c%c%c %"PRIx64" %x:%x %d"
                    " %512s", &min, &max, &flag_r, &flag_w, &flag_x,
                    &flag_p, &offset, &dev_maj, &dev_min, &inode, path);

    if ((fields < 10) || (fields > 11))
        continue;

    if (h2g_valid(min)) {

      int flags = page_get_flags(h2g(min));
      max = h2g_valid(max - 1) ? max : (uintptr_t)g2h(GUEST_ADDR_MAX)  1;
      if (page_check_range(h2g(min), max - min, flags) == -1)
          continue;
      
      if (img_min && !strcmp(img_path, path)) {
        img_max = max;
      } else {
        img_min = min;
        img_max = max;
        strncpy(img_path, path, 512);
      }

      if (guest_addr >= h2g(min) && guest_addr < h2g(max - 1)  1) {
      
        uintptr_t off = guest_addr - h2g(img_min);
      
        char* s;
        char * function = NULL;
        char * codeline = NULL;
        if (strlen(path)) {
          addr2line_cmd(path, off, &function, &codeline);
          if (!function)
            addr2line_cmd(path, guest_addr, &function, &codeline);
        }

        if (function) {
        
          if (codeline) {
          
            size_t l = strlen(function)  strlen(codeline)  32;
            s = malloc(l);
            snprintf(s, l, " in %s %s", function, codeline);
            free(codeline);
            
          } else {

            size_t l = strlen(function)  strlen(path)  32;
            s = malloc(l);
            snprintf(s, l, " in %s (%s0x%lx)", function, path,
                     off);

          }
          
          free(function);
        
        } else {

          size_t l = strlen(path)  32;
          s = malloc(l);
          snprintf(s, l, " (%s0x%lx)", path, off);

        }

        free(line);
        fclose(fp);
        return s;
        
      }

    }

  }

  free(line);
  fclose(fp);

  return NULL;

}
#else
char* asan_giovese_printaddr(TARGET_ULONG guest_addr) {

  return NULL;

}
#endif

#endif

# qasan_shadow_stack_push 用于将一个指针 ptr 推入一个叫做 qasan_shadow_stack 的栈结构中
# 它的实现涉及到动态分配内存和维护栈的状态。
void HELPER(qasan_shadow_stack_push)(target_ulong ptr) {

#if defined(TARGET_ARM)
  ptr &= ~1;
#endif
# 如果目标平台是 ARM 架构，这段代码将 ptr 地址的最低位（最低的 1 位）清除
# ARM 架构通常将地址的最低位作为某种标记（例如，用于指示虚拟地址空间），此操作确保将其标准化为有效的地址。

  if (unlikely(!qasan_shadow_stack.first)) {
    
    qasan_shadow_stack.first = malloc(sizeof(struct shadow_stack_block));
    qasan_shadow_stack.first->index = 0;
    qasan_shadow_stack.size = 0; // may be negative due to last pop
    qasan_shadow_stack.first->next = NULL;

  }
// # 如果 qasan_shadow_stack.first 是 NULL，说明栈尚未初始化。此时动态分配内存为栈的第一个块（shadow_stack_block）。
    
  qasan_shadow_stack.first->buf[qasan_shadow_stack.first->index] = ptr;
  qasan_shadow_stack.size;
// # 将指针 ptr 存储到 qasan_shadow_stack.first->buf 数组中的当前位置，数组的下标由 index 指示
// # index 增加 1，表示栈中的位置向前移动
// # 栈的大小 qasan_shadow_stack.size 增加 1，表示栈中存储的元素数目增加

  if (qasan_shadow_stack.first->index >= SHADOW_BK_SIZE) {

      struct shadow_stack_block* ns = malloc(sizeof(struct shadow_stack_block));
      ns->next = qasan_shadow_stack.first;
      ns->index = 0;
      qasan_shadow_stack.first = ns;
  }
// # 如果当前栈块（qasan_shadow_stack.first）已经满（index >= SHADOW_BK_SIZE），则创建一个新的 shadow_stack_block。
// # 新创建的栈块 ns 将成为栈的顶部（即 qasan_shadow_stack.first）。
// # 新栈块的 next 指向原来的栈块，形成链式结构。
// # 新栈块的 index 初始化为 0，准备接收新的元素。

}

void HELPER(qasan_shadow_stack_pop)(target_ulong ptr) {

#if defined(TARGET_ARM)
  ptr &= ~1;
#endif

  struct shadow_stack_block* cur_bk = qasan_shadow_stack.first;
  if (unlikely(cur_bk == NULL)) return;

  if (cur_bk->index == 0) {

    struct shadow_stack_block* ns = cur_bk->next;
    if (!ns) return;
    if (ns->buf[ns->index -1] != ptr) return;

    free(cur_bk);
    qasan_shadow_stack.first = ns;
    ns->index--;

  } else if (cur_bk->buf[cur_bk->index -1] == ptr) {
    
    cur_bk->index--;

  } else return;

  qasan_shadow_stack.size--;

  /*
  do {
      
      cur_bk->index--;
      qasan_shadow_stack.size--;
      
      if (cur_bk->index < 0) {
          
          struct shadow_stack_block* ns = cur_bk->next;
          free(cur_bk);
          cur_bk = ns;
          if (!cur_bk) break;
          cur_bk->index--;
      }
  
  } while(cur_bk->buf[cur_bk->index] != ptr);
  
  qasan_shadow_stack.first = cur_bk;
  */

}

# 这段代码是一个调度器函数，qasan_actions_dispatcher，它根据传入的 action 执行不同的操作。
# 根据不同的动作（action）类型来执行相应的内存检查、分配、释放等操作。
# param：
#       cpu_env：           表示目标 CPU 环境的指针。
#       action：            操作类型，决定了执行哪个具体的操作。
#       arg1, arg2, arg3：  操作需要的附加参数。
target_long qasan_actions_dispatcher(void *cpu_env,
                                     target_long action, target_long arg1,
                                     target_long arg2, target_long arg3) {

    CPUArchState *env = cpu_env;
#ifndef CONFIG_USER_ONLY
    qasan_cpu = ENV_GET_CPU(env);
#endif

    switch(action) {

# 如果使用asan-giovese
#ifdef ASAN_GIOVESE
        case QASAN_ACTION_CHECK_LOAD:
        // fprintf(stderr, "CHECK LOAD: %p [%p] %ld\n", arg1, g2h(arg1), arg2);
        if (asan_giovese_guest_loadN(arg1, arg2)) {
          asan_giovese_report_and_crash(ACCESS_TYPE_LOAD, arg1, arg2, PC_GET(env), BP_GET(env), SP_GET(env));
        }
        break;
        
        case QASAN_ACTION_CHECK_STORE:
        // fprintf(stderr, "CHECK STORE: %p [%p] %ld\n", arg1, g2h(arg1), arg2);
        if (asan_giovese_guest_storeN(arg1, arg2)) {
          asan_giovese_report_and_crash(ACCESS_TYPE_STORE, arg1, arg2, PC_GET(env), BP_GET(env), SP_GET(env));
        }
        break;
        
        case QASAN_ACTION_POISON:
        // fprintf(stderr, "POISON: %p [%p] %ld %x\n", arg1, g2h(arg1), arg2, arg3);
        asan_giovese_poison_guest_region(arg1, arg2, arg3);
        break;
        
        case QASAN_ACTION_USER_POISON:
        //fprintf(stderr, "USER POISON: %p [%p] %ld\n", arg1, g2h(arg1), arg2);
        asan_giovese_user_poison_guest_region(arg1, arg2);
        break;
        
        case QASAN_ACTION_UNPOISON:
        //fprintf(stderr, "UNPOISON: %p [%p] %ld\n", arg1, g2h(arg1), arg2);
        asan_giovese_unpoison_guest_region(arg1, arg2);
        break;
        
        case QASAN_ACTION_IS_POISON:
        return asan_giovese_guest_loadN(arg1, arg2);
        
        case QASAN_ACTION_ALLOC: {
          //fprintf(stderr, "ALLOC: %p - %p\n", arg1, arg2);
          struct call_context* ctx = calloc(sizeof(struct call_context), 1);
          asan_giovese_populate_context(ctx, PC_GET(env));
          asan_giovese_alloc_insert(arg1, arg2, ctx);
          break;
        }
        
        case QASAN_ACTION_DEALLOC: {
          //fprintf(stderr, "DEALLOC: %p\n", arg1);
          struct chunk_info* ckinfo = asan_giovese_alloc_search(arg1);
          if (ckinfo) {
            if (ckinfo->start != arg1)
              asan_giovese_badfree(arg1, PC_GET(env));
            ckinfo->free_ctx = calloc(sizeof(struct call_context), 1);
            asan_giovese_populate_context(ckinfo->free_ctx, PC_GET(env));
          } else {
            asan_giovese_badfree(arg1, PC_GET(env));
          }
          break;
        }
# 如果 ASAN_GIOVESE 没有定义，则使用默认的 ASAN（AddressSanitizer）函数
#else
        case QASAN_ACTION_CHECK_LOAD:
        __asan_loadN(g2h(arg1), arg2);
        break;
        
        case QASAN_ACTION_CHECK_STORE:
        __asan_storeN(g2h(arg1), arg2);
        break;
        
        case QASAN_ACTION_POISON:
        __asan_poison_memory_region(g2h(arg1), arg2);
        break;
        
        case QASAN_ACTION_USER_POISON:
        __asan_poison_memory_region(g2h(arg1), arg2);
        break;
        
        case QASAN_ACTION_UNPOISON:
        __asan_unpoison_memory_region(g2h(arg1), arg2);
        break;
        
        case QASAN_ACTION_IS_POISON:
        return __asan_region_is_poisoned(g2h(arg1), arg2) != NULL;
        
        case QASAN_ACTION_ALLOC:
          break;
        
        case QASAN_ACTION_DEALLOC:
          break;
#endif

        case QASAN_ACTION_ENABLE:
        qasan_disabled = 0;
        break;
        
        case QASAN_ACTION_DISABLE:
        qasan_disabled = 1;
        break;

        case QASAN_ACTION_SWAP_STATE: {
          int r = qasan_disabled;
          qasan_disabled = arg1;
          return r;
        }

        default:
        fprintf(stderr, "Invalid QASAN action %ld\n", action);
        abort();
    }

    return 0;
}

# 函数 qasan_fake_instr的目的是通过调用 qasan_actions_dispatcher 来处理传入的参数。
void* HELPER(qasan_fake_instr)(CPUArchState *env, void* action, void* arg1,
                               void* arg2, void* arg3) {

  return (void*)qasan_actions_dispatcher(env,
                                         (target_long)action, (target_long)arg1,
                                         (target_long)arg2, (target_long)arg3);

}

#ifndef CONFIG_USER_ONLY

//----------------------------------
// Full system helpers for TLB walk
//----------------------------------

/* Macro to call the above, with local variables from the use context.  */
#define VICTIM_TLB_HIT(TY, ADDR) \
  victim_tlb_hit(env, mmu_idx, index, offsetof(CPUTLBEntry, TY), \
                 (ADDR) & TARGET_PAGE_MASK)
# 这个宏用于检查指定内存地址是否在 TLB 中，并调用 victim_tlb_hit 函数
# TY 和 ADDR 是宏的参数：
#       TY 表示要访问的 TLB 相关字段（例如 addr_read）
#       ADDR 是待检查的地址，TARGET_PAGE_MASK 用于保证地址对齐到页面边界


# victim_tlb_hit 函数用于实际检查 TLB 是否命中，并通过 offsetof(CPUTLBEntry, TY) 提取相应字段
# 该函数负责检查 TLB 是否命中，具体实现需要依赖于 TLB 的实现
# param：
#       env：指向 CPU 环境的指针。
#       mmu_idx：MMU 索引，可能用于区分不同的 MMU。
#       index：TLB 中条目的索引。
#       elt_ofs：偏移量，用于指向特定的 TLB 元素字段。
#       page：需要检查的页面地址。
bool victim_tlb_hit(CPUArchState *env, size_t mmu_idx, size_t index,
                           size_t elt_ofs, target_ulong page);

# qasan_page_loadN 的主要功能是执行内存加载操作，并在加载时进行地址检查和可能的内存保护
void qasan_page_loadN(CPUArchState *env, target_ulong addr, size_t size, uintptr_t mmu_idx)
{
    CPUTLBEntry *entry = tlb_entry(env, mmu_idx, addr);
    target_ulong tlb_addr = entry->addr_read;
# tlb_entry(env, mmu_idx, addr)：获取与给定虚拟地址 addr 相关的 TLB 条目。mmu_idx 是 MMU 索引，用于确定访问哪个 TLB 条目。
# entry->addr_read：这是从 TLB 条目中读取的地址，即映射的物理地址。
    uintptr_t haddr;
    
    /* It is in the TLB, the check is after the real access */
    if (!tlb_hit(tlb_addr, addr)) return;
# tlb_hit(tlb_addr, addr) 检查当前访问的虚拟地址 addr 是否在 TLB 中。
# 如果没有命中，函数会直接返回，意味着没有缓存该地址的映射。

    /* Handle an IO access.  */
    if (unlikely(tlb_addr & ~TARGET_PAGE_MASK))
        return;
# unlikely(tlb_addr & ~TARGET_PAGE_MASK)：检查 tlb_addr 地址是否是有效的物理地址。
# TARGET_PAGE_MASK 是一个掩码，用来确保地址符合页对齐要求。如果地址无效，返回不处理。

    haddr = addr  entry->addend;
# 根据 TLB 条目的 addend（附加值），计算实际的物理地址 haddr。
# 这是因为 TLB 条目可能包含偏移信息，修正虚拟地址到物理地址的映射。
    
#ifdef ASAN_GIOVESE
    if (asan_giovese_loadN((void*)haddr, size)) {
      qasan_cpu = ENV_GET_CPU(env);
      asan_giovese_report_and_crash(ACCESS_TYPE_LOAD, addr, size, PC_GET(env), BP_GET(env), SP_GET(env));
    }
# asan_giovese_loadN((void*)haddr, size)：这是一个内存保护检查函数，用于检测加载操作是否存在问题（例如越界或非法访问）
# 如果检查发现问题，调用 asan_giovese_report_and_crash 报告错误并崩溃程序。
#else
    __asan_loadN((void*)haddr, size);
# 这是 AddressSanitizer (ASan) 的标准加载检测函数，用于检测内存加载操作是否存在越界或访问已经释放的内存等问题
#endif
}

void qasan_page_storeN(CPUArchState *env, target_ulong addr, size_t size, uintptr_t mmu_idx)
{
    CPUTLBEntry *entry = tlb_entry(env, mmu_idx, addr);
    target_ulong tlb_addr = entry->addr_read;
# tlb_entry(env, mmu_idx, addr)：获取与给定虚拟地址 addr 相关的 TLB 条目。mmu_idx 是 MMU 索引，用于确定访问哪个 TLB 条目。
# entry->addr_read：这是从 TLB 条目中读取的地址，即映射的物理地址。
    uintptr_t haddr;
    
    /* It is in the TLB, the check is after the real access */
    if (!tlb_hit(tlb_addr, addr)) return;
# tlb_hit(tlb_addr, addr) 检查当前访问的虚拟地址 addr 是否在 TLB 中。
# 如果没有命中，函数会直接返回，意味着没有缓存该地址的映射。

    /* Handle an IO access.  */
    if (unlikely(tlb_addr & ~TARGET_PAGE_MASK))
        return;
# unlikely(tlb_addr & ~TARGET_PAGE_MASK)：检查 tlb_addr 地址是否是有效的物理地址。
# TARGET_PAGE_MASK 是一个掩码，用来确保地址符合页对齐要求。如果地址无效，返回不处理。

    haddr = addr  entry->addend;
    
#ifdef ASAN_GIOVESE
    if (asan_giovese_storeN((void*)haddr, size)) {
      qasan_cpu = ENV_GET_CPU(env);
      asan_giovese_report_and_crash(ACCESS_TYPE_STORE, addr, size, PC_GET(env), BP_GET(env), SP_GET(env));
    }
# asan_giovese_storeN((void*)haddr, size)：这是一个内存保护检查函数，用于检测存储操作是否存在问题（例如越界或非法访问）
# 如果检测到问题，调用 asan_giovese_report_and_crash 报告错误并崩溃程序。
#else
    __asan_storeN((void*)haddr, size);
# 这是 AddressSanitizer (ASan) 的标准存储检测函数，用于检测存储操作是否存在越界或访问已释放的内存等问题
#endif
}

void HELPER(qasan_load1)(CPUArchState *env, target_ulong addr, uint32_t idx)
{
    if (qasan_disabled) return;
    
    uintptr_t mmu_idx = idx;
    CPUTLBEntry *entry = tlb_entry(env, mmu_idx, addr);
    target_ulong tlb_addr = entry->addr_read;
    uintptr_t haddr;

    /* It is in the TLB, the check is after the real access */
    if (!tlb_hit(tlb_addr, addr)) return;

    /* Handle an IO access.  */
    if (unlikely(tlb_addr & ~TARGET_PAGE_MASK))
        return;

    haddr = addr  entry->addend;
    
#ifdef ASAN_GIOVESE
    if (asan_giovese_load1((void*)haddr)) {
      qasan_cpu = ENV_GET_CPU(env);
      asan_giovese_report_and_crash(ACCESS_TYPE_LOAD, addr, 1, PC_GET(env), BP_GET(env), SP_GET(env));
    }
#else
    __asan_load1((void*)haddr);
#endif
}

void HELPER(qasan_load2)(CPUArchState *env, target_ulong addr, uint32_t idx)
{
    if (qasan_disabled) return;
    
    uintptr_t mmu_idx = idx;
    CPUTLBEntry *entry = tlb_entry(env, mmu_idx, addr);
    target_ulong tlb_addr = entry->addr_read;
    uintptr_t haddr;

    /* It is in the TLB, the check is after the real access */
    if (!tlb_hit(tlb_addr, addr)) return;

    /* Handle an IO access.  */
    if (unlikely(tlb_addr & ~TARGET_PAGE_MASK))
        return;

    /* Handle slow unaligned access (it spans two pages or IO).  */
    if (unlikely((addr & ~TARGET_PAGE_MASK)  2 - 1
                    >= TARGET_PAGE_SIZE)) {
        target_ulong addr1, addr2;

        addr1 = addr & ~(2 - 1);
        addr2 = addr1  2;
        
        size_t span = addr2 - addr;
        haddr = addr  entry->addend;
        
        // tlb already processed for first half
#ifdef ASAN_GIOVESE
        if (asan_giovese_loadN((void*)haddr, span)) {
          qasan_cpu = ENV_GET_CPU(env);
          asan_giovese_report_and_crash(ACCESS_TYPE_LOAD, addr, span, PC_GET(env), BP_GET(env), SP_GET(env));
        }
#else
        __asan_loadN((void*)haddr, span);
#endif
        
        qasan_page_loadN(env, addr2, 2 - span, mmu_idx);
        return;
    }

    haddr = addr  entry->addend;
    
#ifdef ASAN_GIOVESE
    if (asan_giovese_load2((void*)haddr)) {
      qasan_cpu = ENV_GET_CPU(env);
      asan_giovese_report_and_crash(ACCESS_TYPE_LOAD, addr, 2, PC_GET(env), BP_GET(env), SP_GET(env));
    }
#else
    __asan_load2((void*)haddr);
#endif
}

void HELPER(qasan_load4)(CPUArchState *env, target_ulong addr, uint32_t idx)
{
    if (qasan_disabled) return;

    uintptr_t mmu_idx = idx;
    CPUTLBEntry *entry = tlb_entry(env, mmu_idx, addr);
    target_ulong tlb_addr = entry->addr_read;
    uintptr_t haddr;
    
    /* It is in the TLB, the check is after the real access */
    if (!tlb_hit(tlb_addr, addr)) return;

    /* Handle an IO access.  */
    if (unlikely(tlb_addr & ~TARGET_PAGE_MASK))
        return;

    /* Handle slow unaligned access (it spans two pages or IO).  */
    if (unlikely((addr & ~TARGET_PAGE_MASK)  4 - 1
                    >= TARGET_PAGE_SIZE)) {
        target_ulong addr1, addr2;

        addr1 = addr & ~(4 - 1);
        addr2 = addr1  4;
        
        size_t span = addr2 - addr;
        haddr = addr  entry->addend;
        
        // tlb already processed for first half
#ifdef ASAN_GIOVESE
        if (asan_giovese_loadN((void*)haddr, span)) {
          qasan_cpu = ENV_GET_CPU(env);
          asan_giovese_report_and_crash(ACCESS_TYPE_LOAD, addr, span, PC_GET(env), BP_GET(env), SP_GET(env));
        }
#else
        __asan_loadN((void*)haddr, span);
#endif
        
        qasan_page_loadN(env, addr2, 4 - span, mmu_idx);
        return;
    }

    haddr = addr  entry->addend;
    
#ifdef ASAN_GIOVESE
    if (asan_giovese_load4((void*)haddr)) {
      qasan_cpu = ENV_GET_CPU(env);
      asan_giovese_report_and_crash(ACCESS_TYPE_LOAD, addr, 4, PC_GET(env), BP_GET(env), SP_GET(env));
    }
#else
    __asan_load4((void*)haddr);
#endif
}

void HELPER(qasan_load8)(CPUArchState *env, target_ulong addr, uint32_t idx)
{
    if (qasan_disabled) return;

    uintptr_t mmu_idx = idx;
    CPUTLBEntry *entry = tlb_entry(env, mmu_idx, addr);
    target_ulong tlb_addr = entry->addr_read;
    uintptr_t haddr;

    /* It is in the TLB, the check is after the real access */
    if (!tlb_hit(tlb_addr, addr)) return;

    /* Handle an IO access.  */
    if (unlikely(tlb_addr & ~TARGET_PAGE_MASK))
        return;

    /* Handle slow unaligned access (it spans two pages or IO).  */
    if (unlikely((addr & ~TARGET_PAGE_MASK)  8 - 1
                    >= TARGET_PAGE_SIZE)) {
        target_ulong addr1, addr2;

        addr1 = addr & ~(8 - 1);
        addr2 = addr1  8;
        
        size_t span = addr2 - addr;
        haddr = addr  entry->addend;
        
        // tlb already processed for first half
#ifdef ASAN_GIOVESE
        if (asan_giovese_loadN((void*)haddr, span)) {
          qasan_cpu = ENV_GET_CPU(env);
          asan_giovese_report_and_crash(ACCESS_TYPE_LOAD, addr, span, PC_GET(env), BP_GET(env), SP_GET(env));
        }
#else
        __asan_loadN((void*)haddr, span);
#endif
        
        qasan_page_loadN(env, addr2, 8 - span, mmu_idx);
        return;
    }

    haddr = addr  entry->addend;
    
#ifdef ASAN_GIOVESE
    if (asan_giovese_load8((void*)haddr)) {
      qasan_cpu = ENV_GET_CPU(env);
      asan_giovese_report_and_crash(ACCESS_TYPE_LOAD, addr, 8, PC_GET(env), BP_GET(env), SP_GET(env));
    }
#else
    __asan_load8((void*)haddr);
#endif
}

void HELPER(qasan_store1)(CPUArchState *env, target_ulong addr, uint32_t idx)
{
    if (qasan_disabled) return;
    
    uintptr_t mmu_idx = idx;
    CPUTLBEntry *entry = tlb_entry(env, mmu_idx, addr);
    target_ulong tlb_addr = entry->addr_read;
    uintptr_t haddr;

    /* It is in the TLB, the check is after the real access */
    if (!tlb_hit(tlb_addr, addr)) return;

    /* Handle an IO access.  */
    if (unlikely(tlb_addr & ~TARGET_PAGE_MASK))
        return;

    haddr = addr  entry->addend;
    
#ifdef ASAN_GIOVESE
    if (asan_giovese_store1((void*)haddr)) {
      qasan_cpu = ENV_GET_CPU(env);
      asan_giovese_report_and_crash(ACCESS_TYPE_STORE, addr, 1, PC_GET(env), BP_GET(env), SP_GET(env));
    }
#else
    __asan_store1((void*)haddr);
#endif
}

void HELPER(qasan_store2)(CPUArchState *env, target_ulong addr, uint32_t idx)
{
    if (qasan_disabled) return;
    
    uintptr_t mmu_idx = idx;
    CPUTLBEntry *entry = tlb_entry(env, mmu_idx, addr);
    target_ulong tlb_addr = entry->addr_read;
    uintptr_t haddr;

    /* It is in the TLB, the check is after the real access */
    if (!tlb_hit(tlb_addr, addr)) return;

    /* Handle an IO access.  */
    if (unlikely(tlb_addr & ~TARGET_PAGE_MASK))
        return;

    /* Handle slow unaligned access (it spans two pages or IO).  */
    if (unlikely((addr & ~TARGET_PAGE_MASK)  2 - 1
                    >= TARGET_PAGE_SIZE)) {
        target_ulong addr1, addr2;

        addr1 = addr & ~(2 - 1);
        addr2 = addr1  2;
        
        size_t span = addr2 - addr;
        haddr = addr  entry->addend;
        
        // tlb already processed for first half
#ifdef ASAN_GIOVESE
        if (asan_giovese_storeN((void*)haddr, span)) {
          qasan_cpu = ENV_GET_CPU(env);
          asan_giovese_report_and_crash(ACCESS_TYPE_STORE, addr, span, PC_GET(env), BP_GET(env), SP_GET(env));
        }
#else
        __asan_storeN((void*)haddr, span);
#endif
        
        qasan_page_storeN(env, addr2, 2 - span, mmu_idx);
        return;
    }

    haddr = addr  entry->addend;
    
#ifdef ASAN_GIOVESE
    if (asan_giovese_store2((void*)haddr)) {
      qasan_cpu = ENV_GET_CPU(env);
      asan_giovese_report_and_crash(ACCESS_TYPE_STORE, addr, 2, PC_GET(env), BP_GET(env), SP_GET(env));
    }
#else
    __asan_store2((void*)haddr);
#endif
}

void HELPER(qasan_store4)(CPUArchState *env, target_ulong addr, uint32_t idx)
{
    if (qasan_disabled) return;
    
    uintptr_t mmu_idx = idx;
    CPUTLBEntry *entry = tlb_entry(env, mmu_idx, addr);
    target_ulong tlb_addr = entry->addr_read;
    uintptr_t haddr;

    /* It is in the TLB, the check is after the real access */
    if (!tlb_hit(tlb_addr, addr)) return;

    /* Handle an IO access.  */
    if (unlikely(tlb_addr & ~TARGET_PAGE_MASK))
        return;

    /* Handle slow unaligned access (it spans two pages or IO).  */
    if (unlikely((addr & ~TARGET_PAGE_MASK)  4 - 1
                    >= TARGET_PAGE_SIZE)) {
        target_ulong addr1, addr2;

        addr1 = addr & ~(4 - 1);
        addr2 = addr1  4;
        
        size_t span = addr2 - addr;
        haddr = addr  entry->addend;
        
        // tlb already processed for first half
#ifdef ASAN_GIOVESE
        if (asan_giovese_storeN((void*)haddr, span)) {
          qasan_cpu = ENV_GET_CPU(env);
          asan_giovese_report_and_crash(ACCESS_TYPE_STORE, addr, span, PC_GET(env), BP_GET(env), SP_GET(env));
        }
#else
        __asan_storeN((void*)haddr, span);
#endif
        
        qasan_page_storeN(env, addr2, 4 - span, mmu_idx);
        return;
    }

    haddr = addr  entry->addend;
    
#ifdef ASAN_GIOVESE
    if (asan_giovese_store4((void*)haddr)) {
      qasan_cpu = ENV_GET_CPU(env);
      asan_giovese_report_and_crash(ACCESS_TYPE_STORE, addr, 4, PC_GET(env), BP_GET(env), SP_GET(env));
    }
#else
    __asan_store4((void*)haddr);
#endif
}

void HELPER(qasan_store8)(CPUArchState *env, target_ulong addr, uint32_t idx)
{
    if (qasan_disabled) return;
    
    uintptr_t mmu_idx = idx;
    CPUTLBEntry *entry = tlb_entry(env, mmu_idx, addr);
    target_ulong tlb_addr = entry->addr_read;
    uintptr_t haddr;

    /* It is in the TLB, the check is after the real access */
    if (!tlb_hit(tlb_addr, addr)) return;

    /* Handle an IO access.  */
    if (unlikely(tlb_addr & ~TARGET_PAGE_MASK))
        return;

    /* Handle slow unaligned access (it spans two pages or IO).  */
    if (unlikely((addr & ~TARGET_PAGE_MASK)  8 - 1
                    >= TARGET_PAGE_SIZE)) {
        target_ulong addr1, addr2;

        addr1 = addr & ~(8 - 1);
        addr2 = addr1  8;
        
        size_t span = addr2 - addr;
        haddr = addr  entry->addend;
        
        // tlb already processed for first half
#ifdef ASAN_GIOVESE
        if (asan_giovese_storeN((void*)haddr, span)) {
          qasan_cpu = ENV_GET_CPU(env);
          asan_giovese_report_and_crash(ACCESS_TYPE_STORE, addr, span, PC_GET(env), BP_GET(env), SP_GET(env));
        }
#else
        __asan_storeN((void*)haddr, span);
#endif
        
        qasan_page_storeN(env, addr2, 8 - span, mmu_idx);
        return;
    }

    haddr = addr  entry->addend;
    
#ifdef ASAN_GIOVESE
    if (asan_giovese_store8((void*)haddr)) {
      qasan_cpu = ENV_GET_CPU(env);
      asan_giovese_report_and_crash(ACCESS_TYPE_STORE, addr, 8, PC_GET(env), BP_GET(env), SP_GET(env));
    }
#else
    __asan_store8((void*)haddr);
#endif
}

#else

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

void HELPER(qasan_load2)(CPUArchState *env, target_ulong addr) {

  if (qasan_disabled) return;

  void* ptr = (void*)g2h(addr);

#ifdef ASAN_GIOVESE
  if (asan_giovese_load2(ptr)) {
    asan_giovese_report_and_crash(ACCESS_TYPE_LOAD, addr, 2, PC_GET(env), BP_GET(env), SP_GET(env));
  }
#else
  __asan_load2(ptr);
#endif

}

void HELPER(qasan_load4)(CPUArchState *env, target_ulong addr) {

  if (qasan_disabled) return;
  
  void* ptr = (void*)g2h(addr);

#ifdef ASAN_GIOVESE
  if (asan_giovese_load4(ptr)) {
    asan_giovese_report_and_crash(ACCESS_TYPE_LOAD, addr, 4, PC_GET(env), BP_GET(env), SP_GET(env));
  }
#else
  __asan_load4(ptr);
#endif

}

void HELPER(qasan_load8)(CPUArchState *env, target_ulong addr) {

  if (qasan_disabled) return;
  
  void* ptr = (void*)g2h(addr);

#ifdef ASAN_GIOVESE
  if (asan_giovese_load8(ptr)) {
    asan_giovese_report_and_crash(ACCESS_TYPE_LOAD, addr, 8, PC_GET(env), BP_GET(env), SP_GET(env));
  }
#else
  __asan_load8(ptr);
#endif

}

void HELPER(qasan_store1)(CPUArchState *env, target_ulong addr) {

  if (qasan_disabled) return;
  
  void* ptr = (void*)g2h(addr);

#ifdef ASAN_GIOVESE
  if (asan_giovese_store1(ptr)) {
    asan_giovese_report_and_crash(ACCESS_TYPE_STORE, addr, 1, PC_GET(env), BP_GET(env), SP_GET(env));
  }
#else
  __asan_store1(ptr);
#endif

}

void HELPER(qasan_store2)(CPUArchState *env, target_ulong addr) {

  if (qasan_disabled) return;
  
  void* ptr = (void*)g2h(addr);
  
#ifdef ASAN_GIOVESE
  if (asan_giovese_store2(ptr)) {
    asan_giovese_report_and_crash(ACCESS_TYPE_STORE, addr, 2, PC_GET(env), BP_GET(env), SP_GET(env));
  }
#else
  __asan_store2(ptr);
#endif

}

void HELPER(qasan_store4)(CPUArchState *env, target_ulong addr) {

  if (qasan_disabled) return;
  
  void* ptr = (void*)g2h(addr);

#ifdef ASAN_GIOVESE
  if (asan_giovese_store4(ptr)) {
    asan_giovese_report_and_crash(ACCESS_TYPE_STORE, addr, 4, PC_GET(env), BP_GET(env), SP_GET(env));
  }
#else
  __asan_store4(ptr);
#endif

}

void HELPER(qasan_store8)(CPUArchState *env, target_ulong addr) {

  if (qasan_disabled) return;

  void* ptr = (void*)g2h(addr);

#ifdef ASAN_GIOVESE
  if (asan_giovese_store8(ptr)) {
    asan_giovese_report_and_crash(ACCESS_TYPE_STORE, addr, 8, PC_GET(env), BP_GET(env), SP_GET(env));
  }
#else
  __asan_store8(ptr);
#endif

}

#endif