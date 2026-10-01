/* Freestanding Linux launcher for one fixed isolated Python script. */

#if !defined(__linux__) || (!defined(__x86_64__) && !defined(__aarch64__))
#error "the Grok freestanding launcher requires x86_64 or AArch64 Linux"
#endif

#ifndef GROK_LAUNCHER_SCRIPT
#error "GROK_LAUNCHER_SCRIPT must be a fixed absolute string literal"
#endif

#ifndef GROK_LAUNCHER_FORWARD_ARGS
#error "GROK_LAUNCHER_FORWARD_ARGS must be exactly 0 or 1"
#endif

#if GROK_LAUNCHER_FORWARD_ARGS != 0 && GROK_LAUNCHER_FORWARD_ARGS != 1
#error "GROK_LAUNCHER_FORWARD_ARGS must be exactly 0 or 1"
#endif

#if defined(__x86_64__)
#define SYS_WRITE 1L
#define SYS_EXECVE 59L
#define SYS_EXIT_GROUP 231L
#else
#define SYS_WRITE 64L
#define SYS_EXECVE 221L
#define SYS_EXIT_GROUP 94L
#endif
#ifdef GROK_LAUNCHER_TEST_CLOSE_RANGE_SYSCALL
#define SYS_CLOSE_RANGE GROK_LAUNCHER_TEST_CLOSE_RANGE_SYSCALL
#else
#define SYS_CLOSE_RANGE 436L
#endif
#define MAX_FORWARDED_ARGUMENTS 64UL

typedef unsigned long grok_size_t;

static char python_path[] = "/usr/bin/python3";
static char isolated_option[] = "-I";
static char no_bytecode_option[] = "-B";
static char no_site_option[] = "-S";
static char script_path[] = GROK_LAUNCHER_SCRIPT;
static char path_environment[] = "PATH=/usr/bin:/bin";
static char lang_environment[] = "LANG=C";
static char locale_environment[] = "LC_ALL=C";
static char bytecode_environment[] = "PYTHONDONTWRITEBYTECODE=1";
static char failure_message[] = "grok-python-launcher: EXEC\n";
#if GROK_LAUNCHER_FORWARD_ARGS == 1
__attribute__((used))
static char launcher_contract[] =
    "grok-static-python-launcher-v1:forward-bounded-64";
#else
__attribute__((used))
static char launcher_contract[] =
    "grok-static-python-launcher-v1:zero-arguments";
#endif

static char *fixed_environment[] = {
    path_environment,
    lang_environment,
    locale_environment,
    bytecode_environment,
    (char *)0,
};

static inline long raw_syscall1(long number, long argument_one) {
#if defined(__x86_64__)
    register long result __asm__("rax") = number;
    register long first __asm__("rdi") = argument_one;
    __asm__ volatile(
        "syscall"
        : "+a"(result)
        : "D"(first)
        : "rcx", "r11", "memory"
    );
    return result;
#else
    register long result __asm__("x0") = argument_one;
    register long system_call __asm__("x8") = number;
    __asm__ volatile(
        "svc 0"
        : "+r"(result)
        : "r"(system_call)
        : "cc", "memory"
    );
    return result;
#endif
}

static inline long raw_syscall3(
    long number, long argument_one, long argument_two, long argument_three
) {
#if defined(__x86_64__)
    register long result __asm__("rax") = number;
    register long first __asm__("rdi") = argument_one;
    register long second __asm__("rsi") = argument_two;
    register long third __asm__("rdx") = argument_three;
    __asm__ volatile(
        "syscall"
        : "+a"(result)
        : "D"(first), "S"(second), "d"(third)
        : "rcx", "r11", "memory"
    );
    return result;
#else
    register long result __asm__("x0") = argument_one;
    register long second __asm__("x1") = argument_two;
    register long third __asm__("x2") = argument_three;
    register long system_call __asm__("x8") = number;
    __asm__ volatile(
        "svc 0"
        : "+r"(result)
        : "r"(second), "r"(third), "r"(system_call)
        : "cc", "memory"
    );
    return result;
#endif
}

__attribute__((noreturn, used, visibility("hidden")))
void grok_launcher_start(grok_size_t *initial_stack) {
    char *arguments[MAX_FORWARDED_ARGUMENTS + 6UL];
    grok_size_t forwarded_count = 0UL;
    grok_size_t index;

#if GROK_LAUNCHER_FORWARD_ARGS == 1
    grok_size_t argument_count = initial_stack[0];
    if (argument_count == 0UL || argument_count > MAX_FORWARDED_ARGUMENTS + 1UL) {
        goto fail;
    }
    forwarded_count = argument_count - 1UL;
#else
    (void)initial_stack;
#endif

    arguments[0] = python_path;
    arguments[1] = isolated_option;
    arguments[2] = no_bytecode_option;
    arguments[3] = no_site_option;
    arguments[4] = script_path;
#if GROK_LAUNCHER_FORWARD_ARGS == 1
    for (index = 0UL; index < forwarded_count; ++index) {
        arguments[5UL + index] = (char *)initial_stack[2UL + index];
    }
#else
    (void)index;
#endif
    arguments[5UL + forwarded_count] = (char *)0;

    /* No inherited descriptor is an input or authority for the Python child. */
    if (raw_syscall3(SYS_CLOSE_RANGE, 3L, 0xffffffffL, 0L) != 0L) {
        goto fail;
    }
    (void)raw_syscall3(
        SYS_EXECVE,
        (long)python_path,
        (long)arguments,
        (long)fixed_environment
    );

fail:
    (void)raw_syscall3(
        SYS_WRITE,
        2L,
        (long)failure_message,
        (long)(sizeof(failure_message) - 1UL)
    );
    (void)raw_syscall1(SYS_EXIT_GROUP, 126L);
    for (;;) {
#if defined(__x86_64__)
        __asm__ volatile("hlt");
#else
        __asm__ volatile("hlt #0");
#endif
    }
}

#if defined(__x86_64__)
__asm__(
    ".global _start\n"
    ".type _start,@function\n"
    "_start:\n"
    "mov %rsp,%rdi\n"
    "andq $-16,%rsp\n"
    "call grok_launcher_start\n"
    ".size _start,.-_start\n"
    ".section .note.GNU-stack,\"\",@progbits\n"
    ".text\n"
);
#else
__asm__(
    ".global _start\n"
    ".type _start,%function\n"
    "_start:\n"
    "mov x0,sp\n"
    "bl grok_launcher_start\n"
    ".size _start,.-_start\n"
    ".section .note.GNU-stack,\"\",%progbits\n"
    ".text\n"
);
#endif
