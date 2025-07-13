#include <elf.h>          // Elf64_{Ehdr,Phdr,auxv_t}
#include <fcntl.h>        // O_{RDONLY,CLOEXEC}
#include <sys/mman.h>     // MAP_{FIXED,PRIVATE,ANONYMOUS}, PROT_{NONE,READ,WRITE,EXEC}
#include <sys/syscall.h>  // SYS_*

#include "detour.h"

typedef unsigned char Uint8;
typedef unsigned long Uint64;
typedef signed long Sint64;
typedef signed long Off64;

typedef Elf64_Ehdr Elf_Ehdr;
typedef Elf64_Phdr Elf_Phdr;
typedef Elf64_auxv_t Elf_auxv_t;

#define min(x, y) ((x) < (y) ? (x) : (y))
#define max(x, y) ((x) > (y) ? (x) : (y))

static inline Uint64 detour_syscall1(Uint64 n, Uint64 a0) {
	Uint64 result;
	__asm__ __volatile__("syscall" : "=a"(result) : "a"(n), "D"(a0) : "rcx", "r11", "memory");
	return result;
}
static inline Uint64 detour_syscall2(Uint64 n, Uint64 a0, Uint64 a1) {
	Uint64 result;
	__asm__ __volatile__("syscall" : "=a"(result) : "a"(n), "D"(a0), "S"(a1) : "rcx", "r11", "memory");
	return result;
}
static inline Uint64 detour_syscall3(Uint64 n, Uint64 a0, Uint64 a1, Uint64 a2) {
	Uint64 result;
	__asm__ __volatile__("syscall" : "=a"(result) : "a"(n), "D"(a0), "S"(a1), "d"(a2): "rcx", "r11", "memory");
	return result;
}
static inline Uint64 detour_syscall4(Uint64 n, Uint64 a0, Uint64 a1, Uint64 a2, Uint64 a3) {
	Uint64 result;
	register Uint64 r10 __asm__("r10") = a3;
	__asm__ __volatile__("syscall" : "=a"(result) : "a"(n), "D"(a0), "S"(a1), "d"(a2), "r"(r10) : "rcx", "r11", "memory");
	return result;
}
static inline Uint64 detour_syscall6(Uint64 n, Uint64 a0, Uint64 a1, Uint64 a2, Uint64 a3, Uint64 a4, Uint64 a5) {
	Uint64 result;
	register Uint64 r10 __asm__("r10") = a3;
	register Uint64 r8  __asm__("r8") = a4;
	register Uint64 r9  __asm__("r9") = a5;
	__asm__ __volatile__("syscall" : "=a"(result) : "a"(n), "D"(a0), "S"(a1), "d"(a2), "r"(r10), "r"(r8), "r"(r9) : "rcx", "r11", "memory");
	return result;
}

static inline int detour_open(const char* filename, int flags) {
	return (int)detour_syscall2(SYS_open, (Uint64)filename, (Uint64)flags);
}
static inline int detour_close(int fd) {
	return (int)detour_syscall1(SYS_close, (Uint64)fd);
}
static inline Sint64 detour_pread(int fd, void* buf, size_t count, Off64 offset) {
	return (Sint64)detour_syscall4(SYS_pread64, (Uint64)fd, (Uint64)buf, (Uint64)count, (Uint64)offset);
}
static inline int detour_exit(int status) {
	return (int)detour_syscall1(SYS_exit, (Uint64)(status));
}
static inline int detour_munmap(void* addr, size_t length) {
	return (int)detour_syscall2(SYS_munmap, (Uint64)addr, (Uint64)length);
}
static inline int detour_mprotect(void* addr, size_t length, int prot) {
	return (int)detour_syscall3(SYS_mprotect, (Uint64)addr, (Uint64)length, (Uint64)prot);
}
static inline void* detour_mmap(void *addr, size_t length, int prot, int flags, int fd, Off64 offset) {
	return (void *)detour_syscall6(SYS_mmap, (Uint64)addr, (Uint64)length, (Uint64)prot, (Uint64)flags, (Uint64)fd, (Uint64)offset);
}

__attribute__((__returns_twice__, __naked__)) static int detour_setjmp(void*) {
	__asm__ __volatile__ (
		"movq %rbx,(%rdi)\n\t"
		"movq %rbp,8(%rdi)\n\t"
		"movq %r12,16(%rdi)\n\t"
		"movq %r13,24(%rdi)\n\t"
		"movq %r14,32(%rdi)\n\t"
		"movq %r15,40(%rdi)\n\t"
		"leaq 8(%rsp),%rdx\n\t"
		"movq %rdx,48(%rdi)\n\t"
		"movq (%rsp),%rdx\n\t"
		"movq %rdx,56(%rdi)\n\t"
		"xorl %eax,%eax\n\t"
		"ret");
	__builtin_unreachable();
}

__attribute__((__naked__, __noreturn__)) static void detour_longjmp(void*, int) {
	__asm__ __volatile__(
		"xorl %eax,%eax\n\t"
		"cmpl $1,%esi\n\t"
		"adcl %esi,%eax\n\t"
		"movq (%rdi),%rbx\n\t"
		"movq 8(%rdi),%rbp\n\t"
		"movq 16(%rdi),%r12\n\t"
		"movq 24(%rdi),%r13\n\t"
		"movq 32(%rdi),%r14\n\t"
		"movq 40(%rdi),%r15\n\t"
		"movq 48(%rdi),%rsp\n\t"
		"jmpq *56(%rdi)\n\t");
	__builtin_unreachable();
}

// The true entrypoint when freestanding
static void detour_main(Uint64 *sp);
__attribute__((__naked__, __noreturn__)) void detour_start() {
	__asm__ __volatile__(
		"movq %%rsp, %%rdi\n\t"
		"movq %%rdx, %%rsi\n\t"
		"callq *%0\n\t"
		:
		: "r"(detour_main)
		: "rdi", "rsi");
	__builtin_unreachable();
}

static inline void* detour_memcpy(void* dst, const void *src, size_t n) {
	const Uint8 *p = src, *e = p + n;
	for (Uint8 *d = dst; p < e; *d++ = *p++);
	return dst;
}

static struct {
	DTLinker linker;
	Uint8    jmp[64];
	Uint8    addr[17];
	Uint64*  sp;
} detour_state;

#define PAGE_SIZE 4096
#define ALIGN (PAGE_SIZE - 1)
#define ROUND_PAGE(x) (((x) + (ALIGN)) & ~(ALIGN))
#define TRUNC_PAGE(x) ((x) & ~(ALIGN))

typedef struct {
	int      fd;
	Elf_Ehdr ehdr;
	Uint64   base;
	Uint64   size;
	Uint64   entry;
} DetourELF;

static int detour_elf_valid(const Elf_Ehdr* ehdr) {
	const Uint8 *const e_ident = ehdr->e_ident;
	return e_ident[EI_MAG0] == ELFMAG0
	    && e_ident[EI_MAG1] == ELFMAG1
	    && e_ident[EI_MAG2] == ELFMAG2
	    && e_ident[EI_MAG3] == ELFMAG3
	    && e_ident[EI_CLASS] == ELFCLASS64
	    && e_ident[EI_VERSION] <= EV_CURRENT
	    && (ehdr->e_type == ET_EXEC || ehdr->e_type == ET_DYN);
}

static int detour_elf_load(DetourELF* elf, Elf_Ehdr *ehdr, Elf_Phdr *phdr) {
	Uint64 min_va = (Uint64)-1;
	Uint64 max_va = 0;
	for (const Elf_Phdr* i = phdr; i < &phdr[ehdr->e_phnum]; i++) {
		if (i->p_type != PT_LOAD) continue;
		min_va = min(min_va, i->p_vaddr);
		max_va = max(max_va, i->p_vaddr + i->p_memsz);
	}
	min_va = TRUNC_PAGE(min_va);
	max_va = ROUND_PAGE(max_va);
	const Uint64 va = max_va - min_va;
	const int dyn = ehdr->e_type == ET_DYN;
	Uint8 *const hint = dyn ? 0 : (Uint8 *)min_va;
	int flags = MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE;
	if (!dyn) flags |= MAP_FIXED;
	Uint8 *const base = detour_mmap(hint, va, PROT_NONE, flags, -1, 0);
	if (base == (void *)-1) return 0;
	detour_munmap(base, va);
	elf->base = (Uint64)base;
	elf->size = va;
	for (const Elf_Phdr* i = phdr; i < &phdr[ehdr->e_phnum]; i++) {
		if (i->p_type != PT_LOAD) continue;
		const Uint64 off = i->p_vaddr & ALIGN;
		const Uint64 beg = (dyn ? (Uint64)base : 0) + TRUNC_PAGE(i->p_vaddr);
		const Sint64 sz = ROUND_PAGE(i->p_memsz + off);
		Uint8 *const map = detour_mmap((void *)beg, sz, PROT_WRITE, MAP_FIXED | MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
		if (map == (void *)-1) goto L_error;
		if (detour_pread(elf->fd, map + off, i->p_filesz, i->p_offset) != (Sint64)i->p_filesz) goto L_error;
		int prot = 0;
		if (i->p_flags & PF_R) prot |= PROT_READ;
		if (i->p_flags & PF_W) prot |= PROT_WRITE;
		if (i->p_flags & PF_X) prot |= PROT_EXEC;
		detour_mprotect(map, sz, prot);
	}
	return 1;
L_error:
	detour_munmap(base, va);
	elf->base = 0;
	elf->size = 0;
	return 0;
}

static void detour_elf_close(DetourELF* const elf, int unmap) {
	if (unmap && elf->base) detour_munmap((void*)elf->base, elf->size);
	if (elf->fd != -1) detour_close(elf->fd);
}

static void detour_exec(const char *file, int argc, char **argv) {
	Uint64 *p = detour_state.sp;
	int envc = 0, auxc = 0;
	for (p++; *p != 0; p += 1);            // argv
	for (;    *p != 0; p += 1, envc += 1); // envp
	for (p++; *p != 0; p += 2, auxc += 2); // auxv
	// Should be large enough for argc + argv + envp + auxv.
	char b[65536 * 16];
	char **envp = 0;
	Uint64 *x = (Uint64*)b;
	*x++ = argc; // Write and skip 'argc'
	const size_t argn = argc * sizeof(char*);
	argv = (char**)detour_memcpy((char *)x, argv, argn);
	const size_t blkc = envc + 1 + auxc;      // Environment block is ENV + NUL + AUX
	const size_t blkn = blkc * sizeof(char*); // Block is all pointers
	envp = (char**)detour_memcpy((char *)x + argn, p - blkc, blkn);
	DetourELF elfs[2] = { { .fd = -1 }, { .fd = -1 } };
	char *interp = 0;
	for (int i = 0; /**/; i++) {
		DetourELF* elf = &elfs[i];
		Elf_Ehdr *const ehdr = &elf->ehdr;
		if ((elf->fd = detour_open(file, O_RDONLY | O_CLOEXEC)) < 0) goto L_error;
		if (detour_pread(elf->fd, ehdr, sizeof *ehdr, 0) != sizeof *ehdr) goto L_error;
		if (!detour_elf_valid(ehdr)) goto L_error;
		const Sint64 sz = ehdr->e_phnum * sizeof(Elf_Phdr);
		Elf_Phdr* phdr = __builtin_alloca(sz);
		if (detour_pread(elf->fd, phdr, sz, ehdr->e_phoff) != sz) goto L_error;
		if (!detour_elf_load(elf, ehdr, phdr)) goto L_error;
		elf->entry = ehdr->e_entry + (ehdr->e_type == ET_DYN ? elf->base : 0);
		if (file == interp) break;
		for (Elf_Phdr *p = phdr; p < &phdr[ehdr->e_phnum]; p++) {
			if (p->p_type != PT_INTERP) continue;
			interp = __builtin_alloca(p->p_filesz);
			if (detour_pread(elf->fd, interp, p->p_filesz, p->p_offset) != (Sint64)p->p_filesz) goto L_error;
			if (interp[p->p_filesz - 1] != '\0') goto L_error;
			file = interp;
		}
	}
	for (Elf_auxv_t *av = (Elf_auxv_t*)&envp[envc + 1]; av->a_type; av++) switch (av->a_type) {
	break; case AT_PHDR:   av->a_un.a_val = elfs[0].base + elfs[0].ehdr.e_phoff;
	break; case AT_PHENT:  av->a_un.a_val = elfs[0].ehdr.e_phentsize;
	break; case AT_PHNUM:  av->a_un.a_val = elfs[0].ehdr.e_phnum;
	break; case AT_PAGESZ: av->a_un.a_val = PAGE_SIZE;
	break; case AT_BASE:   av->a_un.a_val = interp ? elfs[1].base : av->a_un.a_val;
	break; case AT_FLAGS:  av->a_un.a_val = 0;
	break; case AT_ENTRY:  av->a_un.a_val = elfs[0].entry;
	break; case AT_EXECFN: av->a_un.a_val = (Uint64)argv[1];
	}
	for (int i = 0; i < 2; i++) detour_elf_close(&elfs[i], 0);
	__asm__ __volatile__(
		"mov %2,%%rsp\n\t"
		"jmpq *%1\n\t"
		:
		: "D"(0), "S"(interp ? elfs[1].entry : elfs[0].entry), "d"(x - 1), "b"(0)
		: "memory");
	__builtin_unreachable();
L_error:
	for (int i = 0; i < 2; i++) detour_elf_close(&elfs[i], 1);
}

static void detour_main(Uint64 *sp) {
	detour_state.sp = sp;
	const int argc = (int)*sp;
	char **const argv = (char **)(sp + 1);
	extern int main(int argc, char **, char**);
	detour_exit(main(argc, argv, &argv[argc + 1]));
}

static void detour_link(DTLinker *linker) {
	detour_state.linker = *linker;
	detour_longjmp(detour_state.jmp, 1);
}

static inline void detour_tohex(char* b, Uint64 ul) {
	char* p = b;
	do *p++ = "0123456789abcdef"[ul % 16]; while (ul /= 16);
	for (*p-- = 0; p > b; b++, p--) {
		int c = *p;
		*p = *b, *b = c;
	}
}

const DTLinker* detour_init(char **argv) {
	// When called from a dynamic linked executable.
	if (!detour_state.sp) detour_state.sp = (Uint64 *)argv - 1;
	char *eargv[2];
	eargv[0] = (char *)"linker";
	eargv[1] = (char *)detour_state.addr;
	detour_tohex(eargv[1], (Uint64)&detour_link);
	if (!detour_setjmp(detour_state.jmp)) detour_exec(eargv[0], 2, eargv);
	return &detour_state.linker;
}