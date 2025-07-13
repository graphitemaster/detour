#include <dlfcn.h>
#include "detour.h"
// These are versioned for GLIBC 2002!
__asm__(".symver dlopen,dlopen@GLIBC_2.2.5");
__asm__(".symver dlerror,dlerror@GLIBC_2.2.5");
__asm__(".symver dlsym,dlsym@GLIBC_2.2.5");
__asm__(".symver dlclose,dlclose@GLIBC_2.2.5");
__asm__(".symver __libc_start_main,__libc_start_main@GLIBC_2.2.5");
void _ITM_registerTMCloneTable(void) {}
void _ITM_deregisterTMCloneTable(void) {}
void __gmon_start__(void) {}
__attribute__((visibility("hidden"))) void __cxa_finalize(void) {}
static unsigned long hexstrtoul(const char *s) {
	unsigned long result = 0;
	for (int c; (c = *s++); /**/) {
		if (c >= '0' && c <= '9') {
			c -= '0';
		} else {
			c &= ~0x20;
			c -= 'A' - 0xa;
		}
		result = result << 4 | c;
	}
	return result;
}
int main(int argc, char **argv) {
	if (argc != 2) return 0;
	void (*jump)(DTLinker*) = (void*)hexstrtoul(argv[1]);
	DTLinker linker;
	linker.dlopen = dlopen;
	linker.dlsym = dlsym;
	linker.dlclose = dlclose;
	linker.dlerror = dlerror;
	jump(&linker);
}
