CFLAGS += -pipe -Wall -Wextra -fPIC -fno-stack-protector -fno-builtin -U_FORTIFY_SOURCE
CFLAGS += -Os -fno-asynchronous-unwind-tables -fno-unwind-tables -fvisibility=hidden
LDFLAGS += -static -nostartfiles -nodefaultlibs -nostdlib -e detour_start -s -Wl,--build-id=none
.PHONY: clean all
all: demo linker
demo: demo.o loader.o
linker: linker.c
	$(CC) -Os linker.c -o linker
clean:
	rm -f demo.o loader.o linker.o
	rm -f demo linker