# Detour

On Linux, the traditional divide between statically and dynamically linked executables can feel like a hard wall. Either you bundle *everything* into your binary, or you accept full dependency on the system's libc and dynamic linker. But Detour, a tiny static library, blows a hole clean through that wall.

Detour lets you build statically linked executables, with no dependency on glibc
or musl while still giving you access to dynamic linking at runtime. You can
`dlopen` libraries, resolve symbols, and even mix multiple C runtimes in the
same process, all without ever linking against libc directly.

## What Is Detour?

At its core, Detour is a minimal bootstrap layer that gives your application access to the system dynamic linker `ld-linux.so` without requiring libc at all. It allows:

- Dynamically loading libraries without linking libc
- Capturing `libdl` functionality (e.g., `dlopen`, `dlsym`) inside a fully static executable
- Mixing different libcs in one process
- Creating freestanding, zero-libc ELF executables

All while remaining entirely under your control, with no extra dependencies or runtime overhead.

> **Note:** Detour is not limited to freestanding or static use. You can also use it in dynamically linked applications that use an alternative libc such as musl. Detour works in both static and dynamic contexts.

> **Note:** Detour only works with **x86_64** Linux currently. Other architectures can be supported but will require writing assembly for system calls, setjmp/longjmp, and the indirect jump into the ELF entry point. See [loader.c](loader.c).

## Why Static Linking Alone Is Not Enough

While fully static linking may sound appealing, it comes with major tradeoffs. When you bundle everything into your binary, you lose access to essential system components that rely on dynamic linking. This includes things like:

- GPU drivers (e.g., OpenGL, Vulkan ICDs)
- Window systems (X11, Wayland)
- Audio subsystems
- Input libraries
- PAM modules and NSS services
- Almost any plugin-based runtime

These components expect a working dynamic linker environment. If you statically link a libc, you cannot also have a dynamic linker in the same process. That means `dlopen` and `dlsym` will not work, and neither will anything that depends on them.

Detour solves this by letting you statically link your core application while still setting up a dynamic linker for runtime use.

## How It Works

To understand Detour, it helps to understand how dynamic executables work under the hood on Linux.

When you run a dynamically linked [ELF](https://en.wikipedia.org/wiki/Executable_and_Linkable_Format) binary, the kernel does not actually execute your binary. Instead, it reads the [ELF Program Header Table](https://en.wikipedia.org/wiki/Executable_and_Linkable_Format#Program_header) to find a segment of type `PT_INTERP`. This segment specifies the program interpreter to use, typically `/lib64/ld-linux-x86-64.so.2`. The kernel then executes *that* interpreter, passing it:

1. The full path to your executable
2. All command-line arguments
3. Environment variables
4. Auxiliary vectors

From there, the dynamic linker takes over. It maps your executable into memory,
resolves shared library dependencies, performs relocations, sets up [TLS](https://en.wikipedia.org/wiki/Thread-local_storage), runs
constructors, and finally jumps to libc's initialization which then jumps to
your binary's `main` function. In effect, the dynamic
linker is the real program, and your application is just a payload it sets up
and transfers control to after initializing everything.

**Detour leverages this system by pretending to be the OS.**

It works like this:

1. We provide a tiny stub ELF executable that *is* dynamically linked against the system dynamic linker.
2. Your actual program (which Detour bootstraps) loads this stub ELF using a minimal ELF loader.
3. Detour reads the stub executable's `PT_INTERP` segment and loads the specified dynamic linker, just like the kernel would.
4. Before jumping into the dynamic linker, Detour calls [`setjmp`](https://en.wikipedia.org/wiki/Setjmp.h) to capture its current state.
5. It then jumps into the dynamic linker, forwarding the stub ELF and original arguments as if it were the kernel.
6. The dynamic linker maps in and initializes the stub ELF, then calls its `main` function. That `main` receives a string argument containing a function pointer encoded as a hex string. It decodes the address, casts it to a function pointer, and calls it.
7. This function captures symbols like `dlopen`, `dlsym`, `dlclose`, `dlerror`, and then calls `longjmp` to return to the original application.
8. Now, back at your main program's entry point, you have full access to the dynamic linker without ever linking against libc.

It is a trampoline: a short, carefully orchestrated detour through the dynamic linker, giving you just enough of its guts to carry on without ever depending on it directly.

## About the Tiny Stub

The helper ELF stub used in the first step is extremely small. It's about 35
lines of C. It is dynamically linked, but uses `__asm__(".symver")` to
explicitly pin any symbols it calls to the earliest possible version of glibc
that introduced the dynamic linker (around 2002). This ensures maximum forward
compatibility with any glibc-based Linux system in the wild today. Don't believe
me? [Look at the code](linker.c)

You can ship this stub alongside your application, compile it at runtime on the
user's system, or even embed it directly into your binary and extract it to a
temporary file at startup. Its only job is to get the dynamic linker to call a
known function pointer. Nothing more.

## Included Demo

Included is a demo that uses Detour to render a flashing colored window using SDL2 and OpenGL. The demo is a fully freestanding static executable that dynamically loads the system's `libc`, `libm`, `libSDL2`, and `libGL` at runtime.

It is compiled with:

```sh
-static -nostartfiles -nodefaultlibs -nostdlib -e detour_start
```

> **Note:** When using Detour in a freestanding way (such as this demo), the ELF entry point must be `detour_start`.

Despite being entirely statically linked, the executable dynamically loads
everything it needs at runtime. This includes: graphics drivers, windowing system libraries,
and more without ever linking against glibc or any dynamic libraries at build
time. Provided the system has a `libSDL2.so` this will work on any Linux install
from 2002 onwards!

## Why Use It?

- Create libc-free executables that still load plugins or shared libraries
- Avoid [dependency hell](https://en.wikipedia.org/wiki/Dependency_hell) when shipping portable tools across Linux distributions
- Experiment with new runtimes that bootstrap their own environment
- Mix musl and glibc in the same process for advanced compatibility or sandboxing
- Access graphics drivers, window systems, and hardware-accelerated APIs without linking glibc
- Maintain compatibility with system components that require a functioning `PT_INTERP` chain

## Final Thoughts

Detour does not hide how Linux works, it uses how Linux works. By repurposing the exact same mechanism the OS uses to launch dynamic binaries, it gives static executables a back door into the dynamic linker.

Whether you are building minimal tooling, crafting portable binaries, or writing
your own runtime, Detour gives you surgical control over how and when the
dynamic linker shows up.
