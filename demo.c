#define RTLD_NOW 0x0002
#include "detour.h"
#include <dlfcn.h>

// Minimal SDL2 bindings
typedef unsigned int Uint32;
#define SDL_INIT_VIDEO   0x00000020u
#define SDL_INIT_EVENTS  0x00004000u
#define SDL_WINDOW_OPENGL 0x00000002
#define SDL_WINDOWPOS_CENTERED 0x2FFF0000u
#define SDL_QUIT 0x100
typedef struct SDL_Window SDL_Window;
typedef struct SDL_GLContext* SDL_GLContext;
typedef struct { Uint32 type; char data[1024]; } SDL_Event;
int (*SDL_Init)(Uint32 flags);
void (*SDL_Quit)(void);
SDL_Window *(*SDL_CreateWindow)(const char*, int, int, int, int, Uint32);
int (*SDL_DestroyWindow)(SDL_Window*);
int (*SDL_PollEvent)(SDL_Event*);
SDL_GLContext (*SDL_GL_CreateContext)(SDL_Window*);
void (*SDL_GL_DeleteContext)(SDL_GLContext);
void (*SDL_GL_SwapWindow)(SDL_Window*);
void *(*SDL_GL_GetProcAddress)(const char*);
int (*SDL_GL_SetSwapInterval)(int);

// Minimal OpenGL bindings
typedef unsigned int GLbitfield;
typedef float GLfloat;
#define GL_COLOR_BUFFER_BIT 0x00004000
void (*glClearColor)(GLfloat, GLfloat, GLfloat, GLfloat);
void (*glClear)(GLbitfield);

// libc
int (*printf)(const char *, ...);
// libm
float (*sinf)(float);

int main(int argc, char **argv) {
	argc--;
	const DTLinker *const linker = detour_init(argv);
	void *libc = linker->dlopen("libc.so.6", RTLD_NOW);
	void *libm = linker->dlopen("libm.so.6", RTLD_NOW);
	void *sdl2 = linker->dlopen("libSDL2.so", RTLD_NOW);

	// libc
	*(void **)&printf = linker->dlsym(libc, "printf");
	// libm
	*(void **)&sinf = linker->dlsym(libm, "sinf");
	// sdl2
	*(void **)&SDL_Init = linker->dlsym(sdl2, "SDL_Init");
	*(void **)&SDL_Quit = linker->dlsym(sdl2, "SDL_Quit");
	*(void **)&SDL_CreateWindow = linker->dlsym(sdl2, "SDL_CreateWindow");
	*(void **)&SDL_DestroyWindow = linker->dlsym(sdl2, "SDL_DestroyWindow");
	*(void **)&SDL_PollEvent = linker->dlsym(sdl2, "SDL_PollEvent");
	*(void **)&SDL_GL_CreateContext = linker->dlsym(sdl2, "SDL_GL_CreateContext");
	*(void **)&SDL_GL_DeleteContext = linker->dlsym(sdl2, "SDL_GL_DeleteContext");
	*(void **)&SDL_GL_SwapWindow = linker->dlsym(sdl2, "SDL_GL_SwapWindow");
	*(void **)&SDL_GL_GetProcAddress = linker->dlsym(sdl2, "SDL_GL_GetProcAddress");
	*(void **)&SDL_GL_SetSwapInterval = linker->dlsym(sdl2, "SDL_GL_SetSwapInterval");

	printf("libm.so is %p\n", libm);
	printf("libc.so is %p\n", libc);
	printf("libSDL2.so is %p\n", sdl2);

	SDL_Init(SDL_INIT_VIDEO | SDL_INIT_EVENTS);
	SDL_Window *window = SDL_CreateWindow(
		"Hello, world",
		SDL_WINDOWPOS_CENTERED,
		SDL_WINDOWPOS_CENTERED,
		1920,
		1080,
		SDL_WINDOW_OPENGL);
	SDL_GLContext context = SDL_GL_CreateContext(window);
	SDL_GL_SetSwapInterval(1); // VSync
	*(void **)&glClearColor = SDL_GL_GetProcAddress("glClearColor");
	*(void **)&glClear = SDL_GL_GetProcAddress("glClear");
	float t = 0.0;
	#define M_PI 3.14159265
	for (;;) {
		for (SDL_Event event; SDL_PollEvent(&event); /**/) {
			if (event.type == SDL_QUIT) {
				goto L_done;
			}
		}
		float r = 0.5f + 0.5f * sinf(t);
		float g = 0.5f + 0.5f * sinf(t + 2.0f * M_PI / 3.0f);
		float b = 0.5f + 0.5f * sinf(t + 4.0f * M_PI / 3.0f);
		glClearColor(r, g, b, 1.0f);
		glClear(GL_COLOR_BUFFER_BIT);
		SDL_GL_SwapWindow(window);
		t += 60.0f / 1000.0f; // Assume 60fps
	}
L_done:
	SDL_GL_DeleteContext(context);
	SDL_DestroyWindow(window);
	SDL_Quit();
	linker->dlclose(sdl2);
	linker->dlclose(libm);
}
