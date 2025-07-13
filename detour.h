#ifndef DETOUR_H
#define DETOUR_H

typedef struct DTLinker DTLinker;

struct DTLinker {
	void *(*dlopen)(const char *filename, int flags);
	void *(*dlsym)(void *handle, const char *symbol);
	int (*dlclose)(void *handle);
	char *(*dlerror)(void);
};

const DTLinker* detour_init(char **argv);

#endif // DETOUR_H