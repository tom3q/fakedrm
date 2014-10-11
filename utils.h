/*
 * Userspace DRM emulation library - common helpers
 *
 * Copyright 2014 Tomasz Figa <tomasz.figa@gmail.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice (including the next
 * paragraph) shall be included in all copies or substantial portions of the
 * Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * PRECISION INSIGHT AND/OR ITS SUPPLIERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#ifndef _UTILS_H_
#define _UTILS_H_

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>

#define U642VOID(x)		((void *)(unsigned long)(x))
#define VOID2U64(x)		((uint64_t)(unsigned long)(x))

#define ARRAY_SIZE(x)		(sizeof(x) / sizeof((x)[0]))

#define PUBLIC			__attribute__((__visibility__("default")))
#define CONSTRUCTOR		__attribute__((constructor))
#define DESTRUCTOR		__attribute__((destructor))

#define DEBUG
//#define DEBUG_REFCNT
//#define DEBUG_VERBOSE

#ifdef DEBUG
#define DEBUG_MSG(fmt, ...) \
	do { fprintf(stderr, "[D] (%d) "fmt " (%s:%d)\n", \
		getpid(), ##__VA_ARGS__, __FUNCTION__, __LINE__); } while (0)
#else
#define DEBUG_MSG(fmt, ...) \
	if (0) { fprintf(stderr, "[D] (%d) "fmt " (%s:%d)\n", \
		getpid(), ##__VA_ARGS__, __FUNCTION__, __LINE__); }
#endif

#ifdef DEBUG_VERBOSE
#define VERBOSE_MSG(fmt, ...) \
	do { fprintf(stderr, "[V] (%d) "fmt " (%s:%d)\n", \
		getpid(), ##__VA_ARGS__, __FUNCTION__, __LINE__); } while (0)
#else
#define VERBOSE_MSG(fmt, ...) \
	if (0) { fprintf(stderr, "[V] (%d) "fmt " (%s:%d)\n", \
		getpid(), ##__VA_ARGS__, __FUNCTION__, __LINE__); }
#endif

#define ERROR_MSG(fmt, ...) \
	do { fprintf(stderr, "[E] (%d) "fmt " (%s:%d)\n", \
		getpid(), ##__VA_ARGS__, __FUNCTION__, __LINE__); } while (0)

struct stat;

struct locked_hash_table {
	pthread_rwlock_t lock;
	void *table;
};

typedef void (*hash_callback_t)(void *);

void hash_insert(struct locked_hash_table *table,
		 unsigned long key, void *value);
void *hash_lookup_callback(struct locked_hash_table *table,
			   unsigned long key, hash_callback_t func);
void hash_remove(struct locked_hash_table *table, unsigned long key);
void hash_create(struct locked_hash_table *table);
void hash_destroy(struct locked_hash_table *table);

static inline void *hash_lookup(struct locked_hash_table *table,
				unsigned long key)
{
	return hash_lookup_callback(table, key, NULL);
}

extern int (*open_real)(const char *, int, ...);
extern int (*close_real)(int);
extern int (*ioctl_real)(int, unsigned long, ...);
extern void *(*mmap_real)(void *, size_t, int, int, int, off_t);
extern int (*munmap_real)(void *, size_t);
extern int (*__fxstat_real)(int, int, struct stat *);
extern int (*__xstat_real)(int, const char *, struct stat *);

extern volatile sig_atomic_t cleanup_in_progress;
extern sigset_t captured_signals;

#endif
