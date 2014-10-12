/*
 * Userspace DRM emulation library - library entry points
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

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <xf86drm.h>

#include "file.h"
#include "gem.h"
#include "utils.h"

#ifndef O_TMPFILE
#  define O_TMPFILE 0
#endif

volatile sig_atomic_t cleanup_in_progress;
sigset_t captured_signals;

/*
 * Pointers to originals of wrapped functions
 */

int (*open_real)(const char *, int, ...);
int (*close_real)(int);
int (*ioctl_real)(int, unsigned long, ...);
void *(*mmap_real)(void *, size_t, int, int, int, off_t);
int (*munmap_real)(void *, size_t);
int (*__fxstat_real)(int, int, struct stat *);
int (*__xstat_real)(int, const char *, struct stat *);

/*
 * Syscall wrappers which hook into operations on DRM devices
 */

PUBLIC int open(const char *pathname, int flags, ...)
{
	va_list args;
	mode_t mode = 0;

	if (flags & (O_CREAT | O_TMPFILE)) {
		va_start(args, flags);
		mode = va_arg(args, mode_t);
		va_end(args);
	}

	VERBOSE_MSG("%s(pathname = '%s', flags = %d, mode = %x)",
		__func__, pathname, flags, mode);

	if (!strcmp(pathname, "/dev/dri/card0"))
		return file_open(pathname, flags, mode);

	if (strstr(pathname, "/dev/tty") || strstr(pathname, "/dev/vc/"))
		return open_real("/dev/null", O_RDWR, 0);

	return open_real(pathname, flags, mode);
}

PUBLIC int close(int fd)
{
	struct fakedrm_file_desc *file;

	VERBOSE_MSG("%s(fd = %d)", __func__, fd);

	file = file_lookup(fd);
	if (file)
		file_close(file);

	return close_real(fd);
}

PUBLIC int ioctl(int d, unsigned long request, ...)
{
	struct fakedrm_file_desc *file;
	char *argp = NULL;
	va_list args;

	va_start(args, request);
	argp = va_arg(args, char *);
	va_end(args);

	VERBOSE_MSG("%s(d = %d, request = %lx, argp = %p)",
		__func__, d, request, argp);

	if (_IOC_TYPE(request) == 'V' || _IOC_TYPE(request) == 'K')
		return vt_ioctl(request, argp);

	if (_IOC_TYPE(request) == DRM_IOCTL_BASE) {
		file = file_lookup(d);
		if (file)
			return file_ioctl(file, request, argp);
	}

	return ioctl_real(d, request, argp);
}

PUBLIC void *mmap(void *addr, size_t length, int prot, int flags,
		  int fd, off_t offset)
{
	struct fakedrm_file_desc *file;

	VERBOSE_MSG("%s(addr = %p, length = %lx, prot = %d, flags = %d, fd = %d, offset = %lx)",
		__func__, addr, length, prot, flags, fd, offset);

	file = file_lookup(fd);
	if (file)
		return file_mmap(file, addr, length, prot, flags, offset);

	return mmap_real(addr, length, prot, flags, fd, offset);
}

PUBLIC int munmap(void *addr, size_t length)
{
	int ret;

	VERBOSE_MSG("%s(addr = %p, length = %lx)", __func__, addr, length);

	ret = bo_unmap(addr, length);
	if (ret == -ENOENT)
		ret = munmap_real(addr, length);

	return ret;
}

PUBLIC int __fxstat(int ver, int fd, struct stat *buf)
{
	struct fakedrm_file_desc *file;

	VERBOSE_MSG("%s(ver = %d, fd = %d, buf = %p)",
		__func__, ver, fd, buf);

	file = file_lookup(fd);
	if (file)
		return file_fstat(file, ver, buf);

	return __fxstat_real(ver, fd, buf);
}

PUBLIC int __xstat(int ver, const char *pathname, struct stat *buf)
{
	VERBOSE_MSG("%s(ver = %d, pathname = '%s', buf = %p)",
		__func__, ver, pathname, buf);

	if (strstr(pathname, "/dev/dri"))
		pathname = "/dev/null";
	return __xstat_real(ver, pathname, buf);
}

/*
 * Library initialization/cleanup
 */

static void *lookup_symbol(const char *name)
{
	void *symbol;
	const char *error;

	symbol = dlsym(RTLD_NEXT, name);
	if ((error = dlerror())) {
		ERROR_MSG("dlsym(%s) failed: %s", name, error);
		exit(1);
	}

	return symbol;
}

DESTRUCTOR static void destructor(void)
{
	DEBUG_MSG("cleaning up open handles...");

	file_cleanup();

	DEBUG_MSG("cleaning up open BO mappings...");

	bo_cleanup();
}

static void signal_handler(int sig)
{
	if (__sync_fetch_and_add(&cleanup_in_progress, 1))
		return;

	destructor();

	signal (sig, SIG_DFL);
	raise (sig);
}

CONSTRUCTOR static void constructor(void)
{
	open_real = lookup_symbol("open");
	close_real = lookup_symbol("close");
	ioctl_real = lookup_symbol("ioctl");
	mmap_real = lookup_symbol("mmap");
	munmap_real = lookup_symbol("munmap");
	__fxstat_real = lookup_symbol("__fxstat");
	__xstat_real = lookup_symbol("__xstat");

	file_init();
	bo_init();

	signal(SIGINT, signal_handler);
	signal(SIGSEGV, signal_handler);
	signal(SIGABRT, signal_handler);
	signal(SIGTRAP, signal_handler);
}
