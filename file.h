/*
 * Userspace DRM emulation library - file management
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

#ifndef _FILE_H_
#define _FILE_H_

#include "utils.h"

struct fakedrm_file_desc {
	int fd;
	unsigned int refcnt;
	unsigned int g2d_pipes;
	unsigned int g3d_pipes;
	struct locked_hash_table bo_table;
	/* More to come */
};

void __file_get(struct fakedrm_file_desc *file);
void __file_put(struct fakedrm_file_desc *file);

#ifdef DEBUG_REFCNT
static void __file_get_debug(struct fakedrm_file_desc *file,
			   const char *func, int line)
{
	DEBUG_MSG("file_get(%p) from %s():%d", file, func, line);
	__file_get(file);
}
#define file_get(file)		__file_get_debug(file, __func__, __LINE__)

static void __file_put_debug(struct fakedrm_file_desc *file,
			   const char *func, int line)
{
	DEBUG_MSG("file_put(%p) from %s():%d", file, func, line);
	__file_put(file);
}
#define file_put(file)		__file_put_debug(file, __func__, __LINE__)
#else
#define file_get		__file_get
#define file_put		__file_put
#endif

int file_open(const char *pathname, int flags, mode_t mode);
int file_dup(struct fakedrm_file_desc *file, int fd);
void file_close(struct fakedrm_file_desc *file);
int file_ioctl(struct fakedrm_file_desc *file, unsigned long request,
	       void *arg);
void *file_mmap(struct fakedrm_file_desc *file, void *addr, size_t length,
		int prot, int flags, off_t offset);
int file_fstat(struct fakedrm_file_desc *file, int ver, struct stat *buf);

struct fakedrm_file_desc *file_lookup(int fd);

void file_init(void);
void file_cleanup(void);

int vt_ioctl(unsigned long request, void *arg);

/*
 * "Driver" model
 */

struct fakedrm_file_desc;

struct fakedrm_driver {
	const char *name;
	const char *date;
	const char *desc;

	int version_major;
	int version_minor;
	int version_patchlevel;

	int (*ioctl)(struct fakedrm_file_desc *, unsigned long, void *);
};

extern struct fakedrm_driver exynos_driver;
extern struct fakedrm_driver msm_driver;

#endif
