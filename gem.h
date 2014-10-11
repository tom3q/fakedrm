/*
 * Userspace DRM emulation library - GEM support
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

#ifndef _GEM_H_
#define _GEM_H_

#include "utils.h"

struct fakedrm_file_desc;
struct fakedrm_bo_handle;

int dummy_gem_open(struct fakedrm_file_desc *file, void *arg);
int dummy_gem_close(struct fakedrm_file_desc *file, void *arg);
int dummy_gem_flink(struct fakedrm_file_desc *file, void *arg);

int bo_create(struct fakedrm_file_desc *file, uint32_t size,
	      uint32_t *out_handle);
int bo_map(struct fakedrm_file_desc *file, uint32_t handle, void **out_addr);
int bo_unmap(void *addr, size_t length);
int bo_map_offset(struct fakedrm_file_desc *file,
		  uint32_t handle, uint64_t *offset);
void __bo_handle_put(struct fakedrm_bo_handle *handle);

void bo_init(void);
void bo_cleanup(void);

#ifdef DEBUG_REFCNT
static void __bo_handle_get_debug(struct fakedrm_bo_handle *handle,
			   const char *func, int line)
{
	DEBUG_MSG("bo_handle_get(%p) from %s():%d", handle, func, line);
	__bo_handle_get(handle);
}
#define bo_handle_get(handle)	__bo_handle_get_debug(handle, __func__, __LINE__)

static void __bo_handle_put_debug(struct fakedrm_bo_handle *handle,
			   const char *func, int line)
{
	DEBUG_MSG("bo_handle_put(%p) from %s():%d", handle, func, line);
	__bo_handle_put(handle);
}
#define bo_handle_put(handle)	__bo_handle_put_debug(handle, __func__, __LINE__)
#else
#define bo_handle_get		__bo_handle_get
#define bo_handle_put		__bo_handle_put
#endif

#endif
