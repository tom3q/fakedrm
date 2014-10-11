/*
 * Userspace DRM emulation library - Exynos DRM specifics
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

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <sys/types.h>
#include <unistd.h>

#include <xf86drm.h>

#include "exynos_drm.h"
#include "file.h"
#include "gem.h"

/*
 * Exynos-specific GEM IOCTLs
 */

#define CMD_IOCTL_DRM_EXYNOS_GEM_CREATE				\
	DRM_IOC(DRM_IOC_READ | DRM_IOC_WRITE, DRM_IOCTL_BASE,	\
		DRM_COMMAND_BASE + DRM_EXYNOS_GEM_CREATE,	\
		sizeof(struct drm_exynos_gem_create))
#define CMD_IOCTL_DRM_EXYNOS_GEM_MMAP				\
	DRM_IOC(DRM_IOC_READ | DRM_IOC_WRITE, DRM_IOCTL_BASE,	\
		DRM_COMMAND_BASE + DRM_EXYNOS_GEM_MMAP,	\
		sizeof(struct drm_exynos_gem_mmap))
#define CMD_IOCTL_DRM_EXYNOS_GEM_MAP_OFFSET			\
	DRM_IOC(DRM_IOC_READ | DRM_IOC_WRITE, DRM_IOCTL_BASE,	\
		DRM_COMMAND_BASE + DRM_EXYNOS_GEM_MAP_OFFSET,	\
		sizeof(struct drm_exynos_gem_map_off))

static int dummy_cmd_exynos_gem_create(struct fakedrm_file_desc *file,
				       void *arg)
{
	struct drm_exynos_gem_create *req = arg;

	return bo_create(file, req->size, &req->handle);
}

static int dummy_cmd_exynos_gem_mmap(struct fakedrm_file_desc *file, void *arg)
{
	struct drm_exynos_gem_mmap *req = arg;
	void *addr;
	int ret;

	ret = bo_map(file, req->handle, &addr);
	if (ret)
		return ret;

	req->mapped = VOID2U64(addr);
	return 0;
}

static int dummy_cmd_exynos_gem_map_offset(struct fakedrm_file_desc *file,
					   void *arg)
{
	struct drm_exynos_gem_map_off *req = arg;

	return bo_map_offset(file, req->handle, &req->offset);
}

/*
 * Exynos-specific pipe IOCTLs
 */

#define CMD_IOCTL_DRM_EXYNOS_G3D_CREATE_PIPE			\
	DRM_IOC(DRM_IOC_READ | DRM_IOC_WRITE, DRM_IOCTL_BASE,	\
		DRM_COMMAND_BASE + DRM_EXYNOS_G3D_CREATE_PIPE,	\
		sizeof(struct drm_exynos_g3d_pipe))
#define CMD_IOCTL_DRM_EXYNOS_G2D_CREATE_PIPE			\
	DRM_IOC(DRM_IOC_READ | DRM_IOC_WRITE, DRM_IOCTL_BASE,	\
		DRM_COMMAND_BASE + DRM_EXYNOS_G2D_CREATE_PIPE,	\
		sizeof(struct drm_exynos_g3d_pipe))
#define CMD_IOCTL_DRM_EXYNOS_G3D_DESTROY_PIPE			\
	DRM_IOC(DRM_IOC_READ | DRM_IOC_WRITE, DRM_IOCTL_BASE,	\
		DRM_COMMAND_BASE + DRM_EXYNOS_G3D_DESTROY_PIPE,	\
		sizeof(struct drm_exynos_g3d_pipe))
#define CMD_IOCTL_DRM_EXYNOS_G2D_DESTROY_PIPE			\
	DRM_IOC(DRM_IOC_READ | DRM_IOC_WRITE, DRM_IOCTL_BASE,	\
		DRM_COMMAND_BASE + DRM_EXYNOS_G2D_DESTROY_PIPE,	\
		sizeof(struct drm_exynos_g3d_pipe))
#define CMD_IOCTL_DRM_EXYNOS_G3D_SUBMIT			\
	DRM_IOC(DRM_IOC_READ | DRM_IOC_WRITE, DRM_IOCTL_BASE,	\
		DRM_COMMAND_BASE + DRM_EXYNOS_G3D_SUBMIT,	\
		sizeof(struct drm_exynos_g3d_submit))
#define CMD_IOCTL_DRM_EXYNOS_G2D_SUBMIT			\
	DRM_IOC(DRM_IOC_READ | DRM_IOC_WRITE, DRM_IOCTL_BASE,	\
		DRM_COMMAND_BASE + DRM_EXYNOS_G2D_SUBMIT,	\
		sizeof(struct drm_exynos_g3d_submit))
#define CMD_IOCTL_DRM_EXYNOS_G3D_WAIT			\
	DRM_IOC(DRM_IOC_WRITE, DRM_IOCTL_BASE,	\
		DRM_COMMAND_BASE + DRM_EXYNOS_G3D_WAIT,	\
		sizeof(struct drm_exynos_g3d_wait))
#define CMD_IOCTL_DRM_EXYNOS_G3D_CPU_PREP			\
	DRM_IOC(DRM_IOC_WRITE, DRM_IOCTL_BASE,	\
		DRM_COMMAND_BASE + DRM_EXYNOS_G3D_CPU_PREP,	\
		sizeof(struct drm_exynos_g3d_cpu_prep))

static int dummy_cmd_exynos_g3d_create_pipe(struct fakedrm_file_desc *file,
					    void *arg)
{
	struct drm_exynos_g3d_pipe *pipe = arg;

	if (file->g3d_pipes == -1U)
		return -ENOMEM;

	pipe->pipe = ++file->g3d_pipes;

	return 0;
}

static int dummy_cmd_exynos_g2d_create_pipe(struct fakedrm_file_desc *file,
					    void *arg)
{
	struct drm_exynos_g3d_pipe *pipe = arg;

	if (file->g2d_pipes == -1U)
		return -ENOMEM;

	pipe->pipe = ++file->g2d_pipes;

	return 0;
}

static int dummy_cmd_exynos_g3d_destroy_pipe(struct fakedrm_file_desc *file,
					     void *arg)
{
	return 0;
}

static int dummy_cmd_exynos_g2d_destroy_pipe(struct fakedrm_file_desc *file,
					     void *arg)
{
	return 0;
}

static int dummy_cmd_exynos_g3d_submit(struct fakedrm_file_desc *file,
				       void *arg)
{
	struct drm_exynos_g3d_submit *submit = arg;

	DEBUG_MSG("pipe = %d, handle = %08x, offset = %08x, length = %08x",
			submit->pipe, submit->handle, submit->offset,
			submit->length);

	return 0;
}

static int dummy_cmd_exynos_g2d_submit(struct fakedrm_file_desc *file,
				       void *arg)
{
	struct drm_exynos_g3d_submit *submit = arg;

	DEBUG_MSG("pipe = %d, handle = %08x, offset = %08x, length = %08x",
			submit->pipe, submit->handle, submit->offset,
			submit->length);

	return 0;
}

static int dummy_cmd_exynos_g3d_wait(struct fakedrm_file_desc *file, void *arg)
{
	return 0;
}

static int dummy_cmd_exynos_g3d_cpu_prep(struct fakedrm_file_desc *file,
					 void *arg)
{
	return 0;
}

static int exynos_ioctl(struct fakedrm_file_desc *file, unsigned long request,
			void *arg)
{
	switch (request) {
	/* Exynos-specific GEM IOCTLs */
	case CMD_IOCTL_DRM_EXYNOS_GEM_CREATE:
		return dummy_cmd_exynos_gem_create(file, arg);
	case CMD_IOCTL_DRM_EXYNOS_GEM_MMAP:
		return dummy_cmd_exynos_gem_mmap(file, arg);
	case CMD_IOCTL_DRM_EXYNOS_GEM_MAP_OFFSET:
		return dummy_cmd_exynos_gem_map_offset(file, arg);

	/* Exynos-specific pipe IOCTLs */
	case CMD_IOCTL_DRM_EXYNOS_G3D_CREATE_PIPE:
		return dummy_cmd_exynos_g3d_create_pipe(file, arg);
	case CMD_IOCTL_DRM_EXYNOS_G2D_CREATE_PIPE:
		return dummy_cmd_exynos_g2d_create_pipe(file, arg);
	case CMD_IOCTL_DRM_EXYNOS_G3D_DESTROY_PIPE:
		return dummy_cmd_exynos_g3d_destroy_pipe(file, arg);

	case CMD_IOCTL_DRM_EXYNOS_G2D_DESTROY_PIPE:
		return dummy_cmd_exynos_g2d_destroy_pipe(file, arg);
	case CMD_IOCTL_DRM_EXYNOS_G3D_SUBMIT:
		return dummy_cmd_exynos_g3d_submit(file, arg);
	case CMD_IOCTL_DRM_EXYNOS_G2D_SUBMIT:
		return dummy_cmd_exynos_g2d_submit(file, arg);

	case CMD_IOCTL_DRM_EXYNOS_G3D_WAIT:
		return dummy_cmd_exynos_g3d_wait(file, arg);
	case CMD_IOCTL_DRM_EXYNOS_G3D_CPU_PREP:
		return dummy_cmd_exynos_g3d_cpu_prep(file, arg);

	default:
		break;
	}

	return -ENOTTY;
}

struct fakedrm_driver exynos_driver = {
	.name = "exynos",
	.date = "20110530",
	.desc = "Samsung SoC DRM",

	.version_major = 1,
	.version_minor = 0,
	.version_patchlevel = 0,

	.ioctl = exynos_ioctl,
};
