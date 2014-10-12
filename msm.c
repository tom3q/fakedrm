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

#define __user

#include "msm_drm.h"
#include "file.h"
#include "gem.h"

/*
 * MSM-specific GEM IOCTLs
 */

#define SZ_512K				0x00080000

static int dummy_cmd_msm_get_param(struct fakedrm_file_desc *file, void *data)
{
	struct drm_msm_param *args = data;

	if (args->pipe != MSM_PIPE_3D0)
		return -EINVAL;

	/* TODO might be useful for these to be configurable to simulate
	 * different gpu's..
	 */
	switch (args->param) {
	case MSM_PARAM_GPU_ID:
		args->value = 320;
		return 0;
	case MSM_PARAM_GMEM_SIZE:
		args->value = SZ_512K;
		return 0;
	case MSM_PARAM_CHIP_ID:
		args->value = 0x03020002;
		return 0;
	default:
		DEBUG_MSG("invalid param: %u", args->param);
		return -EINVAL;
	}
}

static int dummy_cmd_msm_gem_new(struct fakedrm_file_desc *file, void *data)
{
	struct drm_msm_gem_new *args = data;

	return bo_create(file, args->size, &args->handle);
}

static int dummy_cmd_msm_gem_info(struct fakedrm_file_desc *file, void *data)
{
	struct drm_msm_gem_info *args = data;

	return bo_map_offset(file, args->handle, &args->offset);
}

static int dummy_cmd_msm_gem_cpu_prep(struct fakedrm_file_desc *file, void *data)
{
	return 0;
}

static int dummy_cmd_msm_gem_cpu_fini(struct fakedrm_file_desc *file, void *data)
{
	return 0;
}

static int dummy_cmd_msm_gem_submit(struct fakedrm_file_desc *file, void *data)
{
	struct drm_msm_gem_submit *args = data;
	static uint32_t fence = 0;

	args->fence = ++fence;

	DEBUG_MSG("pipe=%d, fence=%d", args->pipe, args->fence);

	return 0;
}


static int dummy_cmd_msm_wait_fence(struct fakedrm_file_desc *file, void *data)
{
	return 0;
}

static int msm_ioctl(struct fakedrm_file_desc *file, unsigned long request,
			void *arg)
{
	switch (_IOC_NR(request)) {

	case _IOC_NR(DRM_IOCTL_MSM_GET_PARAM):
		return dummy_cmd_msm_get_param(file, arg);
	case _IOC_NR(DRM_IOCTL_MSM_GEM_NEW):
		return dummy_cmd_msm_gem_new(file, arg);
	case _IOC_NR(DRM_IOCTL_MSM_GEM_INFO):
		return dummy_cmd_msm_gem_info(file, arg);
	case _IOC_NR(DRM_IOCTL_MSM_GEM_CPU_PREP):
		return dummy_cmd_msm_gem_cpu_prep(file, arg);
	case _IOC_NR(DRM_IOCTL_MSM_GEM_CPU_FINI):
		return dummy_cmd_msm_gem_cpu_fini(file, arg);
	case _IOC_NR(DRM_IOCTL_MSM_GEM_SUBMIT):
		return dummy_cmd_msm_gem_submit(file, arg);
	case _IOC_NR(DRM_IOCTL_MSM_WAIT_FENCE):
		return dummy_cmd_msm_wait_fence(file, arg);
	default:
		break;
	}

	return -ENOTTY;
}

struct fakedrm_driver msm_driver = {
	.name = "msm",
	.date = "20130625",
	.desc = "MSM Snapdragon DRM",

	.version_major = 1,
	.version_minor = 0,
	.version_patchlevel = 0,

	.ioctl = msm_ioctl,
};
