/*
 * Fake DRM
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
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <pthread.h>
#include <fcntl.h>
#include <errno.h>
#include <semaphore.h>
#include <signal.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <stdarg.h>
#include <stdint.h>
#include <drm.h>
#include <xf86drmMode.h>
#include <xf86drm.h>

#define U642VOID(x)		((void *)(unsigned long)(x))
#define VOID2U64(x)		((uint64_t)(unsigned long)(x))

#define ARRAY_SIZE(x)		(sizeof(x) / sizeof((x)[0]))

#define PUBLIC			__attribute__((__visibility__("default")))
#define CONSTRUCTOR		__attribute__((constructor))
#define DESTRUCTOR		__attribute__((destructor))

//#define DEBUG

#ifdef DEBUG
#define DEBUG_MSG(fmt, ...) \
	do { fprintf(stderr, "[D] "fmt " (%s:%d)\n", \
		##__VA_ARGS__, __FUNCTION__, __LINE__); } while (0)
#else
#define DEBUG_MSG(fmt, ...)
#endif

#define ERROR_MSG(fmt, ...) \
	do { fprintf(stderr, "[E] "fmt " (%s:%d)\n", \
		##__VA_ARGS__, __FUNCTION__, __LINE__); } while (0)

#include "exynos_drm.h"

/*
 * Pointers to originals of wrapped functions
 */
static int (*open_real)(const char *, int, ...);
static int (*close_real)(int);
static int (*ioctl_real)(int, unsigned long, ...);
static void *(*mmap_real)(void *, size_t, int, int, int, off_t);
static int (*munmap_real)(void *, size_t);
static int (*__fxstat_real)(int, int, struct stat *);
static int (*__xstat_real)(int, const char *, struct stat *);

/*
 * Synchronized hash table (wrappers for drmHash*)
 */

struct locked_hash_table {
	pthread_rwlock_t lock;
	void *table;
};

static void hash_insert(struct locked_hash_table *table,
			unsigned long key, void *value)
{
	pthread_rwlock_wrlock(&table->lock);
	drmHashInsert(table->table, key, value);
	pthread_rwlock_unlock(&table->lock);
}

static void *hash_lookup(struct locked_hash_table *table, unsigned long key)
{
	void *value;
	int ret;

	pthread_rwlock_rdlock(&table->lock);
	ret = drmHashLookup(table->table, key, &value);
	pthread_rwlock_unlock(&table->lock);

	return ret ? NULL : value;
}

static void hash_remove(struct locked_hash_table *table, unsigned long key)
{
	pthread_rwlock_wrlock(&table->lock);
	drmHashDelete(table->table, key);
	pthread_rwlock_unlock(&table->lock);
}

static void hash_create(struct locked_hash_table *table)
{
	pthread_rwlock_init(&table->lock, NULL);
	table->table = drmHashCreate();
	if (!table->table) {
		ERROR_MSG("failed to create hash table");
		exit(1);
	}
}

/*
 * Dummy file descriptors
 */

struct dummy_drm_desc {
	int fd;
	unsigned int refcnt;
	/* More to come */
};

static struct locked_hash_table desc_table;

static void desc_get(struct dummy_drm_desc *desc)
{
	__sync_add_and_fetch(&desc->refcnt, 1);
}

static void desc_put(struct dummy_drm_desc *desc)
{
	if (__sync_sub_and_fetch(&desc->refcnt, 1) == 0)
		free(desc);
}

/*
 * Dummy map descriptors
 */

struct dummy_map_desc {
	uint32_t handle;
	void *addr;
};

static struct locked_hash_table map_table;

/*
 * Fake BO management
 */

#define FAKEDRM_BO_SHM_CTRL_LENGTH	4096
#define FAKEDRM_BO_SHM_BITMAP_OFFSET	FAKEDRM_BO_SHM_CTRL_LENGTH
#define FAKEDRM_BO_BITMAP_SIZE_INIT	1024
#define FAKEDRM_BO_BITMAP_SIZE_MAX	32768

#define FAKEDRM_BO_SHM_HDR_LENGTH	4096

struct fakedrm_bo_ctrl {
	uint32_t bitmap_size;
};

struct fakedrm_bo_data {
	uint32_t name;
	uint32_t size;
	uint32_t refcnt;
};

static sem_t *bo_sem;
static int bo_shm;
static void *bo_shm_mem;
static uint32_t *bo_bitmap;
static uint32_t bo_bitmap_size;
static struct fakedrm_bo_ctrl *bo_ctrl;
static struct locked_hash_table bo_table;

static int __bo_remap_bitmap(void)
{
	uint32_t *new_bitmap;

	new_bitmap = mmap(NULL, bo_ctrl->bitmap_size * sizeof(*bo_bitmap),
				PROT_READ | PROT_WRITE, MAP_SHARED, bo_shm,
				FAKEDRM_BO_SHM_BITMAP_OFFSET);
	if (new_bitmap == MAP_FAILED) {
		ERROR_MSG("failed to (re)map BO bitmap: %s", strerror(errno));
		return -1;
	}

	munmap(bo_bitmap, bo_bitmap_size * sizeof(*bo_bitmap));
	bo_bitmap = new_bitmap;
	bo_bitmap_size = bo_ctrl->bitmap_size;

	return 0;
}

static uint32_t __bo_grow_bitmap(void)
{
	unsigned old_size = bo_ctrl->bitmap_size;
	unsigned old_bytes = old_size * sizeof(*bo_bitmap);
	unsigned new_size = old_size * 2;
	unsigned new_bytes;
	int ret;

	if (old_size >= FAKEDRM_BO_BITMAP_SIZE_MAX) {
		ERROR_MSG("FAKEDRM_BO_BITMAP_SIZE_MAX exceeded");
		return 0;
	}

	/* Handle unallocated bitmap */
	if (!new_size)
		new_size = FAKEDRM_BO_BITMAP_SIZE_INIT;
	new_bytes = new_size * sizeof(*bo_bitmap);

	ret = ftruncate(bo_shm, FAKEDRM_BO_SHM_BITMAP_OFFSET + new_bytes);
	if (ret) {
		ERROR_MSG("failed to resize BO shared memory: %s",
				strerror(errno));
		return 0;
	}
	bo_ctrl->bitmap_size = new_size;

	ret = __bo_remap_bitmap();
	if (ret) {
		bo_ctrl->bitmap_size = old_size;
		return 0;
	}
	memset(&bo_bitmap[old_size], 0xff, new_bytes - old_bytes);

	bo_bitmap[old_size] &= ~(1 << 0);
	return old_size * 8 * sizeof(*bo_bitmap) + 1;
}

static uint32_t bo_get_name(void)
{
	unsigned name = 0;
	unsigned i;

	sem_wait(bo_sem);

	if (bo_bitmap_size != bo_ctrl->bitmap_size)
		if (__bo_remap_bitmap())
			goto done;

	for (i = 0; i < bo_bitmap_size; ++i) {
		unsigned bit = __builtin_ffs(bo_bitmap[i]);

		if (bit) {
			--bit;
			bo_bitmap[i] &= ~(1 << bit);
			name = i * 8 * sizeof(*bo_bitmap) + bit + 1;
			goto done;
		}
	}

	name = __bo_grow_bitmap();

done:
	sem_post(bo_sem);

	return name;
}

static void bo_put_name(uint32_t name)
{
	unsigned word = (name - 1) / (8 * sizeof(*bo_bitmap));
	unsigned bit = (name - 1) % (8 * sizeof(*bo_bitmap));

	if (word >= bo_bitmap_size)
		return;

	sem_wait(bo_sem);

	bo_bitmap[word] |= 1 << bit;

	sem_post(bo_sem);
}

static void bo_get(struct fakedrm_bo_data *bo)
{
	__sync_add_and_fetch(&bo->refcnt, 1);
}

static void bo_put(struct fakedrm_bo_data *bo)
{
	char pathname[] = "/fakedrm_bo.012345678";
	uint32_t name = bo->name;

	if (__sync_sub_and_fetch(&bo->refcnt, 1))
		return;

	munmap(bo, FAKEDRM_BO_SHM_HDR_LENGTH);

	snprintf(pathname, sizeof(pathname), "/fakedrm_bo.%08x", name);
	shm_unlink(pathname);

	bo_put_name(name);
}

static int bo_import(uint32_t name, uint32_t *handle, uint32_t *size)
{
	char pathname[] = "/fakedrm_bo.012345678";
	struct fakedrm_bo_data *bo;
	int obj_shm;
	int ret;

	snprintf(pathname, sizeof(pathname), "/fakedrm_bo.%08x", name);
	obj_shm = shm_open(pathname, O_RDWR,
				S_IWUSR | S_IRUSR | S_IWGRP | S_IRGRP);
	if (obj_shm < 0) {
		ret = -errno;
		ERROR_MSG("failed to open BO SHM object: %s",
				strerror(errno));
		return ret;
	}

	bo = mmap(NULL, FAKEDRM_BO_SHM_HDR_LENGTH, PROT_READ | PROT_WRITE,
			MAP_SHARED, obj_shm, 0);
	if (bo == MAP_FAILED) {
		ret = -errno;
		ERROR_MSG("failed to map BO SHM object header: %s",
				strerror(errno));
		close(obj_shm);
		return ret;
	}

	*handle = obj_shm;
	*size = bo->size;

	bo_get(bo);

	hash_insert(&bo_table, obj_shm, bo);

	return 0;
}

static int bo_export(uint32_t handle, uint32_t *name)
{
	struct fakedrm_bo_data *bo;
	int ret = 0;

	bo = hash_lookup(&bo_table, handle);
	if (!bo) {
		ERROR_MSG("failed to lookup BO name %08x", handle);
		return -ENOENT;
	}

	*name = bo->name;

	return ret;
}

static int bo_create(uint32_t size,
			 uint32_t *out_handle)
{
	char pathname[] = "/fakedrm_bo.012345678";
	struct fakedrm_bo_data *bo;
	uint32_t name;
	int obj_shm;
	int ret;

	name = bo_get_name();
	if (!name) {
		ERROR_MSG("out of free handles");
		return -ENOMEM;
	}

	snprintf(pathname, sizeof(pathname), "/fakedrm_bo.%08x", name);
	obj_shm = shm_open(pathname, O_RDWR | O_CREAT | O_EXCL,
				S_IWUSR | S_IRUSR | S_IWGRP | S_IRGRP);
	if (obj_shm < 0) {
		ret = -errno;
		ERROR_MSG("failed to create BO SHM object: %s",
				strerror(errno));
		goto err_handle;
	}

	ret = ftruncate(obj_shm, FAKEDRM_BO_SHM_HDR_LENGTH);
	if (ret) {
		ret = -errno;
		ERROR_MSG("failed to resize BO SHM object: %s",
				strerror(errno));
		goto err_close_unlink;
	}

	bo = mmap(NULL, FAKEDRM_BO_SHM_HDR_LENGTH, PROT_READ | PROT_WRITE,
			MAP_SHARED, obj_shm, 0);
	if (bo == MAP_FAILED) {
		ret = -errno;
		ERROR_MSG("failed to map BO SHM object header: %s",
				strerror(errno));
		goto err_close_unlink;
	}

	*out_handle = obj_shm;
	bo->name = name;
	bo->size = size;
	bo->refcnt = 1;

	hash_insert(&bo_table, obj_shm, bo);

	return 0;

err_close_unlink:
	shm_unlink(pathname);
	close(obj_shm);
err_handle:
	bo_put_name(name);

	return ret;
}

static void bo_close(uint32_t handle)
{
	struct fakedrm_bo_data *bo;

	bo = hash_lookup(&bo_table, handle);
	if (!bo) {
		ERROR_MSG("failed to lookup BO name %08x", handle);
		return;
	}

	hash_remove(&bo_table, handle);

	bo_put(bo);
}

static int bo_map(uint32_t handle, void **out_addr)
{
	struct fakedrm_bo_data *bo;
	void *addr = NULL;
	int ret;

	bo = hash_lookup(&bo_table, handle);
	if (!bo) {
		ERROR_MSG("failed to lookup BO name %08x", handle);
		return -ENOENT;
	}

	ret = ftruncate(handle, FAKEDRM_BO_SHM_HDR_LENGTH + bo->size);
	if (ret) {
		ret = -errno;
		ERROR_MSG("failed to resize BO SHM object: %s",
				strerror(errno));
		return ret;
	}

	addr = mmap(NULL, bo->size, PROT_READ | PROT_WRITE, MAP_SHARED,
			handle, FAKEDRM_BO_SHM_HDR_LENGTH);
	if (addr == MAP_FAILED) {
		ret = -errno;
		ERROR_MSG("failed to mmap BO: %s", strerror(errno));
		return ret;
	}

	bo_get(bo);

	*out_addr = addr;
	return 0;
}

static void bo_unmap(uint32_t handle)
{
	struct fakedrm_bo_data *bo;

	bo = hash_lookup(&bo_table, handle);
	if (!bo) {
		ERROR_MSG("failed to lookup BO name %08x", handle);
		return;
	}

	bo_put(bo);
}

/*
 * Dummy IOCTL handlers
 */

/* DRM device IOCTLs */

#define DUMMY_VERSION_MAJOR		1
#define DUMMY_VERSION_MINOR		0
#define DUMMY_VERSION_PATCH		0
#define DUMMY_VERSION_NAME		"exynos"
#define DUMMY_VERSION_DATE		"20110530"
#define DUMMY_VERSION_DESC		"Samsung SoC DRM"

static int dummy_version(void *arg)
{
	struct drm_version *version = arg;

	version->version_major = DUMMY_VERSION_MAJOR;
	version->version_minor = DUMMY_VERSION_MINOR;
	version->version_patchlevel = DUMMY_VERSION_PATCH;

	version->name_len = strlen(DUMMY_VERSION_NAME);
	version->date_len = strlen(DUMMY_VERSION_DATE);
	version->desc_len = strlen(DUMMY_VERSION_DESC);

	if (!version->name || !version->date || !version->desc)
		return 0;

	strcpy(version->name, DUMMY_VERSION_NAME);
	strcpy(version->date, DUMMY_VERSION_DATE);
	strcpy(version->desc, DUMMY_VERSION_DESC);

	return 0;
}

static int dummy_get_unique(void *arg)
{
	return -EINVAL;
}

static uint32_t magic;

static int dummy_get_magic(void *arg)
{
	struct drm_auth *auth = arg;

	auth->magic = magic;

	return 0;
}

static int dummy_auth_magic(void *arg)
{
	struct drm_auth *auth = arg;

	magic = auth->magic;

	return 0;
}

/* Mode setting IOCTLs */

#define DUMMY_WIDTH			1680
#define DUMMY_HEIGHT			1050
#define DUMMY_REFRESH_RATE		60

#define __MODE_NAME(w,h)		#w "x" #h
#define MODE_NAME(w,h)			__MODE_NAME(w,h)
#define DUMMY_MODE_NAME			MODE_NAME(DUMMY_WIDTH, DUMMY_HEIGHT)

#define DUMMY_HFP			10
#define DUMMY_HBP			10
#define DUMMY_HSYNC_LEN			10
#define DUMMY_VFP			10
#define DUMMY_VBP			10
#define DUMMY_VSYNC_LEN			10

#define DUMMY_HSYNC_START		(DUMMY_WIDTH + DUMMY_HFP)
#define DUMMY_HSYNC_END			(DUMMY_HSYNC_START + DUMMY_HSYNC_LEN)
#define DUMMY_HTOTAL			(DUMMY_HSYNC_END + DUMMY_HBP)
#define DUMMY_VSYNC_START		(DUMMY_HEIGHT + DUMMY_VFP)
#define DUMMY_VSYNC_END			(DUMMY_VSYNC_START + DUMMY_VSYNC_LEN)
#define DUMMY_VTOTAL			(DUMMY_VSYNC_END + DUMMY_VBP)

#define DUMMY_PIXEL_CLOCK		((DUMMY_HTOTAL * DUMMY_VTOTAL \
					* DUMMY_REFRESH_RATE) / 1000)

#define DUMMY_WIDTH_MM			474
#define DUMMY_HEIGHT_MM			303

static uint32_t fbs[] = {

};

static struct drm_mode_crtc crtcs[] = {
	{
		.crtc_id = 1,
		.fb_id = 0,
		.x = 0,
		.y = 0,
		.mode = {
			.clock = DUMMY_PIXEL_CLOCK,
			.hdisplay = DUMMY_WIDTH,
			.hsync_start = DUMMY_HSYNC_START,
			.hsync_end = DUMMY_HSYNC_END,
			.htotal = DUMMY_HTOTAL,
			.hskew = 0,
			.vdisplay = DUMMY_HEIGHT,
			.vsync_start = DUMMY_VSYNC_START,
			.vsync_end = DUMMY_VSYNC_END,
			.vtotal = DUMMY_VTOTAL,
			.vscan = 0,
			.vrefresh = DUMMY_REFRESH_RATE,
			.flags = 0,
			.type = DRM_MODE_TYPE_DRIVER | DRM_MODE_TYPE_PREFERRED,
			.name = DUMMY_MODE_NAME,
		},
		.mode_valid = 0,
	},
};

static struct drm_mode_get_encoder encoders[] = {
	{
		.encoder_id = 1,
		.encoder_type = DRM_MODE_ENCODER_LVDS,
		.crtc_id = 1,
		.possible_crtcs = -1U,
		.possible_clones = -1U,
	},
};

static struct drm_mode_modeinfo connector_modes[] = {
	{
		.clock = DUMMY_PIXEL_CLOCK,
		.hdisplay = DUMMY_WIDTH,
		.hsync_start = DUMMY_HSYNC_START,
		.hsync_end = DUMMY_HSYNC_END,
		.htotal = DUMMY_HTOTAL,
		.hskew = 0,
		.vdisplay = DUMMY_HEIGHT,
		.vsync_start = DUMMY_VSYNC_START,
		.vsync_end = DUMMY_VSYNC_END,
		.vtotal = DUMMY_VTOTAL,
		.vscan = 0,
		.vrefresh = DUMMY_REFRESH_RATE,
		.flags = 0,
		.type = DRM_MODE_TYPE_DRIVER | DRM_MODE_TYPE_PREFERRED,
		.name = DUMMY_MODE_NAME,
	}
};

static uint32_t connector_props[] = {

};

static uint64_t connector_prop_values[] = {

};

static struct drm_mode_get_connector connectors[] = {
	{
		.modes_ptr = VOID2U64(connector_modes),
		.count_modes = ARRAY_SIZE(connector_modes),

		.props_ptr = VOID2U64(connector_props),
		.prop_values_ptr = VOID2U64(connector_prop_values),
		.count_props = ARRAY_SIZE(connector_props),

		.encoder_id = 1,
		.connector_id = 1,
		.connector_type = DRM_MODE_CONNECTOR_LVDS,
		.connector_type_id = 0,

		.connection = 1,
		.mm_width = DUMMY_WIDTH_MM,
		.mm_height = DUMMY_HEIGHT_MM,
		.subpixel = 0,
	},
};

static int dummy_mode_getresources(void *arg)
{
	struct drm_mode_card_res *res = arg;
	uint32_t *ptr;
	unsigned i;

	res->min_width = DUMMY_WIDTH;
	res->max_width = DUMMY_WIDTH;
	res->min_height = DUMMY_HEIGHT;
	res->max_height = DUMMY_HEIGHT;

	if (res->count_fbs >= ARRAY_SIZE(fbs))
		memcpy(U642VOID(res->fb_id_ptr), fbs,
			ARRAY_SIZE(fbs) * sizeof(uint32_t));
	res->count_fbs = ARRAY_SIZE(fbs);

	if (res->count_crtcs >= ARRAY_SIZE(crtcs)) {
		ptr = U642VOID(res->crtc_id_ptr);
		for (i = 1; i <= ARRAY_SIZE(crtcs); ++i)
			*(ptr++) = i;
	}
	res->count_crtcs = ARRAY_SIZE(crtcs);

	if (res->count_connectors >= ARRAY_SIZE(connectors)) {
		ptr = U642VOID(res->connector_id_ptr);
		for (i = 1; i <= ARRAY_SIZE(connectors); ++i)
			*(ptr++) = i;
	}
	res->count_connectors = ARRAY_SIZE(connectors);

	if (res->count_encoders >= ARRAY_SIZE(encoders)) {
		ptr = U642VOID(res->encoder_id_ptr);
		for (i = 1; i <= ARRAY_SIZE(encoders); ++i)
			*(ptr++) = i;
	}
	res->count_encoders = ARRAY_SIZE(encoders);

	return 0;
}

static int dummy_mode_getcrtc(void *arg)
{
	struct drm_mode_crtc *crtc_resp = arg;

	if (!crtc_resp->crtc_id
	    || crtc_resp->crtc_id > ARRAY_SIZE(crtcs))
		return -ENOENT;

	memcpy(crtc_resp, &crtcs[crtc_resp->crtc_id - 1], sizeof(*crtc_resp));
	return 0;
}

static int dummy_mode_setcrtc(void *arg)
{
	/* TODO */
	return 0;
}

static int dummy_mode_getencoder(void *arg)
{
	struct drm_mode_get_encoder *enc_resp = arg;

	if (!enc_resp->encoder_id
	    || enc_resp->encoder_id > ARRAY_SIZE(encoders))
		return -ENOENT;

	memcpy(enc_resp, &encoders[enc_resp->encoder_id - 1],
		sizeof(*enc_resp));
	return 0;
}

static int dummy_mode_getconnector(void *arg)
{
	struct drm_mode_get_connector *out_resp = arg;
	struct drm_mode_get_connector *connector;

	if (!out_resp->connector_id
	    || out_resp->connector_id > ARRAY_SIZE(connectors))
		return -ENOENT;

	connector = &connectors[out_resp->connector_id - 1];

	out_resp->encoder_id = connector->encoder_id;
	out_resp->connector_id = connector->connector_id;
	out_resp->connector_type = connector->connector_type;
	out_resp->connector_type_id = connector->connector_type_id;

	out_resp->connection = connector->connection;
	out_resp->mm_width = connector->mm_width;
	out_resp->mm_height = connector->mm_height;
	out_resp->subpixel = connector->subpixel;

	if (out_resp->count_modes >= connector->count_modes)
		memcpy(U642VOID(out_resp->modes_ptr),
			U642VOID(connector->modes_ptr), connector->count_modes
			* sizeof(struct drm_mode_modeinfo));
	out_resp->count_modes = connector->count_modes;

	if (out_resp->count_props >= connector->count_props) {
		memcpy(U642VOID(out_resp->props_ptr),
			U642VOID(connector->props_ptr), connector->count_props
			* sizeof(uint32_t));
		memcpy(U642VOID(out_resp->prop_values_ptr),
			U642VOID(connector->prop_values_ptr),
			connector->count_props * sizeof(uint64_t));
	}
	out_resp->count_props = connector->count_props;

	if (out_resp->count_encoders >= ARRAY_SIZE(encoders)) {
		uint32_t *ptr = U642VOID(out_resp->encoders_ptr);
		uint32_t i;

		for (i = 1; i <= ARRAY_SIZE(encoders); ++i)
			*(ptr++) = i;
	}
	out_resp->count_encoders = ARRAY_SIZE(encoders);

	return 0;
}

static int dummy_mode_addfb(void *arg)
{
	/* TODO */
	return 0;
}

static int dummy_mode_rmfb(void *arg)
{
	/* TODO */
	return 0;
}

static int dummy_mode_page_flip(void *arg)
{
	/* TODO */
	return 0;
}

/*
 * Generic GEM IOCTLs
 */

static int dummy_gem_open(void *arg)
{
	struct drm_gem_open *req = arg;
	uint32_t size;
	int ret;

	ret = bo_import(req->name, &req->handle, &size);
	req->size = size;

	return ret;
}

static int dummy_gem_close(void *arg)
{
	struct drm_gem_close *req = arg;

	bo_close(req->handle);

	return 0;
}

static int dummy_gem_flink(void *arg)
{
	struct drm_gem_flink *req = arg;

	return bo_export(req->handle, &req->name);
}

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

static int dummy_cmd_exynos_gem_create(void *arg)
{
	struct drm_exynos_gem_create *req = arg;

	return bo_create(req->size, &req->handle);
}

static int dummy_cmd_exynos_gem_mmap(void *arg)
{
	struct drm_exynos_gem_mmap *req = arg;
	struct dummy_map_desc *desc;
	void *addr;
	int ret;

	desc = calloc(1, sizeof(*desc));
	if (!desc) {
		ERROR_MSG("failed to allocate map descriptor: %s",
				strerror(errno));
		return -ENOMEM;
	}

	ret = bo_map(req->handle, &addr);
	if (ret) {
		free(desc);
		return ret;
	}

	desc->handle = req->handle;
	desc->addr = addr;

	hash_insert(&map_table, (unsigned long)addr, desc);

	req->mapped = VOID2U64(addr);
	return 0;
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

static int dummy_cmd_exynos_g3d_create_pipe(void *arg)
{
	return 0;
}

static int dummy_cmd_exynos_g2d_create_pipe(void *arg)
{
	return 0;
}

static int dummy_cmd_exynos_g3d_destroy_pipe(void *arg)
{
	return 0;
}

static int dummy_cmd_exynos_g2d_destroy_pipe(void *arg)
{
	return 0;
}

static int dummy_cmd_exynos_g3d_submit(void *arg)
{
	return 0;
}

static int dummy_cmd_exynos_g2d_submit(void *arg)
{
	return 0;
}

/*
 * Implementation of file operations for emulated DRM devices
 */
static int dummy_open(const char *pathname, int flags, mode_t mode)
{
	struct dummy_drm_desc *desc;
	int fd;

	fd = open_real("/dev/null", O_RDWR, 0);
	if (!fd) {
		ERROR_MSG("failed to open '/dev/null': %s",
			strerror(errno));
		return -1;
	}

	desc = calloc(1, sizeof(*desc));
	if (!desc) {
		ERROR_MSG("failed to allocate descriptor");
		close(fd);
		errno = ENOMEM;
		return -1;
	}

	desc_get(desc);
	desc->fd = fd;

	hash_insert(&desc_table, fd, desc);

	return fd;
}

static void dummy_close(struct dummy_drm_desc *desc)
{
	hash_remove(&desc_table, desc->fd);
	desc->fd = -1;
	desc_put(desc);
}

static int dummy_ioctl(struct dummy_drm_desc *desc, unsigned long request,
		       void *arg)
{
	int ret;

	switch (request) {
	/* Core IOCTLs */
	case DRM_IOCTL_VERSION:
		ret = dummy_version(arg);
		break;
	case DRM_IOCTL_GET_UNIQUE:
		ret = dummy_get_unique(arg);
		break;
	case DRM_IOCTL_GET_MAGIC:
		ret = dummy_get_magic(arg);
		break;
	case DRM_IOCTL_AUTH_MAGIC:
		ret = dummy_auth_magic(arg);
		break;

	/* Mode setting IOCTLs */
	case DRM_IOCTL_MODE_GETRESOURCES:
		ret = dummy_mode_getresources(arg);
		break;
	case DRM_IOCTL_MODE_GETCRTC:
		ret = dummy_mode_getcrtc(arg);
		break;
	case DRM_IOCTL_MODE_SETCRTC:
		ret = dummy_mode_setcrtc(arg);
		break;
	case DRM_IOCTL_MODE_GETENCODER:
		ret = dummy_mode_getencoder(arg);
		break;
	case DRM_IOCTL_MODE_GETCONNECTOR:
		ret = dummy_mode_getconnector(arg);
		break;
	case DRM_IOCTL_MODE_ADDFB:
		ret = dummy_mode_addfb(arg);
		break;
	case DRM_IOCTL_MODE_RMFB:
		ret = dummy_mode_rmfb(arg);
		break;
	case DRM_IOCTL_MODE_PAGE_FLIP:
		ret = dummy_mode_page_flip(arg);
		break;

	/* Generic GEM IOCTLs */
	case DRM_IOCTL_GEM_OPEN:
		ret = dummy_gem_open(arg);
		break;
	case DRM_IOCTL_GEM_CLOSE:
		ret = dummy_gem_close(arg);
		break;
	case DRM_IOCTL_GEM_FLINK:
		ret = dummy_gem_flink(arg);
		break;

	/* Exynos-specific GEM IOCTLs */
	case CMD_IOCTL_DRM_EXYNOS_GEM_CREATE:
		ret = dummy_cmd_exynos_gem_create(arg);
		break;
	case CMD_IOCTL_DRM_EXYNOS_GEM_MMAP:
		ret = dummy_cmd_exynos_gem_mmap(arg);
		break;

	/* Exynos-specific pipe IOCTLs */
	case CMD_IOCTL_DRM_EXYNOS_G3D_CREATE_PIPE:
		ret = dummy_cmd_exynos_g3d_create_pipe(arg);
		break;
	case CMD_IOCTL_DRM_EXYNOS_G2D_CREATE_PIPE:
		ret = dummy_cmd_exynos_g2d_create_pipe(arg);
		break;
	case CMD_IOCTL_DRM_EXYNOS_G3D_DESTROY_PIPE:
		ret = dummy_cmd_exynos_g3d_destroy_pipe(arg);
		break;
	case CMD_IOCTL_DRM_EXYNOS_G2D_DESTROY_PIPE:
		ret = dummy_cmd_exynos_g2d_destroy_pipe(arg);
		break;
	case CMD_IOCTL_DRM_EXYNOS_G3D_SUBMIT:
		ret = dummy_cmd_exynos_g3d_submit(arg);
		break;
	case CMD_IOCTL_DRM_EXYNOS_G2D_SUBMIT:
		ret = dummy_cmd_exynos_g2d_submit(arg);
		break;

	default:
		ERROR_MSG("%s: Not implemented dummy handler for IOCTL %08lx",
			__func__, request);
		ret = -EINVAL;
	}

	DEBUG_MSG("%s: IOCTL %08lx, ret=%d", __func__, request, ret);

	if (ret) {
		errno = -ret;
		return -1;
	}

	return 0;
}

static void *dummy_mmap(struct dummy_drm_desc *desc, void *addr, size_t length,
			int prot, int flags, off_t offset)
{
	return MAP_FAILED;
}

static int dummy_munmap(struct dummy_map_desc *desc, size_t length)
{
	bo_unmap(desc->handle);
	hash_remove(&map_table, (unsigned long)desc->addr);

	return munmap_real(desc->addr, length);
}

static int dummy_fstat(struct dummy_drm_desc *desc, int ver, struct stat *buf)
{
	/* TODO: Fake stat info */
	return __fxstat_real(ver, desc->fd, buf);
}

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

	DEBUG_MSG("%s(pathname = '%s', flags = %d, mode = %x)",
		__func__, pathname, flags, mode);

	if (!strcmp(pathname, "/dev/dri/card0"))
		return dummy_open(pathname, flags, mode);

	return open_real(pathname, flags, mode);
}

PUBLIC int close(int fd)
{
	struct dummy_drm_desc *desc;

	DEBUG_MSG("%s(fd = %d)", __func__, fd);

	desc = hash_lookup(&desc_table, fd);
	if (desc)
		dummy_close(desc);

	return close_real(fd);
}

PUBLIC int ioctl(int d, unsigned long request, ...)
{
	unsigned dir = _IOC_DIR(request);
	struct dummy_drm_desc *desc;
	char *argp = NULL;
	va_list args;

	if (dir != _IOC_NONE) {
		va_start(args, request);
		argp = va_arg(args, char *);
		va_end(args);
	}

	DEBUG_MSG("%s(d = %d, request = %lx, argp = %p)",
		__func__, d, request, argp);

	if (_IOC_TYPE(request) == DRM_IOCTL_BASE) {
		desc = hash_lookup(&desc_table, d);
		if (desc)
			return dummy_ioctl(desc, request, argp);
	}

	return ioctl_real(d, request, argp);
}

PUBLIC void *mmap(void *addr, size_t length, int prot, int flags,
		  int fd, off_t offset)
{
	struct dummy_drm_desc *desc;

	DEBUG_MSG("%s(addr = %p, length = %lx, prot = %d, flags = %d, fd = %d, offset = %lx)",
		__func__, addr, length, prot, flags, fd, offset);

	desc = hash_lookup(&desc_table, fd);
	if (desc)
		return dummy_mmap(desc, addr, length, prot, flags, offset);

	return mmap_real(addr, length, prot, flags, fd, offset);
}

PUBLIC int munmap(void *addr, size_t length)
{
	struct dummy_map_desc *desc;

	DEBUG_MSG("%s(addr = %p, length = %lx)", __func__, addr, length);

	desc = hash_lookup(&map_table, (unsigned long)addr);
	if (desc)
		return dummy_munmap(desc, length);

	return munmap_real(addr, length);
}

PUBLIC int __fxstat(int ver, int fd, struct stat *buf)
{
	struct dummy_drm_desc *desc;

	DEBUG_MSG("%s(ver = %d, fd = %d, buf = %p)",
		__func__, ver, fd, buf);

	desc = hash_lookup(&desc_table, fd);
	if (desc)
		return dummy_fstat(desc, ver, buf);

	return __fxstat_real(ver, fd, buf);
}

PUBLIC int __xstat(int ver, const char *pathname, struct stat *buf)
{
	DEBUG_MSG("%s(ver = %d, pathname = '%s', buf = %p)",
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

CONSTRUCTOR static void constructor(void)
{
	int ret;

	open_real = lookup_symbol("open");
	close_real = lookup_symbol("close");
	ioctl_real = lookup_symbol("ioctl");
	mmap_real = lookup_symbol("mmap");
	munmap_real = lookup_symbol("munmap");
	__fxstat_real = lookup_symbol("__fxstat");
	__xstat_real = lookup_symbol("__xstat");

	hash_create(&bo_table);
	hash_create(&desc_table);
	hash_create(&map_table);

	bo_sem = sem_open("/fakedrm_bo", O_RDWR | O_CREAT,
				S_IWUSR | S_IRUSR | S_IWGRP | S_IRGRP, 1);
	if (bo_sem == SEM_FAILED) {
		ERROR_MSG("failed to open BO semaphore: %s", strerror(errno));
		exit(1);
	}

	sem_wait(bo_sem);

	bo_shm = shm_open("/fakedrm_bo", O_RDWR | O_CREAT | O_EXCL,
				S_IWUSR | S_IRUSR | S_IWGRP | S_IRGRP);
	if (bo_shm >= 0) {
		/* We have just created fresh new shared memory block
		 * and we hold the semaphore. This means that we are
		 * responsible for initialization of control data. */
		ret = ftruncate(bo_shm, FAKEDRM_BO_SHM_CTRL_LENGTH);
		if (ret) {
			ERROR_MSG("failed to resize BO shared memory: %s",
					strerror(errno));
			shm_unlink("/fakedrm_bo");
			sem_post(bo_sem);
			exit(1);
		}
	} else {
		bo_shm = shm_open("/fakedrm_bo", O_RDWR, 0);
	}
	if (bo_shm < 0) {
		ERROR_MSG("failed to open BO shared memory: %s",
				strerror(errno));
		sem_post(bo_sem);
		exit(1);
	}

	sem_post(bo_sem);

	bo_shm_mem = mmap(NULL, FAKEDRM_BO_SHM_CTRL_LENGTH,
			PROT_READ | PROT_WRITE, MAP_SHARED, bo_shm, 0);
	if (bo_shm_mem == MAP_FAILED) {
		ERROR_MSG("failed to map BO shared memory: %s", strerror(errno));
		exit(1);
	}
	bo_ctrl = (struct fakedrm_bo_ctrl *)bo_shm_mem;
}

DESTRUCTOR static void destructor(void)
{
	/* TODO: Close open GEM handles */
}
