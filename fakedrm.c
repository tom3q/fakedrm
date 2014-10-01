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

#include "exynos_drm.h"

static volatile sig_atomic_t cleanup_in_progress;
static sigset_t captured_signals;

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

typedef void (*hash_callback_t)(void *);

static void *hash_lookup_callback(struct locked_hash_table *table,
				  unsigned long key,
				  hash_callback_t func)
{
	void *value;
	int ret;

	pthread_rwlock_rdlock(&table->lock);

	ret = drmHashLookup(table->table, key, &value);
	if (!ret && func)
		func(value);

	pthread_rwlock_unlock(&table->lock);

	return ret ? NULL : value;
}

static inline void *hash_lookup(struct locked_hash_table *table,
				unsigned long key)
{
	return hash_lookup_callback(table, key, NULL);
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

static void hash_destroy(struct locked_hash_table *table)
{
	drmHashDestroy(table->table);
}

/*
 * Dummy file descriptors
 */

struct fakedrm_file_desc {
	int fd;
	unsigned int refcnt;
	unsigned int g2d_pipes;
	unsigned int g3d_pipes;
	struct locked_hash_table bo_table;
	/* More to come */
};

static struct locked_hash_table file_table;

static void __file_get(struct fakedrm_file_desc *file)
{
	__sync_add_and_fetch(&file->refcnt, 1);
}

static void __file_put(struct fakedrm_file_desc *file)
{
	if (__sync_sub_and_fetch(&file->refcnt, 1) == 0) {
		hash_destroy(&file->bo_table);
		free(file);
	}
}

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

/*
 * Dummy map descriptors
 */

struct fakedrm_map_data {
	struct fakedrm_bo_handle *handle;
	void *addr;
	size_t length;
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

struct fakedrm_bo_handle {
	struct fakedrm_file_desc *file;
	struct fakedrm_bo_data *bo;
	int fd;
	uint32_t refcnt;
};

static sem_t *bo_sem;
static int bo_shm;
static void *bo_shm_mem;
static volatile uint32_t *bo_bitmap;
static uint32_t bo_bitmap_size;
static volatile struct fakedrm_bo_ctrl *bo_ctrl;

static int __bo_remap_bitmap(void)
{
	volatile uint32_t *new_bitmap;

	new_bitmap = mmap(NULL, bo_ctrl->bitmap_size * sizeof(*bo_bitmap),
				PROT_READ | PROT_WRITE, MAP_SHARED, bo_shm,
				FAKEDRM_BO_SHM_BITMAP_OFFSET);
	if (new_bitmap == MAP_FAILED) {
		ERROR_MSG("failed to (re)map BO bitmap: %s", strerror(errno));
		return -1;
	}

	munmap((void *)bo_bitmap, bo_bitmap_size * sizeof(*bo_bitmap));
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
	memset((void *)&bo_bitmap[old_size], 0xff, new_bytes - old_bytes);

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

static void __bo_get(struct fakedrm_bo_data *bo)
{
	__sync_add_and_fetch(&bo->refcnt, 1);
}

static void __bo_put(struct fakedrm_bo_data *bo)
{
	char pathname[] = "/fakedrm_bo.012345678";
	uint32_t name = bo->name;

	if (__sync_sub_and_fetch(&bo->refcnt, 1) == 0) {
		snprintf(pathname, sizeof(pathname), "/fakedrm_bo.%08x", name);
		shm_unlink(pathname);
		bo_put_name(name);
	}
}

#ifdef DEBUG_REFCNT
static void __bo_get_debug(struct fakedrm_bo_data *bo,
			   const char *func, int line)
{
	DEBUG_MSG("bo_get(%p) from %s():%d", bo, func, line);
	__bo_get(bo);
}
#define bo_get(bo)		__bo_get_debug(bo, __func__, __LINE__)

static void __bo_put_debug(struct fakedrm_bo_data *bo,
			   const char *func, int line)
{
	DEBUG_MSG("bo_put(%p) from %s():%d", bo, func, line);
	__bo_put(bo);
}
#define bo_put(bo)		__bo_put_debug(bo, __func__, __LINE__)
#else
#define bo_get		__bo_get
#define bo_put		__bo_put
#endif

static void __bo_handle_get(struct fakedrm_bo_handle *handle)
{
	if (__sync_add_and_fetch(&handle->refcnt, 1) == 1) {
		bo_get(handle->bo);
		file_get(handle->file);
	}
}

static void __bo_handle_put(struct fakedrm_bo_handle *handle)
{
	if (__sync_sub_and_fetch(&handle->refcnt, 1) == 0) {
		file_put(handle->file);
		bo_put(handle->bo);
		munmap_real(handle->bo, FAKEDRM_BO_SHM_HDR_LENGTH);
		if (!cleanup_in_progress)
			free(handle);
	}
}

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

static int bo_import(struct fakedrm_file_desc *file, uint32_t name,
		     uint32_t *out_handle, uint32_t *size)
{
	char pathname[] = "/fakedrm_bo.012345678";
	struct fakedrm_bo_handle *handle;
	sigset_t oldmask;
	int ret;

	handle = calloc(1, sizeof(*handle));
	if (!handle) {
		ERROR_MSG("failed to allocate BO handle data");
		return -ENOMEM;
	}
	handle->file = file;

	pthread_sigmask(SIG_BLOCK, &captured_signals, &oldmask);

	snprintf(pathname, sizeof(pathname), "/fakedrm_bo.%08x", name);
	handle->fd = shm_open(pathname, O_RDWR,
				S_IWUSR | S_IRUSR | S_IWGRP | S_IRGRP);
	if (handle->fd < 0) {
		ret = -errno;
		ERROR_MSG("failed to open BO SHM object: %s",
				strerror(errno));
		goto err_sigmask;
	}

	handle->bo = mmap_real(NULL, FAKEDRM_BO_SHM_HDR_LENGTH,
				PROT_READ | PROT_WRITE, MAP_SHARED,
				handle->fd, 0);
	if (handle->bo == MAP_FAILED) {
		ret = -errno;
		ERROR_MSG("failed to map BO SHM object header: %s",
				strerror(errno));
		goto err_shm;
	}

	*out_handle = handle->fd;
	*size = handle->bo->size;

	bo_handle_get(handle);
	hash_insert(&file->bo_table, handle->fd, handle);

	pthread_sigmask(SIG_SETMASK, &oldmask, NULL);

	return 0;

err_shm:
	close_real(handle->fd);
err_sigmask:
	pthread_sigmask(SIG_SETMASK, &oldmask, NULL);
	free(handle);

	return ret;
}

static int bo_export(struct fakedrm_file_desc *file, uint32_t handle,
		     uint32_t *name)
{
	struct fakedrm_bo_handle *handle_data;
	int ret = 0;

	handle_data = hash_lookup_callback(&file->bo_table, handle,
					(hash_callback_t)__bo_handle_get);
	if (!handle_data) {
		ERROR_MSG("failed to lookup BO handle %08x", handle);
		return -ENOENT;
	}

	*name = handle_data->bo->name;

	bo_handle_put(handle_data);

	return ret;
}

static int bo_create(struct fakedrm_file_desc *file, uint32_t size,
		     uint32_t *out_handle)
{
	char pathname[] = "/fakedrm_bo.012345678";
	struct fakedrm_bo_handle *handle;
	sigset_t oldmask;
	uint32_t name;
	int ret;

	handle = calloc(1, sizeof(*handle));
	if (!handle) {
		ERROR_MSG("failed to allocate BO handle data");
		return -ENOMEM;
	}
	handle->file = file;

	pthread_sigmask(SIG_BLOCK, &captured_signals, &oldmask);

	name = bo_get_name();
	if (!name) {
		ERROR_MSG("out of free handles");
		ret = -ENOMEM;
		goto err_sigmask;
	}

	snprintf(pathname, sizeof(pathname), "/fakedrm_bo.%08x", name);
	handle->fd = shm_open(pathname, O_RDWR | O_CREAT | O_EXCL,
				S_IWUSR | S_IRUSR | S_IWGRP | S_IRGRP);
	if (handle->fd < 0) {
		ret = -errno;
		ERROR_MSG("failed to create BO SHM object: %s",
				strerror(errno));
		goto err_handle;
	}

	ret = ftruncate(handle->fd, FAKEDRM_BO_SHM_HDR_LENGTH);
	if (ret) {
		ret = -errno;
		ERROR_MSG("failed to resize BO SHM object: %s",
				strerror(errno));
		goto err_close_unlink;
	}

	handle->bo = mmap(NULL, FAKEDRM_BO_SHM_HDR_LENGTH,
				PROT_READ | PROT_WRITE, MAP_SHARED,
				handle->fd, 0);
	if (handle->bo == MAP_FAILED) {
		ret = -errno;
		ERROR_MSG("failed to map BO SHM object header: %s",
				strerror(errno));
		goto err_close_unlink;
	}

	*out_handle = handle->fd;
	handle->bo->name = name;
	handle->bo->size = size;

	bo_handle_get(handle);
	hash_insert(&file->bo_table, handle->fd, handle);

	pthread_sigmask(SIG_SETMASK, &oldmask, NULL);

	return 0;

err_close_unlink:
	shm_unlink(pathname);
	close_real(handle->fd);
err_handle:
	bo_put_name(name);
err_sigmask:
	pthread_sigmask(SIG_SETMASK, &oldmask, NULL);
	free(handle);

	return ret;
}

static void bo_close(struct fakedrm_file_desc *file, uint32_t handle)
{
	struct fakedrm_bo_handle *handle_data;
	sigset_t oldmask;

	handle_data = hash_lookup(&file->bo_table, handle);
	if (!handle_data) {
		ERROR_MSG("failed to lookup BO handle %08x", handle);
		return;
	}

	pthread_sigmask(SIG_BLOCK, &captured_signals, &oldmask);

	hash_remove(&file->bo_table, handle);
	bo_handle_put(handle_data);
	close_real(handle_data->fd);
	handle_data->fd = -1;

	pthread_sigmask(SIG_SETMASK, &oldmask, NULL);
}

static int bo_map(struct fakedrm_file_desc *file, uint32_t handle,
		  void **out_addr)
{
	struct fakedrm_bo_handle *handle_data;
	struct fakedrm_map_data *map;
	sigset_t oldmask;
	void *addr = NULL;
	int ret;

	handle_data = hash_lookup_callback(&file->bo_table, handle,
					(hash_callback_t)__bo_handle_get);
	if (!handle_data) {
		ERROR_MSG("failed to lookup BO handle %08x", handle);
		return -ENOENT;
	}

	pthread_sigmask(SIG_BLOCK, &captured_signals, &oldmask);

	map = calloc(1, sizeof(*map));
	if (!map) {
		ERROR_MSG("failed to allocate map data");
		ret = -ENOMEM;
		goto err_sigmask;
	}

	ret = ftruncate(handle, FAKEDRM_BO_SHM_HDR_LENGTH
			+ handle_data->bo->size);
	if (ret) {
		ret = -errno;
		ERROR_MSG("failed to resize BO SHM object: %s",
				strerror(errno));
		goto err_data;
	}

	addr = mmap_real(NULL, handle_data->bo->size, PROT_READ | PROT_WRITE,
				MAP_SHARED, handle, FAKEDRM_BO_SHM_HDR_LENGTH);
	if (addr == MAP_FAILED) {
		ret = -errno;
		ERROR_MSG("failed to mmap BO: %s", strerror(errno));
		goto err_data;
	}

	map->handle = handle_data;
	map->addr = addr;
	map->length = handle_data->bo->size;
	hash_insert(&map_table, (unsigned long)addr, map);

	pthread_sigmask(SIG_SETMASK, &oldmask, NULL);

	*out_addr = addr;
	return 0;

err_data:
	free(map);
err_sigmask:
	pthread_sigmask(SIG_SETMASK, &oldmask, NULL);
	bo_handle_put(handle_data);

	return ret;
}

static int bo_unmap(void *addr, size_t length)
{
	struct fakedrm_map_data *map;
	sigset_t oldmask;

	map = hash_lookup(&map_table, (unsigned long)addr);
	if (!map)
		return -ENOENT;

	pthread_sigmask(SIG_BLOCK, &captured_signals, &oldmask);

	hash_remove(&map_table, (unsigned long)map->addr);
	bo_handle_put(map->handle);
	munmap_real(map->addr, map->length);
	free(map);

	pthread_sigmask(SIG_SETMASK, &oldmask, NULL);

	return 0;
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

static int dummy_gem_open(struct fakedrm_file_desc *file, void *arg)
{
	struct drm_gem_open *req = arg;
	uint32_t size;
	int ret;

	ret = bo_import(file, req->name, &req->handle, &size);
	req->size = size;

	return ret;
}

static int dummy_gem_close(struct fakedrm_file_desc *file, void *arg)
{
	struct drm_gem_close *req = arg;

	bo_close(file, req->handle);

	return 0;
}

static int dummy_gem_flink(struct fakedrm_file_desc *file, void *arg)
{
	struct drm_gem_flink *req = arg;

	return bo_export(file, req->handle, &req->name);
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
	struct fakedrm_bo_handle *handle_data;

	handle_data = hash_lookup(&file->bo_table, req->handle);
	if (!handle_data) {
		ERROR_MSG("failed to lookup BO handle %08x", req->handle);
		return -ENOENT;
	}

	req->offset = req->handle * 4096;

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

/*
 * Implementation of file operations for emulated DRM devices
 */
static int file_open(const char *pathname, int flags, mode_t mode)
{
	struct fakedrm_file_desc *file;
	sigset_t oldmask;
	int fd;

	pthread_sigmask(SIG_BLOCK, &captured_signals, &oldmask);

	fd = open_real("/dev/null", O_RDWR, 0);
	if (!fd) {
		ERROR_MSG("failed to open '/dev/null': %s",
			strerror(errno));
		goto err_sigmask;
	}

	file = calloc(1, sizeof(*file));
	if (!file) {
		ERROR_MSG("failed to allocate file descriptor");
		errno = ENOMEM;
		goto err_close;
	}

	hash_create(&file->bo_table);
	file->fd = fd;

	file_get(file);
	hash_insert(&file_table, fd, file);

	pthread_sigmask(SIG_SETMASK, &oldmask, NULL);

	return fd;

err_close:
	close_real(fd);
err_sigmask:
	pthread_sigmask(SIG_SETMASK, &oldmask, NULL);

	return -1;
}

static void __file_close(struct fakedrm_file_desc *file)
{
	unsigned long key;
	void *value;
	int ret;

	ret = drmHashFirst(file->bo_table.table, &key, &value);
	while (ret) {
		struct fakedrm_bo_handle *handle = value;

		bo_handle_put(handle);

		ret = drmHashNext(file->bo_table.table, &key, &value);
	}
}

static void file_close(struct fakedrm_file_desc *file)
{
	sigset_t oldmask;

	pthread_sigmask(SIG_BLOCK, &captured_signals, &oldmask);

	hash_remove(&file_table, file->fd);
	__file_close(file);
	close_real(file->fd);
	file->fd = -1;
	file_put(file);

	pthread_sigmask(SIG_SETMASK, &oldmask, NULL);
}

static int file_ioctl(struct fakedrm_file_desc *file, unsigned long request,
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
		ret = dummy_gem_open(file, arg);
		break;
	case DRM_IOCTL_GEM_CLOSE:
		ret = dummy_gem_close(file, arg);
		break;
	case DRM_IOCTL_GEM_FLINK:
		ret = dummy_gem_flink(file, arg);
		break;

	/* Exynos-specific GEM IOCTLs */
	case CMD_IOCTL_DRM_EXYNOS_GEM_CREATE:
		ret = dummy_cmd_exynos_gem_create(file, arg);
		break;
	case CMD_IOCTL_DRM_EXYNOS_GEM_MMAP:
		ret = dummy_cmd_exynos_gem_mmap(file, arg);
		break;
	case CMD_IOCTL_DRM_EXYNOS_GEM_MAP_OFFSET:
		ret = dummy_cmd_exynos_gem_map_offset(file, arg);
		break;

	/* Exynos-specific pipe IOCTLs */
	case CMD_IOCTL_DRM_EXYNOS_G3D_CREATE_PIPE:
		ret = dummy_cmd_exynos_g3d_create_pipe(file, arg);
		break;
	case CMD_IOCTL_DRM_EXYNOS_G2D_CREATE_PIPE:
		ret = dummy_cmd_exynos_g2d_create_pipe(file, arg);
		break;
	case CMD_IOCTL_DRM_EXYNOS_G3D_DESTROY_PIPE:
		ret = dummy_cmd_exynos_g3d_destroy_pipe(file, arg);
		break;

	case CMD_IOCTL_DRM_EXYNOS_G2D_DESTROY_PIPE:
		ret = dummy_cmd_exynos_g2d_destroy_pipe(file, arg);
		break;
	case CMD_IOCTL_DRM_EXYNOS_G3D_SUBMIT:
		ret = dummy_cmd_exynos_g3d_submit(file, arg);
		break;
	case CMD_IOCTL_DRM_EXYNOS_G2D_SUBMIT:
		ret = dummy_cmd_exynos_g2d_submit(file, arg);
		break;

	case CMD_IOCTL_DRM_EXYNOS_G3D_WAIT:
		ret = dummy_cmd_exynos_g3d_wait(file, arg);
		break;
	case CMD_IOCTL_DRM_EXYNOS_G3D_CPU_PREP:
		ret = dummy_cmd_exynos_g3d_cpu_prep(file, arg);
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

static void *file_mmap(struct fakedrm_file_desc *file, void *addr,
		       size_t length, int prot, int flags, off_t offset)
{
	void *out_addr = NULL;
	uint32_t handle;
	int ret;

	if (offset % 4096)
		return MAP_FAILED;

	handle = offset / 4096;
	if (!handle)
		return MAP_FAILED;

	ret = bo_map(file, handle, &out_addr);
	if (ret)
		return MAP_FAILED;

	return out_addr;
}

static int file_fstat(struct fakedrm_file_desc *file, int ver, struct stat *buf)
{
	/* TODO: Fake stat info */
	return __fxstat_real(ver, file->fd, buf);
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

	VERBOSE_MSG("%s(pathname = '%s', flags = %d, mode = %x)",
		__func__, pathname, flags, mode);

	if (!strcmp(pathname, "/dev/dri/card0"))
		return file_open(pathname, flags, mode);

	return open_real(pathname, flags, mode);
}

PUBLIC int close(int fd)
{
	struct fakedrm_file_desc *file;

	VERBOSE_MSG("%s(fd = %d)", __func__, fd);

	file = hash_lookup(&file_table, fd);
	if (file)
		file_close(file);

	return close_real(fd);
}

PUBLIC int ioctl(int d, unsigned long request, ...)
{
	unsigned dir = _IOC_DIR(request);
	struct fakedrm_file_desc *file;
	char *argp = NULL;
	va_list args;

	if (dir != _IOC_NONE) {
		va_start(args, request);
		argp = va_arg(args, char *);
		va_end(args);
	}

	VERBOSE_MSG("%s(d = %d, request = %lx, argp = %p)",
		__func__, d, request, argp);

	if (_IOC_TYPE(request) == DRM_IOCTL_BASE) {
		file = hash_lookup(&file_table, d);
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

	file = hash_lookup(&file_table, fd);
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

	file = hash_lookup(&file_table, fd);
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
	unsigned long key;
	void *value;
	int ret;

	DEBUG_MSG("cleaning up open handles...");

	ret = drmHashFirst(file_table.table, &key, &value);
	while (ret) {
		struct fakedrm_file_desc *file = value;

		__file_close(file);

		ret = drmHashNext(file_table.table, &key, &value);
	}

	DEBUG_MSG("cleaning up open BO mappings...");

	ret = drmHashFirst(map_table.table, &key, &value);
	while (ret) {
		struct fakedrm_map_data *map = value;

		bo_handle_put(map->handle);

		ret = drmHashNext(map_table.table, &key, &value);
	}
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
	int ret;

	open_real = lookup_symbol("open");
	close_real = lookup_symbol("close");
	ioctl_real = lookup_symbol("ioctl");
	mmap_real = lookup_symbol("mmap");
	munmap_real = lookup_symbol("munmap");
	__fxstat_real = lookup_symbol("__fxstat");
	__xstat_real = lookup_symbol("__xstat");

	hash_create(&file_table);
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

	sigemptyset(&captured_signals);
	sigaddset(&captured_signals, SIGINT);
	sigaddset(&captured_signals, SIGSEGV);
	sigaddset(&captured_signals, SIGABRT);
	sigaddset(&captured_signals, SIGTRAP);

	signal(SIGINT, signal_handler);
	signal(SIGSEGV, signal_handler);
	signal(SIGABRT, signal_handler);
	signal(SIGTRAP, signal_handler);
}
