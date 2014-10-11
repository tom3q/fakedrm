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

#include <errno.h>
#include <fcntl.h>
#include <semaphore.h>
#include <signal.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <xf86drm.h>

#include "file.h"
#include "gem.h"
#include "utils.h"

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

void __bo_handle_put(struct fakedrm_bo_handle *handle)
{
	if (__sync_sub_and_fetch(&handle->refcnt, 1) == 0) {
		file_put(handle->file);
		bo_put(handle->bo);
		munmap_real(handle->bo, FAKEDRM_BO_SHM_HDR_LENGTH);
		if (!cleanup_in_progress)
			free(handle);
	}
}

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

int bo_create(struct fakedrm_file_desc *file, uint32_t size,
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

int bo_map(struct fakedrm_file_desc *file, uint32_t handle, void **out_addr)
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

int bo_unmap(void *addr, size_t length)
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

int bo_map_offset(struct fakedrm_file_desc *file,
		  uint32_t handle, uint64_t *offset)
{
	struct fakedrm_bo_handle *handle_data;

	handle_data = hash_lookup(&file->bo_table, handle);
	if (!handle_data) {
		ERROR_MSG("failed to lookup BO handle %08x", handle);
		return -ENOENT;
	}

	*offset = handle * 4096;
	return 0;
}

/*
 * Generic GEM IOCTLs
 */

int dummy_gem_open(struct fakedrm_file_desc *file, void *arg)
{
	struct drm_gem_open *req = arg;
	uint32_t size;
	int ret;

	ret = bo_import(file, req->name, &req->handle, &size);
	req->size = size;

	return ret;
}

int dummy_gem_close(struct fakedrm_file_desc *file, void *arg)
{
	struct drm_gem_close *req = arg;

	bo_close(file, req->handle);

	return 0;
}

int dummy_gem_flink(struct fakedrm_file_desc *file, void *arg)
{
	struct drm_gem_flink *req = arg;

	return bo_export(file, req->handle, &req->name);
}

/* Init/clean-up */

void bo_init(void)
{
	int ret;

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
}

void bo_cleanup(void)
{
	unsigned long key;
	void *value;
	int ret;

	ret = drmHashFirst(map_table.table, &key, &value);
	while (ret) {
		struct fakedrm_map_data *map = value;

		bo_handle_put(map->handle);

		ret = drmHashNext(map_table.table, &key, &value);
	}
}
