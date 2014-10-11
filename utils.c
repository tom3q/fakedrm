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

#include <pthread.h>
#include <unistd.h>
#include <xf86drm.h>

#include "utils.h"

/*
 * Synchronized hash table (wrappers for drmHash*)
 */

void hash_insert(struct locked_hash_table *table,
		 unsigned long key, void *value)
{
	pthread_rwlock_wrlock(&table->lock);
	drmHashInsert(table->table, key, value);
	pthread_rwlock_unlock(&table->lock);
}

void *hash_lookup_callback(struct locked_hash_table *table,
			   unsigned long key, hash_callback_t func)
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

void hash_remove(struct locked_hash_table *table, unsigned long key)
{
	pthread_rwlock_wrlock(&table->lock);
	drmHashDelete(table->table, key);
	pthread_rwlock_unlock(&table->lock);
}

void hash_create(struct locked_hash_table *table)
{
	pthread_rwlock_init(&table->lock, NULL);
	table->table = drmHashCreate();
	if (!table->table) {
		ERROR_MSG("failed to create hash table");
		exit(1);
	}
}

void hash_destroy(struct locked_hash_table *table)
{
	drmHashDestroy(table->table);
}
