/*
 * Userspace DRM emulation library - KMS API support
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
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <xf86drmMode.h>
#include <xf86drm.h>

#include "kms.h"
#include "gem.h"
#include "utils.h"

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

/* Mode setting IOCTLs */

int dummy_mode_getresources(void *arg)
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

int dummy_mode_getcrtc(void *arg)
{
	struct drm_mode_crtc *crtc_resp = arg;

	if (!crtc_resp->crtc_id
	    || crtc_resp->crtc_id > ARRAY_SIZE(crtcs))
		return -ENOENT;

	memcpy(crtc_resp, &crtcs[crtc_resp->crtc_id - 1], sizeof(*crtc_resp));
	return 0;
}

int dummy_mode_setcrtc(void *arg)
{
	/* TODO */
	return 0;
}

int dummy_mode_getencoder(void *arg)
{
	struct drm_mode_get_encoder *enc_resp = arg;

	if (!enc_resp->encoder_id
	    || enc_resp->encoder_id > ARRAY_SIZE(encoders))
		return -ENOENT;

	memcpy(enc_resp, &encoders[enc_resp->encoder_id - 1],
		sizeof(*enc_resp));
	return 0;
}

int dummy_mode_getconnector(void *arg)
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

int dummy_mode_addfb(void *arg)
{
	/* TODO */
	return 0;
}

int dummy_mode_rmfb(void *arg)
{
	/* TODO */
	return 0;
}

int dummy_mode_page_flip(void *arg)
{
	/* TODO */
	return 0;
}

int dummy_mode_map_dumb(struct fakedrm_file_desc *file, void *arg)
{
	struct drm_mode_map_dumb *req = arg;
	uint64_t offset;
	int ret;

	ret = bo_map_offset(file, req->handle, &offset);
	if (ret)
		return ret;

	req->offset = offset;
	return 0;
}
