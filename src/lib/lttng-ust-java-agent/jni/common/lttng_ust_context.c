/*
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Copyright (C) 2016 EfficiOS Inc.
 * Copyright (C) 2016 Alexandre Montplaisir <alexmonthy@efficios.com>
 * Copyright (C) 2016 Mathieu Desnoyers <mathieu.desnoyers@efficios.com>
 */

#include "org_lttng_ust_agent_context_LttngContextApi.h"

#include <string.h>
#include <inttypes.h>
#include <lttng/ust-events.h>
#include <lttng/ust-ringbuffer-context.h>
#include <common/ust-context-provider.h>

#include "common/macros.h"
#include "lttng_ust_context.h"

enum lttng_ust_jni_type {
	JNI_TYPE_NULL = 0,
	JNI_TYPE_INTEGER = 1,
	JNI_TYPE_LONG = 2,
	JNI_TYPE_DOUBLE = 3,
	JNI_TYPE_FLOAT = 4,
	JNI_TYPE_BYTE = 5,
	JNI_TYPE_SHORT = 6,
	JNI_TYPE_BOOLEAN = 7,
	JNI_TYPE_STRING = 8,
};

struct lttng_ust_jni_ctx_entry {
	int32_t context_name_offset;
	char type;	/* enum lttng_ust_jni_type */
	union {
		int32_t _integer;
		int64_t _long;
		double _double;
		float _float;
		signed char _byte;
		int16_t _short;
		signed char _boolean;
		int32_t _string_offset;
	} value;
} __attribute__((packed));

struct lttng_ust_jni_provider {
	struct lttng_ust_registered_context_provider *reg_provider;
	char *name;
	struct lttng_ust_context_provider provider;
};

/* TLS passing context info from JNI to callbacks. */
__thread struct lttng_ust_jni_tls lttng_ust_context_info_tls;

static const char *get_ctx_string_at_offset(int32_t offset)
{
	signed char *ctx_strings_array = lttng_ust_context_info_tls.ctx_strings;

	if (offset < 0 || offset >= lttng_ust_context_info_tls.ctx_strings_len) {
		return NULL;
	}
	return (const char *) (ctx_strings_array + offset);
}

static struct lttng_ust_jni_ctx_entry *lookup_ctx_by_name(const char *ctx_name)
{
	struct lttng_ust_jni_ctx_entry *ctx_entries_array = lttng_ust_context_info_tls.ctx_entries;
	int i, len = lttng_ust_context_info_tls.ctx_entries_len / sizeof(struct lttng_ust_jni_ctx_entry);

	for (i = 0; i < len; i++) {
		int32_t offset = ctx_entries_array[i].context_name_offset;
		const char *string = get_ctx_string_at_offset(offset);

		if (string && strcmp(string, ctx_name) == 0) {
			return &ctx_entries_array[i];
		}
	}
	return NULL;
}

static size_t get_size_cb(void *priv, struct lttng_ust_probe_ctx *probe_ctx __attribute__((unused)),
		size_t offset)
{
	const struct lttng_ust_app_context *app_ctx = (const struct lttng_ust_app_context *) priv;
	const char *ctx_name = app_ctx->ctx_name;
	struct lttng_ust_jni_ctx_entry *jctx;
	size_t size = 0;
	enum lttng_ust_jni_type jni_type;

	size += lttng_ust_ring_buffer_align(offset, lttng_ust_rb_alignof(char));
	size += sizeof(char);		/* tag */
	jctx = lookup_ctx_by_name(ctx_name);
	if (!jctx) {
		jni_type = JNI_TYPE_NULL;
	} else {
		jni_type = jctx->type;
	}
	switch (jni_type) {
	case JNI_TYPE_NULL:
		break;
	case JNI_TYPE_INTEGER:
		size += lttng_ust_ring_buffer_align(offset, lttng_ust_rb_alignof(int32_t));
		size += sizeof(int32_t);	/* variant */
		break;
	case JNI_TYPE_LONG:
		size += lttng_ust_ring_buffer_align(offset, lttng_ust_rb_alignof(int64_t));
		size += sizeof(int64_t);	/* variant */
		break;
	case JNI_TYPE_DOUBLE:
		size += lttng_ust_ring_buffer_align(offset, lttng_ust_rb_alignof(double));
		size += sizeof(double);		/* variant */
		break;
	case JNI_TYPE_FLOAT:
		size += lttng_ust_ring_buffer_align(offset, lttng_ust_rb_alignof(float));
		size += sizeof(float);		/* variant */
		break;
	case JNI_TYPE_SHORT:
		size += lttng_ust_ring_buffer_align(offset, lttng_ust_rb_alignof(int16_t));
		size += sizeof(int16_t);	/* variant */
		break;
	case JNI_TYPE_BYTE:		/* Fall-through. */
	case JNI_TYPE_BOOLEAN:
		size += lttng_ust_ring_buffer_align(offset, lttng_ust_rb_alignof(char));
		size += sizeof(char);		/* variant */
		break;
	case JNI_TYPE_STRING:
	{
		/* The value is an offset, the string is in the "strings" array */
		int32_t string_offset = jctx->value._string_offset;
		const char *string = get_ctx_string_at_offset(string_offset);

		if (string) {
			size += strlen(string) + 1;
		}
		break;
	}
	default:
		abort();
	}
	return size;

}

static void record_cb(void *priv,
		 struct lttng_ust_probe_ctx *probe_ctx __attribute__((unused)),
		 struct lttng_ust_ring_buffer_ctx *ctx,
		 struct lttng_ust_channel_buffer *lttng_chan_buf)
{
	const struct lttng_ust_app_context *app_ctx = (const struct lttng_ust_app_context *) priv;
	const char *ctx_name = app_ctx->ctx_name;
	struct lttng_ust_jni_ctx_entry *jctx;
	enum lttng_ust_jni_type jni_type;
	char sel_char;

	jctx = lookup_ctx_by_name(ctx_name);
	if (!jctx) {
		jni_type = JNI_TYPE_NULL;
	} else {
		jni_type = jctx->type;
	}

	switch (jni_type) {
	case JNI_TYPE_NULL:
		sel_char = LTTNG_UST_DYNAMIC_TYPE_NONE;
		lttng_chan_buf->ops->event_write(ctx, &sel_char, sizeof(sel_char), lttng_ust_rb_alignof(char));
		break;
	case JNI_TYPE_INTEGER:
	{
		int32_t v = jctx->value._integer;

		sel_char = LTTNG_UST_DYNAMIC_TYPE_S32;
		lttng_chan_buf->ops->event_write(ctx, &sel_char, sizeof(sel_char), lttng_ust_rb_alignof(char));
		lttng_chan_buf->ops->event_write(ctx, &v, sizeof(v), lttng_ust_rb_alignof(v));
		break;
	}
	case JNI_TYPE_LONG:
	{
		int64_t v = jctx->value._long;

		sel_char = LTTNG_UST_DYNAMIC_TYPE_S64;
		lttng_chan_buf->ops->event_write(ctx, &sel_char, sizeof(sel_char), lttng_ust_rb_alignof(char));
		lttng_chan_buf->ops->event_write(ctx, &v, sizeof(v), lttng_ust_rb_alignof(v));
		break;
	}
	case JNI_TYPE_DOUBLE:
	{
		double v = jctx->value._double;

		sel_char = LTTNG_UST_DYNAMIC_TYPE_DOUBLE;
		lttng_chan_buf->ops->event_write(ctx, &sel_char, sizeof(sel_char), lttng_ust_rb_alignof(char));
		lttng_chan_buf->ops->event_write(ctx, &v, sizeof(v), lttng_ust_rb_alignof(v));
		break;
	}
	case JNI_TYPE_FLOAT:
	{
		float v = jctx->value._float;

		sel_char = LTTNG_UST_DYNAMIC_TYPE_FLOAT;
		lttng_chan_buf->ops->event_write(ctx, &sel_char, sizeof(sel_char), lttng_ust_rb_alignof(char));
		lttng_chan_buf->ops->event_write(ctx, &v, sizeof(v), lttng_ust_rb_alignof(v));
		break;
	}
	case JNI_TYPE_SHORT:
	{
		int16_t v = jctx->value._short;

		sel_char = LTTNG_UST_DYNAMIC_TYPE_S16;
		lttng_chan_buf->ops->event_write(ctx, &sel_char, sizeof(sel_char), lttng_ust_rb_alignof(char));
		lttng_chan_buf->ops->event_write(ctx, &v, sizeof(v), lttng_ust_rb_alignof(v));
		break;
	}
	case JNI_TYPE_BYTE:
	{
		char v = jctx->value._byte;

		sel_char = LTTNG_UST_DYNAMIC_TYPE_S8;
		lttng_chan_buf->ops->event_write(ctx, &sel_char, sizeof(sel_char), lttng_ust_rb_alignof(char));
		lttng_chan_buf->ops->event_write(ctx, &v, sizeof(v), lttng_ust_rb_alignof(v));
		break;
	}
	case JNI_TYPE_BOOLEAN:
	{
		char v = jctx->value._boolean;

		sel_char = LTTNG_UST_DYNAMIC_TYPE_S8;
		lttng_chan_buf->ops->event_write(ctx, &sel_char, sizeof(sel_char), lttng_ust_rb_alignof(char));
		lttng_chan_buf->ops->event_write(ctx, &v, sizeof(v), lttng_ust_rb_alignof(v));
		break;
	}
	case JNI_TYPE_STRING:
	{
			int32_t offset = jctx->value._string_offset;
			const char *str = get_ctx_string_at_offset(offset);

			if (str) {
				sel_char = LTTNG_UST_DYNAMIC_TYPE_STRING;
			} else {
				sel_char = LTTNG_UST_DYNAMIC_TYPE_NONE;
			}
			lttng_chan_buf->ops->event_write(ctx, &sel_char, sizeof(sel_char), lttng_ust_rb_alignof(char));
			if (str) {
				lttng_chan_buf->ops->event_write(ctx, str, strlen(str) + 1, 1);
			}
			break;
	}
	default:
		abort();
	}
}

static void get_value_cb(void *priv, struct lttng_ust_probe_ctx *probe_ctx __attribute__((unused)),
		struct lttng_ust_ctx_value *value)
{
	const struct lttng_ust_app_context *app_ctx = (const struct lttng_ust_app_context *) priv;
	const char *ctx_name = app_ctx->ctx_name;
	struct lttng_ust_jni_ctx_entry *jctx;
	enum lttng_ust_jni_type jni_type;

	jctx = lookup_ctx_by_name(ctx_name);
	if (!jctx) {
		jni_type = JNI_TYPE_NULL;
	} else {
		jni_type = jctx->type;
	}

	switch (jni_type) {
	case JNI_TYPE_NULL:
		value->sel = LTTNG_UST_DYNAMIC_TYPE_NONE;
		break;
	case JNI_TYPE_INTEGER:
		value->sel = LTTNG_UST_DYNAMIC_TYPE_S64;
		value->u.s64 = (int64_t) jctx->value._integer;
		break;
	case JNI_TYPE_LONG:
		value->sel = LTTNG_UST_DYNAMIC_TYPE_S64;
		value->u.s64 = jctx->value._long;
		break;
	case JNI_TYPE_DOUBLE:
		value->sel = LTTNG_UST_DYNAMIC_TYPE_DOUBLE;
		value->u.d = jctx->value._double;
		break;
	case JNI_TYPE_FLOAT:
		value->sel = LTTNG_UST_DYNAMIC_TYPE_DOUBLE;
		value->u.d = (double) jctx->value._float;
		break;
	case JNI_TYPE_SHORT:
		value->sel = LTTNG_UST_DYNAMIC_TYPE_S64;
		value->u.s64 = (int64_t) jctx->value._short;
		break;
	case JNI_TYPE_BYTE:
		value->sel = LTTNG_UST_DYNAMIC_TYPE_S64;
		value->u.s64 = (int64_t) jctx->value._byte;
		break;
	case JNI_TYPE_BOOLEAN:
		value->sel = LTTNG_UST_DYNAMIC_TYPE_S64;
		value->u.s64 = (int64_t) jctx->value._boolean;
		break;
	case JNI_TYPE_STRING:
	{
		int32_t offset = jctx->value._string_offset;
		const char *str = get_ctx_string_at_offset(offset);

		if (str) {
			value->sel = LTTNG_UST_DYNAMIC_TYPE_STRING;
			value->u.str = str;
		} else {
			value->sel = LTTNG_UST_DYNAMIC_TYPE_NONE;
		}
		break;
	}
	default:
		abort();
	}
}

/*
 * Register a context provider to UST.
 *
 * Called from the Java side when an application registers a context retriever,
 * so we create and register a corresponding provider on the C side.
 */
JNIEXPORT jlong JNICALL Java_org_lttng_ust_agent_context_LttngContextApi_registerProvider(JNIEnv *env,
						jobject jobj __attribute__((unused)),
						jstring provider_name)
{
	jboolean iscopy;
	const char *provider_name_jstr;
	char *provider_name_cstr;
	struct lttng_ust_context_provider *provider;
	struct lttng_ust_jni_provider *jni_provider;
	/*
	 * Note: a "jlong" is 8 bytes on all architectures, whereas a
	 * C "long" varies.
	 */
	jlong provider_ref;

	provider_name_jstr = (*env)->GetStringUTFChars(env, provider_name, &iscopy);
	if (!provider_name_jstr) {
		goto error_jstr;
	}
	/* Keep our own copy of the string so UST can use it. */
	provider_name_cstr = strdup(provider_name_jstr);
	(*env)->ReleaseStringUTFChars(env, provider_name, provider_name_jstr);
	if (!provider_name_cstr) {
		goto error_strdup;
	}
	jni_provider = zmalloc(sizeof(*jni_provider));
	if (!jni_provider) {
		goto error_provider;
	}
	provider = &jni_provider->provider;
	provider->struct_size = sizeof(*provider);
	jni_provider->name = provider_name_cstr;
	provider->name = jni_provider->name;
	provider->get_size = get_size_cb;
	provider->record = record_cb;
	provider->get_value = get_value_cb;
	provider->priv = jni_provider;

	jni_provider->reg_provider = lttng_ust_context_provider_register(provider);
	if (!jni_provider->reg_provider) {
		goto error_register;
	}

	provider_ref = (jlong) (long) jni_provider;
	return provider_ref;

	/* Error handling. */
error_register:
	free(jni_provider);
error_provider:
	free(provider_name_cstr);
error_strdup:
error_jstr:
	return 0;
}

/*
 * Unregister a previously-registered context provider.
 *
 * Called from the Java side when an application unregisters a context retriever,
 * so we unregister and delete the corresponding provider on the C side.
 */
JNIEXPORT void JNICALL Java_org_lttng_ust_agent_context_LttngContextApi_unregisterProvider(JNIEnv *env __attribute__((unused)),
						jobject jobj __attribute__((unused)),
						jlong provider_ref)
{
	struct lttng_ust_jni_provider *jni_provider =
			(struct lttng_ust_jni_provider *) (unsigned long) provider_ref;

	if (!jni_provider) {
		return;
	}

	lttng_ust_context_provider_unregister(jni_provider->reg_provider);

	free(jni_provider->name);
	free(jni_provider);
}
