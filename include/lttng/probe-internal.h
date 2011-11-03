#ifndef _UST_PROBE_H
#define _UST_PROBE_H

/*
 * Copyright (C) 2009 Pierre-Marc Fournier
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA
 *
 */

/* Maximum number of callbacks per marker */
#define LTT_NR_CALLBACKS        10

struct ltt_serialize_closure;
struct ust_buffer;

typedef size_t (*ltt_serialize_cb)(struct ust_buffer *buf, size_t buf_offset,
                        struct ltt_serialize_closure *closure,
                        void *serialize_private,
			unsigned int stack_pos_ctx,
			int *largest_align,
                        const char *fmt, va_list *args);

struct ltt_available_probe {
        const char *name;               /* probe name */
        const char *format;
        ust_marker_probe_func *probe_func;
        ltt_serialize_cb callbacks[LTT_NR_CALLBACKS];
        struct cds_list_head node;          /* registered probes list */
};

extern int ltt_probe_register(struct ltt_available_probe *pdata); 
extern int ltt_probe_unregister(struct ltt_available_probe *pdata); 
extern int ltt_ust_marker_connect(const char *channel, const char *mname, 
                const char *pname); 
extern int ltt_ust_marker_disconnect(const char *channel, const char *mname, 
                const char *pname);

#endif /* _UST_PROBE_H */
