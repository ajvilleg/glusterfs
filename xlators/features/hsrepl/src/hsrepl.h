/*
 * Copyright (c) 2012 Red Hat <http://www.redhat.com>
 *
 * This file is part of GlusterFS.
 *
 * GlusterFS is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or (at your option)
 * any later version.
 *
 * GlusterFS is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __HSREPL_H__
#define __HSREPL_H__

#ifndef _CONFIG_H
#define _CONFIG_H
#include "config.h"
#endif
#include "mem-types.h"

/* Deal with casts for 32-bit architectures. */
#define CAST2INT(x) ((uint64_t)(long)(x))
#define CAST2PTR(x) ((void *)(long)(x))

typedef struct {
        gf_lock_t               lock;
        call_pool_t             pool;
        event_notify_fn_t       real_notify;
        uint16_t                up_count;
        gf_boolean_t            up[2];
} hsrepl_private_t;

typedef struct {
        uint32_t         versions[2];
} hsrepl_ctx_t;

typedef struct {
        uint16_t         calls;
        uint16_t         errors;
        uint16_t         conflicts;
        fd_t            *fd;
        struct iovec     vector[10];
        int32_t          count;
        off_t            off;
        uint32_t         flags;
        struct iobref   *iobref;
        hsrepl_ctx_t    *ctx;
        uint32_t         incrs[2];
        uint32_t         good_op_ret;
        uint32_t         good_op_errno;
        struct iatt      good_prebuf;
        struct iatt      good_postbuf;
        uint16_t         up_children;
} hsrepl_local_t;

enum gf_hsrepl_mem_types_ {
        gf_hsrepl_mt_priv_t = gf_common_mt_end + 1,
        gf_hsrepl_mt_ctx_t,
        gf_hsrepl_mt_int32_t,
        gf_hsrepl_mt_end
};

#endif /* __HSREPL_H__ */
