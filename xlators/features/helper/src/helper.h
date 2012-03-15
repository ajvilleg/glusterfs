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

#ifndef __HELPER_H__
#define __HELPER_H__

#ifndef _CONFIG_H
#define _CONFIG_H
#include "config.h"
#endif
#include "mem-types.h"

/* Deal with casts for 32-bit architectures. */
#define CAST2INT(x) ((uint64_t)(long)(x))
#define CAST2PTR(x) ((void *)(long)(x))

typedef struct {
        char            *partner_xattr;
        call_pool_t      pool;
} helper_private_t;

typedef struct {
        uint32_t         version;
        void            *trans;
} helper_ctx_t;

typedef struct {
        int32_t          real_op_ret;
        int32_t          real_op_errno;
        uint32_t         version;
} helper_local_t;

enum gf_helper_mem_types_ {
        gf_helper_mt_priv_t = gf_common_mt_end + 1,
        gf_helper_mt_ctx_t,
        gf_by_mt_int32_t,
        gf_helper_mt_end
};

#endif /* __HELPER_H__ */
