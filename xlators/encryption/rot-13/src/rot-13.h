/*
   Copyright (c) 2006-2011 Gluster, Inc. <http://www.gluster.com>
   This file is part of GlusterFS.

   GlusterFS is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published
   by the Free Software Foundation; either version 3 of the License,
   or (at your option) any later version.

   GlusterFS is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see
   <http://www.gnu.org/licenses/>.
*/

#ifndef __ROT_13_H__
#define __ROT_13_H__

#ifndef _CONFIG_H
#define _CONFIG_H
#include "config.h"
#endif

#include "uuid.h"

#include <sqlite3.h>

#define MAX_REPLICAS 3
#define I_AM_CLIENT(p) (p->vc_index == 0)

typedef struct {
        uuid_t   node;  /* 16 bytes */
        uint64_t clock; /*  8 bytes */
} vc_element;           /* 24 bytes */

typedef struct {
        vc_element      elems[MAX_REPLICAS+1];  /*  96 bytes */
} vector_clock;

typedef struct {
        uint32_t      vc_index;
        vector_clock  vc;
        call_pool_t   pool;
        sqlite3      *db;
        sqlite3_stmt *sql_log_cmd;
        gf_boolean_t  logging;
} rot_13_private_t;

#endif /* __ROT_13_H__ */
