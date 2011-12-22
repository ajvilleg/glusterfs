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

#include <ctype.h>
#include <sys/uio.h>

#ifndef _CONFIG_H
#define _CONFIG_H
#include "config.h"
#endif

#include "glusterfs.h"
#include "xlator.h"
#include "logging.h"

#include "rot-13.h"

/*
 * This is a rot13 ``encryption'' xlator. It rot13's data when
 * writing to disk and rot13's it back when reading it.
 * This xlator is meant as an example, NOT FOR PRODUCTION
 * USE ;) (hence no error-checking)
 */

void
xd_iterator (dict_t *this, char *key, data_t *value, void *xl_name)
{
        if (!strcmp(key,"vector-clock")) {
                /* Handled elsewhere. */
                return;
        }
        gf_log(xl_name,GF_LOG_DEBUG,"key %s = value %s",
               key,data_to_str(value));
}

int32_t
rot13_writev_cbk (call_frame_t *frame,
                  void *cookie,
                  xlator_t *this,
                  int32_t op_ret,
                  int32_t op_errno,
                  struct iatt *prebuf,
		  struct iatt *postbuf,
                  uint32_t flags)
{
	STACK_UNWIND_STRICT (writev, frame, op_ret, op_errno,
                             prebuf, postbuf, flags);
	return 0;
}

int32_t
rot13_release_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                   int32_t op_ret, int32_t op_errno, struct iatt *buf)
{
        gf_log(this->name,GF_LOG_DEBUG,"got to %s",__func__);
        STACK_DESTROY(frame->root);
        return 0;
}

/*
 * This is called on the client side when we've converted a writev into a
 * writevxd, and converts it back.
 */
int32_t
rot13_writevxd_client_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
			   int32_t op_ret, int32_t op_errno,
			   struct iatt *prebuf, struct iatt *postbuf,
			   uint32_t flags, dict_t *dict)
{
	rot_13_private_t *priv = (rot_13_private_t *)this->private;
        data_t *data = NULL;
        uint32_t i = 0;
        vector_clock *vc = NULL;
        call_frame_t *newframe = NULL;

        if (dict) {
                dict_foreach(dict,xd_iterator,this->name);
                data = dict_get(dict,"vector-clock");
        }
        if (!data) {
                gf_log(this->name,GF_LOG_ERROR,"missing data for XD write");
                goto err;
        }

        vc = (vector_clock *)(data->data);
        /* TBD: convert from network byte order. */
        for (i = 0; i <= MAX_REPLICAS; ++i) {
                gf_log(this->name, GF_LOG_DEBUG, "vc%u: node %s, clock %lu", i,
                       uuid_utoa(vc->elems[i].node), vc->elems[i].clock);
        }
        for (i = 1; i <= MAX_REPLICAS; ++i) {
                if (vc->elems[i].clock > priv->vc.elems[i].clock) {
                        priv->vc.elems[i].clock = vc->elems[i].clock;
                }
        }

        /*
         * TBD: this part is only here right now to make the message patterns
         * the same as what we'd have in the real thing.  Later, this might be
         * a magic fsetxattr or something to retire a specific log entry.
         */
        newframe = create_frame(this,&priv->pool);
        if (newframe) {
                STACK_WIND (newframe, rot13_release_cbk, FIRST_CHILD(this),
                            FIRST_CHILD(this)->fops->fstat, cookie);
        }
        else {
                gf_log(this->name,GF_LOG_ERROR,
                       "could not create release frame");
        }

	dict_unref(frame->local);
	frame->local = NULL;
	STACK_UNWIND_STRICT (writev, frame, op_ret, op_errno, prebuf, postbuf);
	return 0;

err:
        STACK_UNWIND_STRICT(writev,frame,-1,EINVAL,NULL,NULL);
        return 0;
}

/*
 * This is called on the server side when we've converted a writevxd into a
 * writev, and converts it back.
 */
int32_t
rot13_writevxd_server_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
			   int32_t op_ret, int32_t op_errno,
			   struct iatt *prebuf, struct iatt *postbuf,
                           uint32_t flags)
{
	rot_13_private_t *priv = (rot_13_private_t *)this->private;
	dict_t *extra = NULL;
	int     ret = (-1);

        ++(priv->vc.elems[priv->vc_index].clock);
        /* TBD: update per-client clock value */

	extra = dict_new();
	ret = dict_set_static_bin(extra,"vector-clock",
                                  &priv->vc,sizeof(priv->vc));

	STACK_UNWIND_STRICT (writevxd, frame, op_ret, op_errno,
			     prebuf, postbuf, extra);

	dict_unref(extra);
	return 0;
}

int32_t
rot13_writev (call_frame_t *frame,
              xlator_t *this,
              fd_t *fd,
              struct iovec *vector,
              int32_t count,
              off_t offset, uint32_t flags,
              struct iobref *iobref)
{
	rot_13_private_t *priv = (rot_13_private_t *)this->private;
	dict_t *dict = NULL;
	int ret = (-1);

        ++(priv->vc.elems[priv->vc_index].clock);

	if (I_AM_CLIENT(priv)) {
		dict = dict_new();
                /* TBD: convert to network byte order */
		ret = dict_set_static_bin(dict,"vector-clock",
                                          &priv->vc, sizeof(priv->vc));
		frame->local = dict;
		STACK_WIND_COOKIE (frame,
			    rot13_writevxd_client_cbk,
                            fd,
			    FIRST_CHILD (this),
			    FIRST_CHILD (this)->fops->writevxd,
			    fd, vector, count, offset,
			    flags, iobref, dict);
	}
	else {
		STACK_WIND (frame,
			    rot13_writev_cbk,
			    FIRST_CHILD (this),
			    FIRST_CHILD (this)->fops->writev,
			    fd, vector, count, offset,
			    flags, iobref);
	}
	return 0;
}

void
rot13_log (xlator_t *this, rot_13_private_t *priv,
           fd_t *fd, off_t offset, int32_t count, vector_clock *vc)
{
        int     rc      = 0;

        /* TBD: just use pid for now, need to use GFID (or something) */
        rc = sqlite3_bind_int(priv->sql_log_cmd,1,fd->pid);
        if (rc != SQLITE_OK) {
                gf_log(this->name,GF_LOG_ERROR,"could not bind fd");
                return;
        }

        rc = sqlite3_bind_int(priv->sql_log_cmd,2,(int)offset);
        if (rc != SQLITE_OK) {
                gf_log(this->name,GF_LOG_ERROR,"could not bind start");
                return;
        }

        rc = sqlite3_bind_int(priv->sql_log_cmd,3,(int)(offset+count-1));
        if (rc != SQLITE_OK) {
                gf_log(this->name,GF_LOG_ERROR,"could not bind end");
                return;
        }

        rc = sqlite3_bind_int(priv->sql_log_cmd,4,(int)vc->elems[1].clock);
        if (rc != SQLITE_OK) {
                gf_log(this->name,GF_LOG_ERROR,"could not bind server vc");
                return;
        }

        rc = sqlite3_bind_int(priv->sql_log_cmd,5,(int)vc->elems[0].clock);
        if (rc != SQLITE_OK) {
                gf_log(this->name,GF_LOG_ERROR,"could not bind vc3");
                return;
        }

        rc = sqlite3_bind_blob(priv->sql_log_cmd,6,vc->elems[0].node,
                               sizeof(uuid_t),SQLITE_STATIC);
        if (rc != SQLITE_OK) {
                gf_log(this->name,GF_LOG_ERROR,"could not bind end");
                return;
        }

        rc = sqlite3_step(priv->sql_log_cmd);
        if (rc != SQLITE_DONE) {
                gf_log(this->name,GF_LOG_ERROR,"INSERT failed");
                return;
        }

        (void)sqlite3_reset(priv->sql_log_cmd);
        (void)sqlite3_clear_bindings(priv->sql_log_cmd);
}

int32_t
rot13_writevxd (call_frame_t *frame,
                xlator_t *this,
                fd_t *fd,
                struct iovec *vector,
                int32_t count,
                off_t offset,
                uint32_t flags,
                struct iobref *iobref,
		dict_t *dict)
{
	rot_13_private_t *priv = (rot_13_private_t *)this->private;
        data_t *data = NULL;
        uint32_t i = 0;
        vector_clock *vc = NULL;

        if (dict) {
                dict_foreach(dict,xd_iterator,this->name);
                data = dict_get(dict,"vector-clock");
        }
        if (!data) {
                gf_log(this->name,GF_LOG_ERROR,"missing data for XD write");
                goto err;
        }

        vc = (vector_clock *)(data->data);
        /* TBD: convert from network byte order. */
        for (i = 0; i <= MAX_REPLICAS; ++i) {
                gf_log(this->name, GF_LOG_DEBUG, "vc%u: node %s, clock %lu", i,
                       uuid_utoa(vc->elems[i].node), vc->elems[i].clock);
        }

        for (i = 1; i <= MAX_REPLICAS; ++i) {
                if (vc->elems[i].clock > priv->vc.elems[i].clock) {
                        priv->vc.elems[i].clock = vc->elems[i].clock;
                }
        }

        if (!I_AM_CLIENT(priv)) {
                rot13_log(this,priv,fd,offset,count,vc);
        }

	STACK_WIND (frame,
		    rot13_writevxd_server_cbk,
		    FIRST_CHILD (this),
		    FIRST_CHILD (this)->fops->writev,
		    fd, vector, count, offset,
		    flags, iobref);
	return 0;

err:
        STACK_UNWIND_STRICT(writevxd,frame,-1,EINVAL,NULL,NULL,0);
        return 0;
}

int32_t
rot13_fxattrop (call_frame_t *frame, xlator_t *this, fd_t *fd,
                gf_xattrop_flags_t flags, dict_t *dict)
{
        gf_log(this->name,GF_LOG_DEBUG,"stubbing out fxattrop");
        STACK_UNWIND_STRICT (fxattrop, frame, 0, 0, dict);
        return 0;
}

int32_t
rot13_finodelk (call_frame_t *frame, xlator_t *this, const char *volume,
                fd_t *fd, int32_t cmd, struct gf_flock *lock)
{
        gf_log(this->name,GF_LOG_DEBUG,"stubbing out finodelk");
        STACK_UNWIND_STRICT (finodelk, frame, 0, 0);
        return 0;
}

/* TBD: return/check value */
void
rot13_init_db (xlator_t *this, rot_13_private_t *priv)
{
        int      rc             = 0;
        char    *errmsgp        = NULL;
        char    *fname          = NULL;

        if (gf_asprintf(&fname,"/tmp/%s.sql",this->name) < 0) {
                gf_log(this->name,GF_LOG_ERROR,"could not construct file name");
                return;
        }

        /* TBD: for debugging only! */
        (void)unlink(fname);

        rc = sqlite3_open(fname,&priv->db);
        GF_FREE(fname);
        if (rc != SQLITE_OK) {
                gf_log(this->name,GF_LOG_ERROR,"could not open DB");
                return;
        }

        rc = sqlite3_exec(priv->db,
                "CREATE TABLE timeline ("
                        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                        "fd INTEGER, first INTEGER, last INTEGER,"
                        "server_vc INTEGER, client_vc INTEGER,"
                        "client_id BLOB);",
                NULL, NULL, &errmsgp);
        if (rc != SQLITE_OK) {
                gf_log(this->name,GF_LOG_ERROR,"could not create table");
                return;
        }

        rc = sqlite3_prepare_v2(priv->db,
                "INSERT INTO timeline VALUES(NULL,?,?,?,?,?,?)",
                -1, &priv->sql_log_cmd, NULL);
        if (rc != SQLITE_OK) {
                gf_log(this->name,GF_LOG_ERROR,"could not create INSERT");
                return;
        }
}

int32_t
init (xlator_t *this)
{
	data_t *data = NULL;
	rot_13_private_t *priv = NULL;
        uuid_t my_uuid = {0,};

	if (!this->children || this->children->next) {
		gf_log ("rot13", GF_LOG_ERROR,
			"FATAL: rot13 should have exactly one child");
		return -1;
	}

	if (!this->parents) {
		gf_log (this->name, GF_LOG_WARNING,
			"dangling volume. check volfile ");
	}

	priv = GF_CALLOC (sizeof (rot_13_private_t), 1, 0);
        if (!priv)
                return -1;

        GF_OPTION_INIT ("vc-index", priv->vc_index, uint32, err);

        data = dict_get (this->options, "uuid");
        if (data) {
                if (uuid_parse(data->data,my_uuid) != 0) {
                        gf_log(this->name, GF_LOG_ERROR,
                               "could not parse uuid");
                        return -1;
                }
        }
        else if (I_AM_CLIENT(priv)) {
                uuid_generate_random(my_uuid);
                gf_log(this->name, GF_LOG_INFO,
                       "using ephemeral uuid %s", uuid_utoa(my_uuid));
        }
        else {
                gf_log(this->name, GF_LOG_ERROR,
                       "ephemeral uuid not allowed on server");
                return -1;
        }

        uuid_copy(priv->vc.elems[priv->vc_index].node,my_uuid);
        priv->vc.elems[priv->vc_index].clock = priv->vc_index * 1000;

        if (!I_AM_CLIENT(priv)) {
                rot13_init_db(this,priv);
        }

        /* Begin copy from xattr-prefetch xlator. */
        priv->pool.stack_mem_pool = mem_pool_new(call_stack_t,1000);
        if (!priv->pool.stack_mem_pool) {
                gf_log(this->name,GF_LOG_ERROR,
                       "could not allocate call stacks");
                goto err;
        }

        priv->pool.frame_mem_pool = mem_pool_new(call_frame_t,1000);
        if (!priv->pool.frame_mem_pool) {
                gf_log(this->name,GF_LOG_ERROR,
                       "could not allocate call frames");
                goto err_no_frames;
        }

        INIT_LIST_HEAD(&priv->pool.all_frames);
        LOCK_INIT(&priv->pool.lock);
        /* End copy from xattr-prefetch xlator. */

	this->private = priv;
	gf_log ("rot13", GF_LOG_DEBUG, "rot13 xlator loaded");
	return 0;

err_no_frames:
        mem_pool_destroy(priv->pool.stack_mem_pool);
err:
        GF_FREE(priv);
        return -1;
}

void
fini (xlator_t *this)
{
	rot_13_private_t *priv = this->private;

        if (!priv)
                return;
        this->private = NULL;
	GF_FREE (priv);

	return;
}

struct xlator_fops fops = {
	.writev   = rot13_writev,
	.writevxd = rot13_writevxd,
        .fxattrop = rot13_fxattrop,
        .finodelk = rot13_finodelk,
};

struct xlator_cbks cbks = {
};

struct volume_options options[] = {
        { .key = {"vc-index"},
          .type = GF_OPTION_TYPE_INT,
          .min = 0,
          .max = 3,
          .default_value = 0
        },
        { .key = {"uuid"},
          .type = GF_OPTION_TYPE_STR
        },
	{ .key  = {NULL} },
};
