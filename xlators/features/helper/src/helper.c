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

#include <ctype.h>
#include <sys/uio.h>

#ifndef _CONFIG_H
#define _CONFIG_H
#include "config.h"
#endif

#include "glusterfs.h"
#include "call-stub.h"
#include "defaults.h"
#include "logging.h"
#include "xlator.h"

#include "helper.h"

#define PARTNER_XATTR "trusted.hsrepl.partner-xattr"
#define SAFETY_MSG(reason)                                              \
        gf_log (this->name, GF_LOG_DEBUG,                               \
                "failing future I/O to avoid data corruption (%s)",     \
                reason);

dict_t *
get_pending_dict (xlator_t *this, uint32_t bump)
{
	dict_t           *dict = NULL;
	int32_t          *value = NULL;
        helper_private_t *priv = this->private;

	dict = dict_new();
	if (!dict) {
		gf_log (this->name, GF_LOG_WARNING, "failed to allocate dict");
                return NULL;
	}

        value = GF_CALLOC(3,sizeof(*value),gf_by_mt_int32_t);
        if (!value) {
                gf_log (this->name, GF_LOG_WARNING, "failed to allocate value");
                goto free_dict;
        }
        /* Amazingly, there's no constant for this. */
        value[0] = htonl(bump);
        if (dict_set_dynptr(dict,priv->partner_xattr,value,
                            3*sizeof(*value)) < 0) {
                gf_log (this->name, GF_LOG_WARNING, "failed to set up dict");
                goto free_value;
        }
        return dict;

free_value:
        GF_FREE(value);
free_dict:
	dict_unref(dict);
        return NULL;
}

int32_t
helper_set_pending_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
			int32_t op_ret, int32_t op_errno, dict_t *dict)
{
	if (op_ret < 0) {
		goto unwind;
	}

	call_resume(cookie);
	return 0;

unwind:
        STACK_UNWIND_STRICT (writev, frame, op_ret, op_errno, NULL, NULL);
        return 0;
}

int32_t
helper_clr_pending_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
			int32_t op_ret, int32_t op_errno, dict_t *dict)
{
        helper_local_t  *local = frame->local;

        STACK_UNWIND_STRICT (writev_vers, frame,
                             local->real_op_ret, local->real_op_errno,
                             NULL, NULL, local->version);
        return 0;
}

int32_t
helper_writev_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                    int32_t op_ret, int32_t op_errno, struct iatt *prebuf,
                    struct iatt *postbuf)
{
        helper_ctx_t    *ctx_ptr = frame->local;
        uint32_t         version = 0;
        helper_local_t  *local = NULL;
        dict_t          *dict = NULL;

        if (frame->root->trans == ctx_ptr->trans) {
                gf_log (this->name, GF_LOG_DEBUG,
                        "not incrementing version for pipelined request");
        }
        else {
                gf_log (this->name, GF_LOG_DEBUG,
                        "incrementing version for different client");
                version = ++(ctx_ptr->version);
                ctx_ptr->trans = frame->root->trans;
        }

        frame->local = NULL;
        if (op_ret >= 0) {
                goto unwind;
        }

        gf_log (this->name, GF_LOG_DEBUG, "have to undo increment");

        local = mem_get0(this->local_pool);
        if (!local) {
                gf_log (this->name, GF_LOG_ERROR, "could not allocate local");
                goto unwind;
        }

        dict = get_pending_dict(this,-1);
        if (!dict) {
                goto free_local;
        }

        local->real_op_ret = op_ret;
        local->real_op_errno = op_errno;
        local->version = version;
        frame->local = local;

        STACK_WIND_COOKIE (frame, helper_clr_pending_cbk, cookie,
                           FIRST_CHILD(this), FIRST_CHILD(this)->fops->fxattrop,
                           cookie, GF_XATTROP_ADD_ARRAY, dict);

        dict_unref(dict);
        return 0;

free_local:
        GF_FREE(local);
unwind:
        STACK_UNWIND_STRICT (writev_vers, frame, op_ret, op_errno,
                             prebuf, postbuf, version);
        return 0;

}

int32_t
helper_writev_vers_resume (call_frame_t *frame, xlator_t *this, fd_t *fd,
                       struct iovec *vector, int32_t count, off_t off,
                       uint32_t flags, struct iobref *iobref, uint32_t version)
{
        gf_log(this->name,GF_LOG_DEBUG,"got version %u",version);

        STACK_WIND_COOKIE (frame, helper_writev_cbk, fd,
                            FIRST_CHILD(this), FIRST_CHILD(this)->fops->writev,
                            fd, vector, count, off, flags, iobref);
        return 0;
}

int32_t
helper_writev (call_frame_t *frame, xlator_t *this, fd_t *fd,
               struct iovec *vector, int32_t count, off_t off,
               uint32_t flags, struct iobref *iobref, uint32_t version)
{
	dict_t           *dict = NULL;
	call_stub_t      *stub = NULL;
        int32_t           op_errno = ENOMEM;
        uint64_t          ctx_int = 0;
        helper_ctx_t     *ctx_ptr = NULL;
        helper_private_t *priv = this->private;

        if (!priv->partner_xattr) {
                op_errno = ESRCH;
                goto err;
        }

        if (inode_ctx_get(fd->inode,this,&ctx_int) == 0) {
                ctx_ptr = CAST2PTR(ctx_int);
                if (version != ctx_ptr->version) {
                        gf_log (this->name, GF_LOG_DEBUG,
                                "received %u != stored %u",
                                version, ctx_ptr->version);
                        op_errno = EKEYEXPIRED;
                        goto err;
                }
        }
        else {
                ctx_ptr = GF_CALLOC(1,sizeof(*ctx_ptr),gf_helper_mt_ctx_t);
                if (!ctx_ptr) {
                        gf_log (this->name, GF_LOG_WARNING,
                                "failed to allocate context");
                        goto err;
                }
                ctx_ptr->version = 888;
                ctx_ptr->trans = NULL;
                ctx_int = CAST2INT(ctx_ptr);
                if (inode_ctx_set(fd->inode,this,&ctx_int) != 0) {
                        gf_log (this->name, GF_LOG_WARNING,
                                "failed to set context");
                        goto free_ctx;
                }
        }
        /*
         * Warning: we cheat here by pointing "local" to the inode ctx.  This
         * must be undone before we unwind (and is, in helper_writev_cbk).
         */
        frame->local = ctx_ptr;

        /*
         * I wish we could just create the stub pointing to the target's
         * writev function, but then we'd get into another translator's code
         * with "this" pointing to us.
         */
	stub = fop_writev_vers_stub(frame, helper_writev_vers_resume,
			       fd, vector, count, off, flags, iobref, version);
	if (!stub) {
		gf_log (this->name, GF_LOG_WARNING, "failed to allocate stub");
		goto err;
	}

        dict = get_pending_dict(this,1);
        if (!dict) {
                goto free_stub;
        }

	STACK_WIND_COOKIE (frame, helper_set_pending_cbk, stub,
                           FIRST_CHILD(this), FIRST_CHILD(this)->fops->fxattrop,
                           fd, GF_XATTROP_ADD_ARRAY, dict);
	dict_unref(dict);
	return 0;

free_ctx:
        GF_FREE(ctx_ptr);
free_stub:
        call_stub_destroy(stub);
err:
        STACK_UNWIND_STRICT (writev_vers, frame, -1, op_errno, NULL, NULL,
                             ctx_ptr ? ctx_ptr->version : 0);
        return 0;
}

int32_t
helper_setxattr (call_frame_t *frame, xlator_t *this, loc_t *loc, dict_t *dict,
                 int32_t flags)
{
        char                    *partner = NULL;
        helper_private_t        *priv = this->private;

        if (dict_get_str(dict,PARTNER_XATTR,&partner) == 0) {
                gf_log (this->name, GF_LOG_DEBUG,
                        "setting partner to %s", partner);
                if (priv->partner_xattr) {
                        GF_FREE(priv->partner_xattr);
                        priv->partner_xattr = NULL;
                }
                if (gf_asprintf(&priv->partner_xattr,"trusted.afr.%s",
                                partner) < 0) {
                        SAFETY_MSG("format failed");
                }
        }

        STACK_WIND (frame, default_setxattr_cbk, FIRST_CHILD(this),
                    FIRST_CHILD(this)->fops->setxattr, loc, dict, flags);
        return 0;
}

int32_t
helper_get_partner_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                        int32_t op_ret, int32_t op_errno, dict_t *dict)
{
        helper_private_t        *priv = this->private;
        char                    *partner = NULL;

        STACK_DESTROY(frame->root);

        if (op_ret < 0) {
                SAFETY_MSG("getxattr failed");
                goto err;
        }

        if (dict_get_str(dict,PARTNER_XATTR,&partner) != 0) {
                SAFETY_MSG("item missing in dict");
                goto err;
        }

        if (gf_asprintf(&priv->partner_xattr,"trusted.afr.%s", partner) < 0) {
                SAFETY_MSG("format failed");
                goto err;
        }

        gf_log (this->name, GF_LOG_DEBUG,
                "partner-name is %s", priv->partner_xattr);
err:
        return 0;
}

int32_t
notify (xlator_t *this, int32_t event, void *data, ...)
{
        loc_t                    tmploc = {0,};
        call_frame_t            *newframe = NULL;
        xlator_t                *child = NULL;
        helper_private_t        *priv = this->private;

        switch (event) {
        case GF_EVENT_PARENT_UP:
                newframe = create_frame(this,&priv->pool);
                if (newframe) {
                        /* This is sufficient to identify the root gfid. */
                        tmploc.gfid[15] = 1;

                        child = FIRST_CHILD(this);
                        STACK_WIND (newframe, helper_get_partner_cbk,
                                    child,child->fops->getxattr, &tmploc,
                                    PARTNER_XATTR);
                }
                else {
                        SAFETY_MSG("create_frame failed");
                }
                break;
        default:
                ;
        }

        return 0;
}

int32_t
init (xlator_t *this)
{
	helper_private_t *priv = NULL;
        char             *partner = NULL;

	if (!this->children || this->children->next) {
		gf_log (this->name, GF_LOG_ERROR,
			"FATAL: helper should have exactly one child");
		return -1;
	}

        this->local_pool = mem_pool_new(helper_local_t,1024);
        if (!this->local_pool) {
                gf_log (this->name, GF_LOG_ERROR,
                        "FATAL: could not allocate local poool");
                goto err;
        }

	priv = GF_CALLOC (1, sizeof (helper_private_t), gf_helper_mt_priv_t);
        if (!priv) {
                goto free_local_pool;
        }

        /* Begin copy from xattr-prefetch xlator. */
        priv->pool.stack_mem_pool = mem_pool_new(call_stack_t,10);
        if (!priv->pool.stack_mem_pool) {
                gf_log(this->name,GF_LOG_ERROR,
                       "could not allocate call stacks");
                goto free_priv;
        }

        priv->pool.frame_mem_pool = mem_pool_new(call_frame_t,10);
        if (!priv->pool.frame_mem_pool) {
                gf_log(this->name,GF_LOG_ERROR,
                       "could not allocate call frames");
                goto free_stack_pool;
        }

        INIT_LIST_HEAD(&priv->pool.all_frames);
        LOCK_INIT(&priv->pool.lock);
        /* End copy from xattr-prefetch xlator. */

	this->private = priv;

        if (dict_get_str(this->options,PARTNER_XATTR,&partner) == 0) {
                (void)gf_asprintf(&priv->partner_xattr,
                                  "trusted.afr.%s", partner);
        }

	gf_log (this->name, GF_LOG_DEBUG, "helper xlator loaded");
	return 0;

free_stack_pool:
        mem_pool_destroy(priv->pool.stack_mem_pool);
free_priv:
        GF_FREE(priv);
free_local_pool:
        mem_pool_destroy(this->local_pool);
        this->local_pool = NULL;
err:
        return -1;
}

void
fini (xlator_t *this)
{
	helper_private_t *priv = this->private;

        if (!priv) {
                return;
        }
        this->private = NULL;

        GF_FREE(priv->partner_xattr);
	GF_FREE(priv);

	return;
}

struct xlator_fops fops = {
	.writev_vers    = helper_writev,
        .setxattr       = helper_setxattr,
};

struct xlator_cbks cbks = {
};

struct volume_options options[] = {
        { .key = {"partner-xattr"},
          .type = GF_OPTION_TYPE_STR
        },
	{ .key  = {NULL} },
};
