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

#define SAFETY_MSG(reason)                                              \
        gf_log (this->name, GF_LOG_DEBUG,                               \
                "failing future I/O to avoid data corruption (%s)",     \
                reason);

enum {
        CHANGELOG_DATA=0,
        CHANGELOG_METADATA,
        CHANGELOG_ENTRY,
        CHANGELOG_SIZE
};

char *SELF_XATTR        = "trusted.hsrepl.self-xattr";
char *PARTNER_XATTR     = "trusted.hsrepl.partner-xattr";

dict_t *
get_pending_dict (xlator_t *this, uint32_t bump)
{
	dict_t           *dict = NULL;
	int32_t          *value1 = NULL;
	int32_t          *value2 = NULL;
        helper_private_t *priv = this->private;

	dict = dict_new();
	if (!dict) {
		gf_log (this->name, GF_LOG_WARNING, "failed to allocate dict");
                return NULL;
	}

        value1 = GF_CALLOC(CHANGELOG_SIZE,sizeof(*value1),gf_by_mt_int32_t);
        if (!value1) {
                gf_log (this->name, GF_LOG_WARNING, "failed to allocate value");
                goto free_dict;
        }
        value1[CHANGELOG_DATA] = htonl(bump);
        if (dict_set_dynptr(dict,priv->partner_xattr,value1,
                            CHANGELOG_SIZE*sizeof(*value1)) < 0) {
                gf_log (this->name, GF_LOG_WARNING, "failed to set up dict");
                goto free_value1;
        }

        value2 = GF_CALLOC(CHANGELOG_SIZE,sizeof(*value2),gf_by_mt_int32_t);
        if (!value2) {
                gf_log (this->name, GF_LOG_WARNING, "failed to allocate value");
                goto free_value1;
        }
        value2[CHANGELOG_DATA] = htonl(bump);
        if (dict_set_dynptr(dict,priv->self_xattr,value2,
                            CHANGELOG_SIZE*sizeof(*value2)) < 0) {
                gf_log (this->name, GF_LOG_WARNING, "failed to set up dict");
                goto free_value2;
        }

        return dict;

free_value2:
        GF_FREE(value2);
free_value1:
        GF_FREE(value1);
free_dict:
	dict_unref(dict);
        return NULL;
}

dict_t *
helper_add_version (dict_t *in_dict, uint32_t version, uint32_t sh_version)
{
        dict_t  *out_dict       = NULL;

        if (in_dict) {
                out_dict = dict_ref(in_dict);
        }
        else {
                out_dict = dict_new();
                if (!out_dict) {
                        gf_log (THIS->name, GF_LOG_WARNING,
                                "could not allocate out_dict");
                        goto done;
                }
        }

        if (dict_set_uint32(out_dict,"hsrepl.reply-vers",version) != 0) {
                gf_log (THIS->name, GF_LOG_WARNING,
                        "could not set reply-vers");
        }

        if (dict_set_uint32(out_dict,"hsrepl.heal-vers",sh_version) != 0) {
                gf_log (THIS->name, GF_LOG_WARNING,
                        "could not set heal-vers");
        }

done:
        return out_dict;
}

int32_t
helper_set_pending_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
			int32_t op_ret, int32_t op_errno, dict_t *dict,
                        dict_t *xdata)
{
	if (op_ret < 0) {
		goto unwind;
	}

	call_resume(cookie);
	return 0;

unwind:
        STACK_UNWIND_STRICT (writev, frame, op_ret, op_errno, NULL, NULL, NULL);
        return 0;
}

int32_t
helper_clr_pending_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
			int32_t op_ret, int32_t op_errno, dict_t *dict,
                        dict_t *xdata)
{
        helper_local_t  *local = frame->local;

        xdata = helper_add_version(xdata,local->version,local->sh_version);
        STACK_UNWIND_STRICT (writev, frame,
                             local->real_op_ret, local->real_op_errno,
                             NULL, NULL, xdata);
        dict_unref(xdata);
        return 0;
}

int32_t
helper_writev_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                    int32_t op_ret, int32_t op_errno, struct iatt *prebuf,
                    struct iatt *postbuf, dict_t *xdata)
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
                ++(ctx_ptr->version);
                ctx_ptr->trans = frame->root->trans;
        }
        version = ctx_ptr->version;

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
        local->sh_version = ctx_ptr->sh_version;
        frame->local = local;

        STACK_WIND_COOKIE (frame, helper_clr_pending_cbk, cookie,
                           FIRST_CHILD(this), FIRST_CHILD(this)->fops->fxattrop,
                           cookie, GF_XATTROP_ADD_ARRAY, dict, xdata);

        dict_unref(dict);
        return 0;

free_local:
        GF_FREE(local);
unwind:
        xdata = helper_add_version(xdata,version,ctx_ptr->sh_version);
        STACK_UNWIND_STRICT (writev, frame, op_ret, op_errno,
                             prebuf, postbuf, xdata);
        dict_unref(xdata);
        return 0;

}

int32_t
helper_writev_resume (call_frame_t *frame, xlator_t *this, fd_t *fd,
                       struct iovec *vector, int32_t count, off_t off,
                       uint32_t flags, struct iobref *iobref, dict_t *xdata)
{
        STACK_WIND_COOKIE (frame, helper_writev_cbk, fd,
                            FIRST_CHILD(this), FIRST_CHILD(this)->fops->writev,
                            fd, vector, count, off, flags, iobref, xdata);
        return 0;
}

helper_ctx_t *
helper_create_ctx (xlator_t *this, inode_t *inode)
{
        uint64_t          ctx_int = 0;
        helper_ctx_t     *ctx_ptr = NULL;

        ctx_ptr = GF_CALLOC(1,sizeof(*ctx_ptr),gf_helper_mt_ctx_t);
        if (!ctx_ptr) {
                gf_log (this->name, GF_LOG_WARNING,
                        "failed to allocate context");
                return NULL;
        }
        ctx_ptr->version = 888;
        ctx_ptr->sh_version = 5150;
        ctx_ptr->trans = NULL;

        ctx_int = CAST2INT(ctx_ptr);
        if (inode_ctx_set(inode,this,&ctx_int) != 0) {
                gf_log (this->name, GF_LOG_WARNING, "failed to set context");
                GF_FREE(ctx_ptr);
                return NULL;
        }

        return ctx_ptr;
}

int32_t
helper_writev (call_frame_t *frame, xlator_t *this, fd_t *fd,
               struct iovec *vector, int32_t count, off_t off,
               uint32_t flags, struct iobref *iobref, dict_t *xdata)
{
	dict_t           *dict = NULL;
	call_stub_t      *stub = NULL;
        int32_t           op_errno = ENOMEM;
        uint64_t          ctx_int = 0;
        helper_ctx_t     *ctx_ptr = NULL;
        helper_private_t *priv = this->private;
        uint32_t          version = 0;
        uint32_t          sh_version = 0;

        if (dict_get_uint32(xdata,"hsrepl.request-vers",&version) != 0) {
                return default_writev (frame, this, fd, vector, count, off,
                                       flags, iobref, xdata);
        }

        if (dict_get_uint32(xdata,"hsrepl.heal-vers",&sh_version) != 0) {
                return default_writev (frame, this, fd, vector, count, off,
                                       flags, iobref, xdata);
        }

        if (!priv->self_xattr || !priv->partner_xattr) {
                op_errno = ESRCH;
                goto err;
        }

        if (inode_ctx_get(fd->inode,this,&ctx_int) == 0) {
                ctx_ptr = CAST2PTR(ctx_int);
                if (!ctx_ptr) {
                        goto err;
                }
                op_errno = EKEYEXPIRED;
                if (ctx_ptr->locks) {
                        gf_log (this->name, GF_LOG_DEBUG,
                                "data version: received %u != stored %u",
                                version, ctx_ptr->version);
                        goto err;
                 }
                if (version != ctx_ptr->version) {
                        gf_log (this->name, GF_LOG_DEBUG,
                                "data version: received %u != stored %u",
                                version, ctx_ptr->version);
                        goto err;
                }
                if (sh_version != ctx_ptr->sh_version) {
                        gf_log (this->name, GF_LOG_DEBUG,
                                "heal version: received %u != stored %u",
                                sh_version, ctx_ptr->sh_version);
                        goto err;
                }
                op_errno = ENOMEM;
        }
        else {
                ctx_ptr = helper_create_ctx(this,fd->inode);
                if (!ctx_ptr) {
                        goto err;
                }
                ctx_ptr->dirty = _gf_true;
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
	stub = fop_writev_stub(frame, helper_writev_resume,
			       fd, vector, count, off, flags, iobref, xdata);
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
                           fd, GF_XATTROP_ADD_ARRAY, dict, xdata);
	dict_unref(dict);
	return 0;

free_stub:
        call_stub_destroy(stub);
err:
        if (ctx_ptr) {
                xdata = helper_add_version(xdata,ctx_ptr->version,
                                           ctx_ptr->sh_version);
                STACK_UNWIND_STRICT (writev, frame, -1, op_errno,
                                     NULL, NULL, xdata);
                dict_unref(xdata);
        }
        else {
                STACK_UNWIND_STRICT (writev, frame, -1, op_errno,
                                     NULL, NULL, xdata);
        }
        return 0;
}

int32_t
helper_setxattr (call_frame_t *frame, xlator_t *this, loc_t *loc, dict_t *dict,
                 int32_t flags, dict_t *xdata)
{
        char                    *self = NULL;
        char                    *partner = NULL;
        helper_private_t        *priv = this->private;

        if (dict_get_str(dict,SELF_XATTR,&self) == 0) {
                gf_log (this->name, GF_LOG_DEBUG,
                        "setting self to %s", self);
                if (priv->self_xattr) {
                        GF_FREE(priv->self_xattr);
                        priv->self_xattr = NULL;
                }
                if (gf_asprintf(&priv->self_xattr,"trusted.afr.%s",
                                self) < 0) {
                        SAFETY_MSG("format failed");
                }
        }

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
                    FIRST_CHILD(this)->fops->setxattr, loc, dict, flags, xdata);
        return 0;
}

int32_t
helper_fxattrop (call_frame_t *frame, xlator_t *this, fd_t *fd,
                 gf_xattrop_flags_t flags, dict_t *dict, dict_t *xdata)
{
        uint64_t         ctx_int = 0;
        helper_ctx_t    *ctx_ptr = NULL;
        uint32_t         sh_version = 0;
        data_t          *data = NULL;

        if (inode_ctx_get(fd->inode,this,&ctx_int) == 0) {
                ctx_ptr = CAST2PTR(ctx_int);
                if (!dict_get_uint32(xdata,"hsrepl.heal-vers",&sh_version)) {
                        if (sh_version != ctx_ptr->sh_version) {
                                gf_log (this->name, GF_LOG_DEBUG,
                                        "dropping self-heal-interrupted op");
                                STACK_UNWIND_STRICT (fxattrop, frame,
                                                     0, 0, dict, xdata);
                                return 0;
                        }
                }
                data = dict_get(xdata,"trusted.afr.self-heal-erase");
                if (data) {
                        gf_log (this->name, GF_LOG_DEBUG, "detected self-heal");
                        ++(ctx_ptr->sh_version);
                }
        }

        STACK_WIND (frame, default_fxattrop_cbk, FIRST_CHILD(this),
                    FIRST_CHILD(this)->fops->fxattrop, fd, flags, dict, xdata);
        return 0;
}

void
helper_bump_lock_count (xlator_t *this, inode_t *inode, int bump)
{
        uint64_t         ctx_int = 0;
        helper_ctx_t    *ctx_ptr = NULL;

        if (!inode) {
                return;
        }

        if (inode_ctx_get(inode,this,&ctx_int) == 0) {
                ctx_ptr = CAST2PTR(ctx_int);
        }
        else {
                ctx_ptr = helper_create_ctx(this,inode);
        }

        if (!ctx_ptr) {
                return;
        }

        gf_log (this->name, GF_LOG_DEBUG,
                "bumping lock count by %d", bump);
        ctx_ptr->locks += bump;
        if (!ctx_ptr->locks) {
                if (ctx_ptr->dirty) {
                        gf_log (this->name, GF_LOG_DEBUG,
                                "bumping version for inodelk");
                        ++(ctx_ptr->version);
                }
        }
}

int32_t
helper_inodelk_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                    int32_t op_ret, int32_t op_errno, dict_t *xdata)
{
        helper_local_t  *local = frame->local;

        /* Decrement on failed locks and successful unlocks. */
        if ((op_ret < 0) == (local->l_type != F_UNLCK)) {
                helper_bump_lock_count(this,local->inode,-1);
        }

        STACK_UNWIND_STRICT (inodelk, frame, op_ret, op_errno, xdata);
        return 0;
}

int32_t
helper_inodelk (call_frame_t *frame, xlator_t *this,
                const char *volume, loc_t *loc, int32_t cmd,
                struct gf_flock *lock, dict_t *xdata)
{
        helper_local_t  *local = NULL;

        local = mem_get0(this->local_pool);
        if (!local) {
                STACK_UNWIND_STRICT(inodelk,frame,-1,ENOMEM, xdata);
                return 0;
        }
        local->inode = loc->inode;
        local->l_type = lock->l_type;
        frame->local = local;
        
        if (lock->l_type != F_UNLCK) {
                helper_bump_lock_count(this,local->inode,1);
        }

        STACK_WIND (frame, helper_inodelk_cbk, FIRST_CHILD(this),
                    FIRST_CHILD(this)->fops->inodelk, volume, loc, cmd, lock,
                    xdata);
        return 0;
}

int32_t
helper_finodelk (call_frame_t *frame, xlator_t *this, const char *volume,
                 fd_t *fd, int32_t cmd, struct gf_flock *lock, dict_t *xdata)
{
        helper_local_t  *local = NULL;

        local = mem_get0(this->local_pool);
        if (!local) {
                STACK_UNWIND_STRICT(inodelk,frame,-1,ENOMEM,xdata);
                return 0;
        }
        local->inode = fd->inode;
        local->l_type = lock->l_type;
        frame->local = local;
        
        if (lock->l_type != F_UNLCK) {
                helper_bump_lock_count(this,local->inode,1);
        }

        STACK_WIND (frame, helper_inodelk_cbk, FIRST_CHILD(this),
                    FIRST_CHILD(this)->fops->finodelk, volume, fd, cmd, lock,
                    xdata);
        return 0;
}

int32_t
helper_get_partner_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                        int32_t op_ret, int32_t op_errno, dict_t *dict,
                        dict_t *xdata)
{
        helper_private_t        *priv = this->private;
        char                    *self = NULL;
        char                    *partner = NULL;

        STACK_DESTROY(frame->root);

        if (op_ret < 0) {
                SAFETY_MSG("getxattr failed");
                goto err;
        }

        if (dict_get_str(dict,SELF_XATTR,&self) != 0) {
                SAFETY_MSG("self missing in dict");
                goto err;
        }

        if (gf_asprintf(&priv->self_xattr,"trusted.afr.%s", self) < 0) {
                SAFETY_MSG("format failed");
                goto err;
        }

        gf_log (this->name, GF_LOG_DEBUG,
                "self-xattr is %s", priv->self_xattr);

        if (dict_get_str(dict,PARTNER_XATTR,&partner) != 0) {
                SAFETY_MSG("partner missing in dict");
                goto err;
        }

        if (gf_asprintf(&priv->partner_xattr,"trusted.afr.%s", partner) < 0) {
                SAFETY_MSG("format failed");
                goto err;
        }

        gf_log (this->name, GF_LOG_DEBUG,
                "partner-xattr is %s", priv->partner_xattr);
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
                                    PARTNER_XATTR, NULL);
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

int
helper_forget (xlator_t *this, inode_t *inode)
{
        uint64_t        ctx     = 0;

        if (inode_ctx_get(inode,this,&ctx) == 0) {
                GF_FREE(CAST2PTR(ctx));
        }

        return 0;
}

int32_t
init (xlator_t *this)
{
	helper_private_t *priv = NULL;
        char             *self = NULL;
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

        if (dict_get_str(this->options,SELF_XATTR,&self) == 0) {
                (void)gf_asprintf(&priv->self_xattr,
                                  "trusted.afr.%s", self);
        }

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

        GF_FREE(priv->self_xattr);
        GF_FREE(priv->partner_xattr);
	GF_FREE(priv);

	return;
}

struct xlator_fops fops = {
	.writev         = helper_writev,
        .setxattr       = helper_setxattr,
        .fxattrop       = helper_fxattrop,
        .inodelk        = helper_inodelk,
        .finodelk       = helper_finodelk,
};

struct xlator_cbks cbks = {
        .forget      = helper_forget,
};

struct volume_options options[] = {
        { .key = {"self-xattr"},
          .type = GF_OPTION_TYPE_STR
        },
        { .key = {"partner-xattr"},
          .type = GF_OPTION_TYPE_STR
        },
	{ .key  = {NULL} },
};
