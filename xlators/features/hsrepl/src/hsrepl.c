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

#include "hsrepl.h"

enum {
        CHANGELOG_DATA=0,
        CHANGELOG_METADATA,
        CHANGELOG_ENTRY,
        CHANGELOG_SIZE
};

char *SELF_XATTR        = "trusted.hsrepl.self-xattr";
char *PARTNER_XATTR     = "trusted.hsrepl.partner-xattr";

/* Forward declarations for use by fop functions/callbacks. */
gf_boolean_t
hsrepl_writev_continue (call_frame_t *frame, xlator_t *this, hsrepl_ctx_t *ctx);

dict_t *
get_pending_dict (xlator_t *this, uint32_t *incrs, gf_boolean_t *up,
                  uint8_t dest)
{
	dict_t           *dict = NULL;
	xlator_list_t    *trav = NULL;
	char             *key = NULL;
	int32_t          *value = NULL;
        xlator_t         *afr = NULL;
        uint8_t           i = 0;

	dict = dict_new();
	if (!dict) {
		gf_log (this->name, GF_LOG_WARNING, "failed to allocate dict");
                return NULL;
	}

        afr = this->children->xlator;
	for (trav = afr->children; trav; trav = trav->next, ++i) {
                if (!up[i]) {
                        continue;
                }

		if (gf_asprintf(&key,"trusted.afr.%s",trav->xlator->name) < 0) {
			gf_log (this->name, GF_LOG_WARNING,
				"failed to allocate key");
			goto free_dict;
		}
		value = GF_CALLOC(CHANGELOG_SIZE,sizeof(*value),
                                  gf_hsrepl_mt_int32_t);
		if (!value) {
			gf_log (this->name, GF_LOG_WARNING,
				"failed to allocate value");
			goto free_key;
		}
                if (incrs[dest] != 1) {
                        gf_log (this->name, GF_LOG_DEBUG, "%s -= %u for %u",
                                key, incrs[dest], dest);
                }
                value[CHANGELOG_DATA] = htonl(-incrs[dest]);
		if (dict_set_dynptr(dict,key,value,
                                    CHANGELOG_SIZE*sizeof(*value)) < 0) {
			gf_log (this->name, GF_LOG_WARNING,
				"failed to set up dict");
			goto free_value;
		}
	}
        return dict;

free_value:
        GF_FREE(value);
free_key:
        GF_FREE(key);
free_dict:
	dict_unref(dict);
        return NULL;
}

int32_t
hsrepl_decr_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                 int32_t op_ret, int32_t op_errno, dict_t *dict, dict_t *xdata)
{
        hsrepl_local_t          *local          = frame->local;
        gf_boolean_t             done           = _gf_false;

        gf_log(this->name,GF_LOG_DEBUG,"got to %s",__func__);

        LOCK(&frame->lock);
        --(local->calls);
        done = (local->calls == 0);
        UNLOCK(&frame->lock);

        dict_unref(dict);
        if (done) {
                fd_unref(cookie);
                STACK_DESTROY(frame->root);
        }

        return 0;
}

int32_t
hsrepl_writev_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
                   int32_t op_ret, int32_t op_errno, struct iatt *prebuf,
                   struct iatt *postbuf, dict_t *xdata, uint32_t version)
{
        hsrepl_local_t          *local          = frame->local;
        gf_boolean_t             done           = _gf_false;
        call_frame_t            *newframe       = NULL;
        hsrepl_private_t        *priv           = this->private;
        dict_t                  *dict           = NULL;
        xlator_list_t           *trav           = NULL;
        uint8_t                  i              = 0;
        hsrepl_ctx_t            *ctx            = local->ctx;
        gf_boolean_t             up_copy[2]     = { _gf_false, };

        LOCK(&frame->lock);
        --(local->calls);
        done = (local->calls == 0);
        if (op_ret == (-1)) {
                ++(local->errors);
                if (op_errno == EKEYEXPIRED) {
                        ++(local->conflicts);
                }
        }
        else {
                local->good_op_ret = op_ret;
                local->good_op_errno = op_errno;
                if (prebuf) {
                        memcpy(&local->good_prebuf,prebuf,sizeof(*prebuf));
                }
                if (postbuf) {
                        memcpy(&local->good_postbuf,postbuf,sizeof(*postbuf));
                }
                ++(local->incrs[CAST2INT(cookie)]);
        }
        if (version) {
                gf_log (this->name, GF_LOG_DEBUG,
                        "got version %u from %lu", version, CAST2INT(cookie));
                ctx->versions[CAST2INT(cookie)] = version;
        }
        UNLOCK(&frame->lock);

        if (!done) {
                goto out;
        }

        if (local->conflicts) {
                gf_log (this->name, GF_LOG_DEBUG, "queuing wrong version");
                (void)pthread_mutex_lock(&priv->qlock);
                local->next = NULL;
                if (priv->qtail) {
                        priv->qtail->next = local;
                }
                else {
                        priv->qhead = local;
                }
                priv->qtail = local;
                (void)pthread_cond_signal(&priv->cond);
                (void)pthread_mutex_unlock(&priv->qlock);
                return 0;
        }

        iobref_unref(local->iobref);
        if (local->xdata) {
                dict_unref(local->xdata);
        }

        if (local->errors) {
                op_ret = local->good_op_ret;
                op_errno = local->good_op_errno;
                prebuf = &local->good_prebuf;
                postbuf = &local->good_postbuf;
                goto unwind;
        }

        newframe = create_frame(this,&priv->pool);
        if (!newframe) {
                gf_log(this->name,GF_LOG_ERROR,
                       "could not create release frame");
                op_errno = ENOMEM;
                goto err;
        }

        newframe->local = local;
        frame->local = NULL;
        LOCK(&priv->lock);
        local->calls = priv->up_count;
        memcpy(up_copy,priv->up,sizeof(up_copy));
        UNLOCK(&priv->lock);

        if (local->calls) {
                trav = this->children->xlator->children;
                for (i = 0; i < 2; ++i) {
                        if (!up_copy[i]) {
                                continue;
                        }
                        dict = get_pending_dict(this,local->incrs,priv->up,i);
                        if (!dict) {
                                gf_log (this->name, GF_LOG_WARNING,
                                        "failed to allocate dict");
                                continue;
                        }
                        STACK_WIND_COOKIE (newframe, hsrepl_decr_cbk, local->fd,
                                    trav->xlator, trav->xlator->fops->fxattrop,
                                    local->fd, GF_XATTROP_ADD_ARRAY, dict,
                                    NULL);
                        dict_unref(dict);
                        trav = trav->next;
                }
        }
        else {
                STACK_DESTROY(newframe->root);
        }

unwind:
        STACK_UNWIND_STRICT (writev, frame, op_ret, op_errno, prebuf, postbuf,
                             xdata);
out:
        return 0;

err:
        fd_unref(local->fd);
        STACK_UNWIND_STRICT(writev, frame, -1, op_errno, NULL, NULL, NULL);
        return 0;
}

int32_t
hsrepl_writev (call_frame_t *frame, xlator_t *this, fd_t *fd,
               struct iovec *vector, int32_t count, off_t off,
               uint32_t flags, struct iobref *iobref, dict_t *xdata)
{
        hsrepl_local_t   *local  = NULL;
        uint8_t           i      = 0;
        uint64_t          ctx_int = 0;
        hsrepl_ctx_t     *ctx_ptr = NULL;
        uint32_t          op_errno = ENOMEM;

        local = mem_get0(this->local_pool);
        if (!local) {
                goto err;
        }
        local->frame = frame;

        if (inode_ctx_get(fd->inode,this,&ctx_int) == 0) {
                ctx_ptr = CAST2PTR(ctx_int);
        }
        else {
                ctx_ptr = GF_CALLOC(1,sizeof(*ctx_ptr),gf_hsrepl_mt_ctx_t);
                if (!ctx_ptr) {
                        gf_log (this->name, GF_LOG_WARNING,
                                "failed to allocate context");
                        goto free_local;
                }
                for (i = 0; i < 2; ++i) {
                        ctx_ptr->versions[i] = 888;
                }
                ctx_int = CAST2INT(ctx_ptr);
                if (inode_ctx_set(fd->inode,this,&ctx_int) != 0) {
                        gf_log (this->name, GF_LOG_WARNING,
                                "failed to set context");
                        goto free_ctx;
                }
        }
        local->ctx = ctx_ptr;

        local->fd = fd_ref(fd);
        /* TBD: check length */
        memcpy(local->vector,vector,sizeof(*vector)*count);
        local->count = count;
        local->off = off;
        local->flags = flags;
        local->iobref = iobref_ref(iobref);
        local->xdata = xdata ? dict_ref(xdata) : NULL;
        frame->local = local;

        if (!hsrepl_writev_continue(frame,this,ctx_ptr)) {
                op_errno = ENOTCONN;
                goto free_local;
        }

        return 0;

free_ctx:
        GF_FREE(ctx_ptr);
free_local:
        mem_put(local);
err:
        STACK_UNWIND_STRICT(writev, frame, -1, op_errno, NULL, NULL, NULL);
        return 0;
}

gf_boolean_t
hsrepl_writev_continue (call_frame_t *frame, xlator_t *this, hsrepl_ctx_t *ctx)
{
        hsrepl_local_t          *local          = frame->local;
        hsrepl_private_t        *priv           = this->private;
        gf_boolean_t             up_copy[2]     = { _gf_false, };
        xlator_list_t           *trav           = NULL;
        uint8_t                  i              = 0;

        LOCK(&priv->lock);
        local->calls = priv->up_count;
        memcpy(up_copy,priv->up,sizeof(up_copy));
        UNLOCK(&priv->lock);

        if (!local->calls) {
                return _gf_false;
        }

        local->good_op_ret = -1;
        local->good_op_errno = EINVAL;
        local->errors = 0;
        local->conflicts = 0;

        trav = this->children->xlator->children;
        for (i = 0; i < 2; ++i, trav = trav->next) {
                if (!up_copy[i]) {
                        continue;
                }
                gf_log (this->name, GF_LOG_DEBUG,
                        "sending version %u to %u", ctx->versions[i], i);
                STACK_WIND_COOKIE(frame,hsrepl_writev_cbk, CAST2PTR(i),
                                  trav->xlator, trav->xlator->fops->writev_vers,
                                  local->fd, local->vector, local->count,
                                  local->off, local->flags, local->iobref,
                                  local->xdata, ctx->versions[i]);
        }

        return _gf_true;
}

int32_t
hsrepl_np_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
               int32_t op_ret, int32_t op_errno, dict_t *xdata)
{
        xlator_t *child = cookie;

        if (op_ret >= 0) {
                gf_log (this->name, GF_LOG_DEBUG, "told %s its partner OK",
                        child->name);
        }
        else {
                gf_log (this->name, GF_LOG_WARNING,
                        "could not tell %s its partner (%d), I/O might fail",
                        child->name, op_errno);
        }

        STACK_DESTROY(frame->root);
        return 0;
}

void
hsrepl_notify_partner (xlator_t *this, xlator_t *child1)
{
        hsrepl_private_t        *priv = this->private;
        dict_t                  *dict = NULL;
        xlator_list_t           *trav = NULL;
        xlator_t                *child2 = NULL;
        loc_t                    tmploc = {0,};
        call_frame_t            *newframe = NULL;
        char                    *the_xattr = NULL;

        dict = dict_new();
        if (!dict) {
                gf_log (this->name, GF_LOG_ERROR, "could not create dict");
                goto err;
        }

        for (trav = this->children->xlator->children; trav; trav = trav->next) {
                child2 = trav->xlator;

                the_xattr = (child2 == child1) ? SELF_XATTR : PARTNER_XATTR;
                if (dict_set_str(dict,the_xattr,child2->name) != 0) {
                        gf_log (this->name, GF_LOG_ERROR,
                                "could not create dict entry");
                        continue;
                }
        }

        newframe = create_frame(this,&priv->pool);
        if (!newframe) {
                gf_log (this->name,GF_LOG_ERROR,
                        "could not create notify frame");
                goto err;
        }

        /* This is sufficient to identify the root gfid. */
        tmploc.gfid[15] = 1;

        STACK_WIND_COOKIE (newframe, hsrepl_np_cbk, child1,
                           child1, child1->fops->setxattr,
                           &tmploc, dict, 0, NULL);

        /* TBD: support multiple partners */
        return;

err:
        gf_log (this->name, GF_LOG_WARNING,
                "could not tell %s its partner, I/O might fail", child1->name);
}

int32_t
hsrepl_notify (xlator_t *this, int32_t event, void *data, ...)
{
        xlator_t                *child = data;
        xlator_t                *us = NULL;
        hsrepl_private_t        *priv = NULL;
        uint16_t                 i = 0;
        xlator_list_t           *trav = NULL;

        /*
         * WARNING: we're called in the context of the target (AFR)
         * translator, and they need this information too.  Let's call them
         * first, and then do our own stuff.
         */
        us = this->parents->xlator;
        priv = us->private;
        (void)((priv->real_notify)(this,event,data));

        LOCK(&priv->lock);
        switch (event) {
        case GF_EVENT_CHILD_UP:
                gf_log (us->name, GF_LOG_DEBUG,
                        "got CHILD_UP for %s", child->name);
                trav = this->children;
                for (i = 0; (i < 2) && trav; ++i) {
                        if (!strcmp(trav->xlator->name,child->name)) {
                                if (!priv->up[i]) {
                                        ++(priv->up_count);
                                        hsrepl_notify_partner(us,child);
                                }
                                priv->up[i] = _gf_true;
                                break;
                        }
                        trav = trav->next;
                }
                break;
        case GF_EVENT_CHILD_DOWN:
                gf_log (us->name, GF_LOG_DEBUG,
                        "got CHILD_DOWN for %s", child->name);
                trav = this->children;
                for (i = 0; (i < 2) && trav; ++i) {
                        if (!strcmp(trav->xlator->name,child->name)) {
                                if (priv->up[i]) {
                                        --(priv->up_count);
                                }
                                priv->up[i] = _gf_false;
                                break;
                        }
                        trav = trav->next;
                }
                break;
        default:
                ;
        }
        UNLOCK(&priv->lock);

        return 0;
}

void *
hsrepl_worker (void *arg)
{
        xlator_t                *this = arg;
        hsrepl_private_t        *priv = this->private;
        hsrepl_local_t          *local = NULL;
        call_frame_t            *frame = NULL;
        uint64_t                 ctx_int = 0;
        hsrepl_ctx_t            *ctx_ptr = NULL;

        for (;;) {
                (void)pthread_mutex_lock(&priv->qlock);
                while (!priv->qhead) {
                        (void)pthread_cond_wait(&priv->cond,&priv->qlock);
                }
                local = priv->qhead;
                priv->qhead = local->next;
                if (!priv->qhead) {
                        priv->qtail = NULL;
                }
                (void)pthread_mutex_unlock(&priv->qlock);
                frame = local->frame;
                gf_log (this->name, GF_LOG_DEBUG, "queuing wrong version");
                if (inode_ctx_get(local->fd->inode,this,&ctx_int) != 0) {
                        gf_log (this->name, GF_LOG_ERROR,
                                "got retry frame without inode ctx");
                        mem_put(local);
                        STACK_UNWIND_STRICT(writev,frame,-1,EIO,NULL,NULL,NULL);
                        continue;
                }
                ctx_ptr = CAST2PTR(ctx_int);
                if (!hsrepl_writev_continue(frame,this,ctx_ptr)) {
                        gf_log (this->name, GF_LOG_ERROR,
                                "could not retry write");
                        mem_put(local);
                        STACK_UNWIND_STRICT(writev,frame,-1,EIO,NULL,NULL,NULL);
                        continue;
                }
        }
                

        return NULL;
}

int32_t
init (xlator_t *this)
{
	xlator_t         *tgt_xl = NULL;
	hsrepl_private_t *priv = NULL;

	if (!this->children || this->children->next) {
		gf_log (this->name, GF_LOG_ERROR,
			"FATAL: hsrepl should have exactly one child");
		goto err;
	}

	tgt_xl = this->children->xlator;
	/* TBD: check for cluster/afr as well */
	if (strcmp(tgt_xl->type,"cluster/replicate")) {
		gf_log (this->name, GF_LOG_ERROR,
			"%s must be loaded above cluster/replicate",
                        this->type);
		goto err;
	}

        this->local_pool = mem_pool_new(hsrepl_local_t,1024);
        if (!this->local_pool) {
                gf_log (this->name, GF_LOG_ERROR,
                        "FATAL: could not allocate local poool");
                goto err;
        }

	priv = GF_CALLOC (1, sizeof (hsrepl_private_t), gf_hsrepl_mt_priv_t);
        if (!priv) {
                goto free_local_pool;
        }
        LOCK_INIT(&priv->lock);

        /* Begin copy from xattr-prefetch xlator. */
        priv->pool.stack_mem_pool = mem_pool_new(call_stack_t,1000);
        if (!priv->pool.stack_mem_pool) {
                gf_log(this->name,GF_LOG_ERROR,
                       "could not allocate call stacks");
                goto free_priv;
        }

        priv->pool.frame_mem_pool = mem_pool_new(call_frame_t,1000);
        if (!priv->pool.frame_mem_pool) {
                gf_log(this->name,GF_LOG_ERROR,
                       "could not allocate call frames");
                goto free_stack_pool;
        }

        INIT_LIST_HEAD(&priv->pool.all_frames);
        LOCK_INIT(&priv->pool.lock);
        /* End copy from xattr-prefetch xlator. */

        /*
         * Yes, I know this is a creepy thing to do.  Unfortunately, notify
         * functions aren't stackable the same way that fops are, and they're
         * not always propagated upward (nor should they be) so we have to
         * "reach around" to get the information we need.
         */
        priv->real_notify = tgt_xl->notify;
        tgt_xl->notify = hsrepl_notify;

	gf_log (this->name, GF_LOG_DEBUG, "hsrepl xlator loaded");
	this->private = priv;

        (void)pthread_mutex_init(&priv->qlock,NULL);
        (void)pthread_cond_init(&priv->cond,NULL);
        (void)pthread_create(&priv->worker,NULL,hsrepl_worker,this);
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
	hsrepl_private_t *priv = this->private;

        if (!priv)
                return;
        this->private = NULL;

        (void)pthread_cancel(priv->worker);
        (void)pthread_join(priv->worker,NULL);
	GF_FREE (priv);

	return;
}

struct xlator_fops fops = {
	.writev = hsrepl_writev,
};

struct xlator_cbks cbks = {
};

struct volume_options options[] = {
	{ .key  = {NULL} },
};
