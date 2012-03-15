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

#define PARTNER_XATTR "trusted.hsrepl.partner-xattr"

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
                if ((i == dest) || !up[i]) {
                        continue;
                }

		if (gf_asprintf(&key,"trusted.afr.%s",trav->xlator->name) < 0) {
			gf_log (this->name, GF_LOG_WARNING,
				"failed to allocate key");
			goto free_dict;
		}
		value = GF_CALLOC(3,sizeof(*value),gf_hsrepl_mt_int32_t);
		if (!value) {
			gf_log (this->name, GF_LOG_WARNING,
				"failed to allocate value");
			goto free_key;
		}
                if (incrs[dest] != 1) {
                        gf_log (this->name, GF_LOG_DEBUG, "%s -= %u for %u",
                                key, incrs[dest], dest);
                }
                /* Amazingly, there's no constant for this. */
                value[0] = htonl(-incrs[dest]);
		if (dict_set_dynptr(dict,key,value,3*sizeof(*value)) < 0) {
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
                 int32_t op_ret, int32_t op_errno, dict_t *dict)
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
                   struct iatt *postbuf, uint32_t version)
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
                gf_log (this->name, GF_LOG_DEBUG, "retrying wrong version");
                LOCK(&priv->lock);
                local->calls = priv->up_count;
                memcpy(up_copy,priv->up,sizeof(up_copy));
                UNLOCK(&priv->lock);
                if (local->calls) {
                        local->errors = 0;
                        local->conflicts = 0;
                        trav = this->children->xlator->children;
                        for (i = 0; i < 2; ++i) {
                                if (!up_copy[i]) {
                                        continue;
                                }
                                gf_log (this->name, GF_LOG_DEBUG,
                                        "re-sending version %u to %u",
                                        ctx->versions[i], i);
                                /* TBD: use a queue+thread to avoid recursion */
                                STACK_WIND_COOKIE(frame,hsrepl_writev_cbk,
                                        CAST2PTR(i), trav->xlator,
                                        trav->xlator->fops->writev_vers,
                                        local->fd, local->vector, local->count,
                                        local->off, local->flags, local->iobref,
                                        ctx->versions[i]);
                                trav = trav->next;
                        }
                        return 0;
                }
        }

        iobref_unref(local->iobref);

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
                                    local->fd, GF_XATTROP_ADD_ARRAY, dict);
                        dict_unref(dict);
                        trav = trav->next;
                }
        }
        else {
                STACK_DESTROY(newframe->root);
        }

unwind:
        STACK_UNWIND_STRICT(writev, frame, op_ret, op_errno, prebuf, postbuf);
out:
        return 0;

err:
        fd_unref(local->fd);
        STACK_UNWIND_STRICT(writev, frame, -1, ENOMEM, NULL, NULL);
        return 0;
}

int32_t
hsrepl_writev (call_frame_t *frame, xlator_t *this, fd_t *fd,
               struct iovec *vector, int32_t count, off_t off,
               uint32_t flags, struct iobref *iobref)
{
        hsrepl_local_t   *local  = NULL;
        xlator_list_t    *trav   = NULL;
        uint8_t           i      = 0;
        uint64_t          ctx_int = 0;
        hsrepl_ctx_t     *ctx_ptr = NULL;
        uint32_t          op_errno = ENOMEM;
        gf_boolean_t      up_copy[2] = { _gf_false, };
        hsrepl_private_t *priv = this->private;

        local = mem_get0(this->local_pool);
        if (!local) {
                goto err;
        }

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
        local->good_op_ret = -1;
        local->good_op_errno = EINVAL;
        frame->local = local;

        LOCK(&priv->lock);
        local->calls = priv->up_count;
        memcpy(up_copy,priv->up,sizeof(up_copy));
        UNLOCK(&priv->lock);
        if (!local->calls) {
                op_errno = ENOTCONN;
                goto free_local;
        }
        if (local->calls != 2) {
                gf_log (this->name, GF_LOG_DEBUG,
                        "only sending to %u subvols", local->calls);
        }

        trav = this->children->xlator->children;
        for (i = 0; i < 2; ++i, trav = trav->next) {
                if (!up_copy[i]) {
                        continue;
                }
                gf_log (this->name, GF_LOG_DEBUG,
                        "sending version %u to %u",
                        ctx_ptr->versions[i], i);
                STACK_WIND_COOKIE(frame,hsrepl_writev_cbk,CAST2PTR(i),
                        trav->xlator, trav->xlator->fops->writev_vers,
                        fd, vector, count, off, flags, iobref,
                        ctx_ptr->versions[i]);
        }

        return 0;

free_ctx:
        GF_FREE(ctx_ptr);
free_local:
        mem_put(local);
        fd_unref(fd);
        iobref_unref(iobref);
err:
        STACK_UNWIND_STRICT(writev, frame, -1, ENOMEM, NULL, NULL);
        return 0;
}

int32_t
hsrepl_np_cbk (call_frame_t *frame, void *cookie, xlator_t *this,
               int32_t op_ret, int32_t op_errno)
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

        dict = dict_new();
        if (!dict) {
                gf_log (this->name, GF_LOG_ERROR, "could not create dict");
                goto err;
        }

        for (trav = this->children->xlator->children; trav; trav = trav->next) {
                child2 = trav->xlator;
                if (child2 == child1) {
                        continue;
                }

                if (dict_set_str(dict,PARTNER_XATTR,child2->name) != 0) {
                        gf_log (this->name, GF_LOG_ERROR,
                                "could not create dict entry");
                        continue;
                }

                newframe = create_frame(this,&priv->pool);
                if (!newframe) {
                        gf_log (this->name,GF_LOG_ERROR,
                                "could not create notify frame");
                        continue;
                }

                /* This is sufficient to identify the root gfid. */
                tmploc.gfid[15] = 1;

                STACK_WIND_COOKIE (newframe, hsrepl_np_cbk, child1,
                                   child1, child1->fops->setxattr,
                                   &tmploc, dict, 0);
                /* TBD: support multiple partners */
                return;

        }

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

gf_boolean_t
hsrepl_link_partners (xlator_t *this, xlator_t *afr)
{
        xlator_list_t   *kid1 = NULL;
        xlator_list_t   *kid2 = NULL;

        for (kid1 = afr->children; kid1; kid1 = kid1->next) {
                for (kid2 = afr->children; kid2; kid2 = kid2->next) {
                        if (kid2 == kid1) {
                                continue;
                        }
                        gf_log (this->name, GF_LOG_DEBUG, "tell %s about %s",
                                kid1->xlator->name, kid2->xlator->name);
                }
        }

        return _gf_true;
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

        hsrepl_link_partners(this,tgt_xl);

	gf_log (this->name, GF_LOG_DEBUG, "hsrepl xlator loaded");
	this->private = priv;
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
