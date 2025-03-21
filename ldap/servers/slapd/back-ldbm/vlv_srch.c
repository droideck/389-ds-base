/** BEGIN COPYRIGHT BLOCK
 * Copyright (C) 2001 Sun Microsystems, Inc. Used by permission.
 * Copyright (C) 2005 Red Hat, Inc.
 * All rights reserved.
 *
 * License: GPL (version 3 or any later version).
 * See LICENSE for details.
 * END COPYRIGHT BLOCK **/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

/* vlv_srch.c */


#include "back-ldbm.h"
#include "vlv_srch.h"

/* Attributes for vlvSearch */
char *const type_vlvName = "cn";
char *const type_vlvBase = "vlvBase";
char *const type_vlvScope = "vlvScope";
char *const type_vlvFilter = "vlvFilter";

/* Attributes for vlvIndex */
char *const type_vlvSort = "vlvSort";
char *const type_vlvFilename = "vlvFilename";
char *const type_vlvEnabled = "vlvEnabled";
char *const type_vlvUses = "vlvUses";

static const char *file_prefix = "vlv#"; /* '#' used to avoid collision with real attributes */

static int vlvIndex_equal(const struct vlvIndex *p1, const sort_spec *sort_control);
static void vlvIndex_checkforindex(struct vlvIndex *p, backend *be);

/*
 * Create a new vlvSearch object
 */
struct vlvSearch *
vlvSearch_new()
{
    struct vlvSearch *p = (struct vlvSearch *)slapi_ch_calloc(1, sizeof(struct vlvSearch));
    if (p != NULL) {
        p->vlv_e = NULL;
        p->vlv_dn = NULL;
        p->vlv_name = NULL;
        p->vlv_base = NULL;
        p->vlv_scope = LDAP_SCOPE_BASE;
        p->vlv_filter = NULL;
        p->vlv_slapifilter = NULL;
        p->vlv_index = NULL;
        p->vlv_next = NULL;
    }
    return p;
}

/*
 * Trim spaces off the end of the string
 */
static void
trimspaces(char *s)
{
    if (s) {
        PRUint32 i = strlen(s) - 1;
        while (i > 0 && isascii(s[i]) && isspace(s[i])) {
            s[i] = '\0';
            i--;
        }
    }
}

/*
 * Re-Initialise a vlvSearch object
 */
void
vlvSearch_reinit(struct vlvSearch *p, const struct backentry *base)
{
    if (p->vlv_initialized) {
        return; /* no work to do */
    }
    if (LDAP_SCOPE_ONELEVEL != p->vlv_scope) {
        /* Only kind we re-init is onelevel searches */
        return;
    }
    /* Now down to work */
    if (NULL != p->vlv_slapifilter) {
        slapi_filter_free(p->vlv_slapifilter, 1);
    }
    p->vlv_slapifilter = slapi_str2filter(p->vlv_filter);
    filter_normalize(p->vlv_slapifilter);
    /* make (&(parentid=idofbase)(|(originalfilter)(objectclass=referral))) */
    p->vlv_slapifilter = create_onelevel_filter(p->vlv_slapifilter, base, 0 /* managedsait */);
    slapi_filter_optimise(p->vlv_slapifilter);
}

/*
 * Initialise a vlvSearch object
 */
void
vlvSearch_init(struct vlvSearch *p, Slapi_PBlock *pb, const Slapi_Entry *e, ldbm_instance *inst)
{
    /* VLV specification */
    /* Need to copy the entry here because this one is in the cache,
     * not forever ! */
    p->vlv_e = slapi_entry_dup(e);
    p->vlv_dn = slapi_sdn_dup(slapi_entry_get_sdn_const(e));
    p->vlv_name = slapi_entry_attr_get_charptr(e, type_vlvName);
    p->vlv_base = slapi_sdn_new_dn_passin(slapi_entry_attr_get_charptr(e, type_vlvBase));
    p->vlv_scope = slapi_entry_attr_get_int(e, type_vlvScope);
    p->vlv_filter = slapi_entry_attr_get_charptr(e, type_vlvFilter);
    p->vlv_initialized = 1;

    /* JCM: Should perform some validation and report errors to the error log */
    /* JCM: Add brackets around the filter if none are there... */
    trimspaces(p->vlv_name);
    trimspaces(p->vlv_filter);

    if (strlen(p->vlv_filter) > 0) {
        /* Convert the textual filter, into a Slapi_Filter structure */
        p->vlv_slapifilter = slapi_str2filter(p->vlv_filter);
        filter_normalize(p->vlv_slapifilter);
    }

    /* JCM: Really should convert the slapifilter into a string and use that. */

    /* Convert the filter based on the scope of the search */
    switch (p->vlv_scope) {
    case LDAP_SCOPE_BASE:
        /* Don't need to alter the filter */
        break;
    case LDAP_SCOPE_ONELEVEL: {
        /*
         * Get the base object for the search.
         * The entry "" will never be contained in the database,
         * so treat it as a special case.
         */
        struct backentry *e = NULL;
        if (!slapi_sdn_isempty(p->vlv_base)) {
            Slapi_Backend *oldbe = NULL;
            entry_address addr;
            back_txn txn = {NULL};

            /* switch context to the target backend */
            slapi_pblock_get(pb, SLAPI_BACKEND, &oldbe);
            slapi_pblock_set(pb, SLAPI_BACKEND, inst->inst_be);
            slapi_pblock_set(pb, SLAPI_PLUGIN, inst->inst_be->be_database);
            slapi_pblock_get(pb, SLAPI_TXN, &txn.back_txn_txn);

            addr.sdn = p->vlv_base;
            addr.uniqueid = NULL;
            e = find_entry(pb, inst->inst_be, &addr, &txn, NULL);
            /* Check to see if the entry is absent. If it is, mark this search
             * as not initialized */
            if (NULL == e) {
                p->vlv_initialized = 0;
                /* We crash on anyhow, and rely on the fact that the filter
                 * we create is bogus to prevent chaos */
            }

            /* switch context back to the DSE backend */
            /* coverity[var_deref_model] */
            slapi_pblock_set(pb, SLAPI_BACKEND, oldbe);
            if (oldbe) {
                slapi_pblock_set(pb, SLAPI_PLUGIN, oldbe->be_database);
            }
        }

        /* make (&(parentid=idofbase)(|(originalfilter)(objectclass=referral))) */
        {
            p->vlv_slapifilter = create_onelevel_filter(p->vlv_slapifilter, e, 0 /* managedsait */);
            slapi_filter_optimise(p->vlv_slapifilter);
            CACHE_RETURN(&inst->inst_cache, &e);
        }
    } break;
    case LDAP_SCOPE_SUBTREE: {
        /* make (|(originalfilter)(objectclass=referral))) */
        /* No need for scope-filter since we apply a scope test before the filter test */
        p->vlv_slapifilter = create_subtree_filter(p->vlv_slapifilter, 0 /* managedsait */);
        slapi_filter_optimise(p->vlv_slapifilter);
    } break;
    }
}

/*
 * Destroy an existing vlvSearch object
 */
void
vlvSearch_delete(struct vlvSearch **ppvs)
{
    if (ppvs != NULL && *ppvs != NULL) {
        struct vlvIndex *pi, *ni;
        if ((*ppvs)->vlv_e) {
            slapi_entry_free((struct slapi_entry *)((*ppvs)->vlv_e));
        }
        slapi_sdn_free(&((*ppvs)->vlv_dn));
        slapi_ch_free((void **)&((*ppvs)->vlv_name));
        slapi_sdn_free(&((*ppvs)->vlv_base));
        slapi_ch_free((void **)&((*ppvs)->vlv_filter));
        slapi_filter_free((*ppvs)->vlv_slapifilter, 1);
        for (pi = (*ppvs)->vlv_index; pi != NULL;) {
            ni = pi->vlv_next;
            if (pi->vlv_be != NULL) {
                vlvIndex_go_offline(pi, pi->vlv_be);
            }
            vlvIndex_delete(&pi);
            pi = ni;
        }
        slapi_ch_free((void **)ppvs);
    }
}

/*
 * Add a search to a list.
 *
 * We add it to the end of the list because there could
 * be other threads traversing the list at this time.
 */
void
vlvSearch_addtolist(struct vlvSearch *p, struct vlvSearch **pplist)
{
    if (pplist != NULL && p != NULL) {
        p->vlv_next = NULL;
        if (*pplist == NULL) {
            *pplist = p;
        } else {
            struct vlvSearch *last = *pplist;
            for (; last->vlv_next != NULL; last = last->vlv_next)
                ;
            last->vlv_next = p;
        }
    }
}


/*
 * Compare two VLV Searches to see if they're the same, based on their VLV Search specification.
 */
static struct vlvIndex *
vlvSearch_equal(const struct vlvSearch *p1, const Slapi_DN *base, int scope, const char *filter, const sort_spec *sort_control)
{
    struct vlvIndex *pi = NULL;
    int r = (slapi_sdn_compare(p1->vlv_base, base) == 0);
    if (r)
        r = (p1->vlv_scope == scope);
    if (r)
        r = (strcasecmp(p1->vlv_filter, filter) == 0);
    if (r) {
        pi = p1->vlv_index;
        r = 0;
        for (; !r && pi != NULL;) {
            r = vlvIndex_equal(pi, sort_control);
            if (!r) {
                pi = pi->vlv_next;
            }
        }
    }
    return pi;
}

/*
 * Find an enabled VLV Search in a list which matches the
 * description provided in "base, scope, filter, sort_control"
 */
struct vlvIndex *
vlvSearch_findenabled(backend *be, struct vlvSearch *plist, const Slapi_DN *base, int scope, const char *filter, const sort_spec *sort_control)
{
    struct vlvSearch *t = plist;
    struct vlvIndex *pi = NULL;
    for (; (t != NULL) && (pi == NULL); t = t->vlv_next) {
        pi = vlvSearch_equal(t, base, scope, filter, sort_control);
        if (pi != NULL) {
            if (!vlvIndex_enabled(pi)) {
                /*
                 * A VLV Spec which matched the search criteria was found.
                 * But it hasn't been enabled yet.  Check to see if the
                 * index is there.  But, only check once every 60 seconds.
                 */
                if (slapi_timespec_expire_check(&(pi->vlv_nextcheck)) == TIMER_EXPIRED) {
                    vlvIndex_checkforindex(pi, be);
                    slapi_timespec_expire_at(60, &(pi->vlv_nextcheck));
                }
            }
            if (!vlvIndex_enabled(pi)) {
                pi = NULL;
            }
        }
    }
    return pi;
}

/*
 * Find a VLV Search in a list which matches the name
 */
struct vlvIndex *
vlvSearch_findname(const struct vlvSearch *plist, const char *name)
{
    const struct vlvSearch *t = plist;
    for (; t != NULL; t = t->vlv_next) {
        struct vlvIndex *pi = t->vlv_index;
        for (; pi != NULL; pi = pi->vlv_next) {
            if (strcasecmp(pi->vlv_name, name) == 0) {
                return pi;
            }
        }
    }
    return NULL;
}

/*
 * Find a VLV Search in a list which matches the index name
 */
struct vlvIndex *
vlvSearch_findindexname(const struct vlvSearch *plist, const char *name)
{
    const struct vlvSearch *t = plist;
    if (NULL == name) {
        return NULL;
    }
    for (; t != NULL; t = t->vlv_next) {
        struct vlvIndex *pi = t->vlv_index;
        for (; pi != NULL; pi = pi->vlv_next) {
            if (strcasecmp(pi->vlv_attrinfo->ai_type, name) == 0) {
                return pi;
            }
        }
    }
    return NULL;
}

/*
 * Get a list of VLV Index names.
 * The returned pointer must be freed with slapi_ch_free
 */
char *
vlvSearch_getnames(const struct vlvSearch *plist)
{
    /* Work out how long the string will be */
    char *text;
    int length = 5; /* enough to hold 'none' */
    const struct vlvSearch *t = plist;
    for (; t != NULL; t = t->vlv_next) {
        struct vlvIndex *pi = t->vlv_index;
        for (; pi != NULL; pi = pi->vlv_next) {
            length += strlen(pi->vlv_name) + 4;
        }
    }
    /* Build a comma delimited list of Index names */
    text = slapi_ch_malloc(length);
    if (length == 5) {
        strcpy(text, "none");
    } else {
        text[0] = '\0';
        t = plist;
        for (; t != NULL; t = t->vlv_next) {
            struct vlvIndex *pi = t->vlv_index;
            for (; pi != NULL; pi = pi->vlv_next) {
                sprintf(text + strlen(text), "'%s', ", pi->vlv_name);
            }
        }
    }
    return text;
}

/*
 * Find a VLV Search in a list, based on the DN.
 */
struct vlvSearch *
vlvSearch_finddn(const struct vlvSearch *plist, const Slapi_DN *dn)
{
    const struct vlvSearch *curr = plist;
    for (; curr != NULL && slapi_sdn_compare(curr->vlv_dn, dn) != 0; curr = curr->vlv_next)
        ;
    return (struct vlvSearch *)curr;
}

/*
 * Remove a VLV Search from a list, based on the DN.
 */
void
vlvSearch_removefromlist(struct vlvSearch **pplist, const Slapi_DN *dn)
{
    int done = 0;
    struct vlvSearch *prev = NULL;
    struct vlvSearch *curr = *pplist;
    while (curr != NULL && !done) {
        if (slapi_sdn_compare(curr->vlv_dn, dn) == 0) {
            if (curr == *pplist) {
                *pplist = curr->vlv_next;
            } else {
                if (prev)
                    prev->vlv_next = curr->vlv_next;
            }
            done = 1;
        } else {
            prev = curr;
            curr = curr->vlv_next;
        }
    }
}

/*
 * Access Control Check to see if the client is allowed to use this VLV Search.
 */
int
vlvSearch_accessallowed(struct vlvSearch *p, Slapi_PBlock *pb)
{
    char *attrs[2] = {NULL, NULL};

    attrs[0] = type_vlvName;
    return (plugin_call_acl_plugin(pb, (Slapi_Entry *)p->vlv_e, attrs, NULL,
                                   SLAPI_ACL_READ, ACLPLUGIN_ACCESS_READ_ON_VLV, NULL));
}

const Slapi_DN *
vlvSearch_getBase(struct vlvSearch *p)
{
    return p->vlv_base;
}

int
vlvSearch_getScope(struct vlvSearch *p)
{
    return p->vlv_scope;
}

Slapi_Filter *
vlvSearch_getFilter(struct vlvSearch *p)
{
    return p->vlv_slapifilter;
}

int
vlvSearch_isVlvSearchEntry(Slapi_Entry *e)
{
    return slapi_entry_attr_hasvalue(e, "objectclass", "vlvsearch");
}

void
vlvSearch_addIndex(struct vlvSearch *pSearch, struct vlvIndex *pIndex)
{
    pIndex->vlv_next = NULL;
    if (pSearch->vlv_index == NULL) {
        pSearch->vlv_index = pIndex;
    } else {
        struct vlvIndex *last = pSearch->vlv_index;
        for (; last->vlv_next != NULL; last = last->vlv_next)
            ;
        last->vlv_next = pIndex;
    }
}

/* ============================================================================================== */

/*
 * Create a new vlvIndex object
 */
struct vlvIndex *
vlvIndex_new()
{
    struct vlvIndex *p = (struct vlvIndex *)slapi_ch_calloc(1, sizeof(struct vlvIndex));
    if (p != NULL) {
        p->vlv_attrinfo = attrinfo_new();
        p->vlv_indexlength_lock = PR_NewLock();
        p->vlv_online = 1;
    }
    return p;
}

/*
 * Destroy an existing vlvIndex object
 */
void
vlvIndex_delete(struct vlvIndex **ppvs)
{
    if (ppvs != NULL && *ppvs != NULL) {
        slapi_ch_free((void **)&((*ppvs)->vlv_sortspec));
        if ((*ppvs)->vlv_sortkey != NULL)
        {
            int n;
            for (n = 0; (*ppvs)->vlv_sortkey[n] != NULL; n++) {
                if ((*ppvs)->vlv_mrpb[n] != NULL) {
                    destroy_matchrule_indexer((*ppvs)->vlv_mrpb[n]);
                    slapi_pblock_destroy((*ppvs)->vlv_mrpb[n]);
                }
            }
        }
        internal_ldap_free_sort_keylist((*ppvs)->vlv_sortkey);
        dblayer_erase_index_file((*ppvs)->vlv_be, (*ppvs)->vlv_attrinfo, PR_FALSE, 1 /* chkpt if not busy */);
        attrinfo_delete(&((*ppvs)->vlv_attrinfo));
        slapi_ch_free((void **)&((*ppvs)->vlv_name));
        slapi_ch_free((void **)&((*ppvs)->vlv_filename));
        slapi_ch_free((void **)&((*ppvs)->vlv_mrpb));
        PR_DestroyLock((*ppvs)->vlv_indexlength_lock);
        slapi_ch_free((void **)ppvs);
        *ppvs = NULL;
    }
}

/*
 * Initialise a vlvSearch object
 */
void
vlvIndex_init(struct vlvIndex *p, backend *be, struct vlvSearch *pSearch, const Slapi_Entry *e)
{
    struct ldbminfo *li = (struct ldbminfo *)be->be_database->plg_private;
    const char *file_suffix = dblayer_get_db_suffix(be);
    char *filename = NULL;

    if (NULL == p)
        return;

    /* JCM: Should perform some validation and report errors to the error log */
    /* JCM: Add brackets around the filter if none are there... */
    p->vlv_sortspec = slapi_entry_attr_get_charptr(e, type_vlvSort);
    trimspaces(p->vlv_sortspec);

    p->vlv_name = slapi_entry_attr_get_charptr(e, type_vlvName);
    trimspaces(p->vlv_name);

    p->vlv_search = pSearch;

    /* Convert the textual sort specification into a keylist structure */
    internal_ldap_create_sort_keylist(&(p->vlv_sortkey), p->vlv_sortspec);
    {
        /*
         * For each sort attribute find the appropriate syntax plugin,
         * and if it has a matching rule, create a matching rule indexer object.
         */
        int n;
        for (n = 0; p->vlv_sortkey[n] != NULL; n++)
            ;
        p->vlv_mrpb = (Slapi_PBlock **)slapi_ch_calloc(n + 1, sizeof(Slapi_PBlock *));
        for (n = 0; p->vlv_sortkey[n] != NULL; n++) {
            if (p->vlv_sortkey[n]->sk_matchruleoid != NULL) {
                create_matchrule_indexer(&p->vlv_mrpb[n], p->vlv_sortkey[n]->sk_matchruleoid, p->vlv_sortkey[n]->sk_attrtype);
            }
        }
    }

    /* Create an index filename for the search */
    filename = vlvIndex_build_filename(p->vlv_name);
    if (filename) {
        p->vlv_filename = slapi_ch_smprintf("%s%s", filename, file_suffix);

        /* Create an attrinfo structure */
        p->vlv_attrinfo->ai_type = filename;
        p->vlv_attrinfo->ai_indexmask = INDEX_VLV;

        /* Check if the index file actually exists */
        if (li != NULL) {
            vlvIndex_checkforindex(p, be);
        }
        slapi_timespec_expire_at(60, &(p->vlv_nextcheck));
    } else {
        slapi_log_err(SLAPI_LOG_ERR, "vlvIndex_init",
                      "Couldn't generate valid filename from Virtual List View Index Name (%s)"
                      " on backend %s. Need some alphabetical characters.\n",
                      p->vlv_name, be->be_name);
    }
}

/*
 * Determine how many {key,data} pairs there are in the VLV Index.
 * We only work out the length of the index once, then we cache
 * it and maintain it.
 */
PRUint32
vlvIndex_get_indexlength(backend *be, struct vlvIndex *p, dbi_db_t *db, back_txn *txn)
{
    int nbentries = 0;
    int err = 0;

    if (NULL == p)
        return 0;

    if (!p->vlv_indexlength_cached) {
        PR_Lock(p->vlv_indexlength_lock);
        err = dblayer_get_entries_count(be, db, (txn ? txn->back_txn_txn : NULL), &nbentries);
        if (err == 0) {
            p->vlv_indexlength_cached = 1;
            p->vlv_indexlength = nbentries;
        }
        PR_Unlock(p->vlv_indexlength_lock);
    }

    return p->vlv_indexlength;
}

/*
 * Increment the index length count.
 * We keep track of the index length for efficiency.
 */
void
vlvIndex_increment_indexlength(backend *be, struct vlvIndex *p, dbi_db_t *db, back_txn *txn)
{
    if (NULL == p)
        return;

    if (p->vlv_indexlength_cached) {
        PR_Lock(p->vlv_indexlength_lock);
        p->vlv_indexlength++;
        PR_Unlock(p->vlv_indexlength_lock);
    } else {
        p->vlv_indexlength = vlvIndex_get_indexlength(be, p, db, txn);
    }
}

/*
 * Decrement the index length count.
 * We keep track of the index length for efficiency.
 */
void
vlvIndex_decrement_indexlength(backend *be, struct vlvIndex *p, dbi_db_t *db, back_txn *txn)
{
    if (NULL == p)
        return;

    if (p->vlv_indexlength_cached) {
        /* jcm: Check for underflow? */
        PR_Lock(p->vlv_indexlength_lock);
        p->vlv_indexlength--;
        PR_Unlock(p->vlv_indexlength_lock);
    } else {
        p->vlv_indexlength = vlvIndex_get_indexlength(be, p, db, txn);
    }
}

/*
 * Increment the usage counter
 */
void
vlvIndex_incrementUsage(struct vlvIndex *p)
{
    if (NULL == p)
        return;
    p->vlv_uses++;
}

/*
 * Get the filename of the index.
 */
const char *
vlvIndex_filename(const struct vlvIndex *p)
{
    if (NULL == p)
        return NULL;
    return p->vlv_filename;
}

/*
 * Check if the index is available.
 */
int
vlvIndex_enabled(const struct vlvIndex *p)
{
    if (NULL == p)
        return 0;
    return p->vlv_enabled;
}

int
vlvIndex_online(const struct vlvIndex *p)
{
    if (NULL == p)
        return 0;
    return p->vlv_online;
}

void
vlvIndex_go_offline(struct vlvIndex *p, backend *be)
{
    if (NULL == p)
        return;
    p->vlv_online = 0;
    p->vlv_enabled = 0;
    p->vlv_indexlength = 0;
    p->vlv_attrinfo->ai_indexmask |= INDEX_OFFLINE;
    dblayer_erase_index_file(be, p->vlv_attrinfo, PR_FALSE, 1 /* chkpt if not busy */);
}

void
vlvIndex_go_online(struct vlvIndex *p, backend *be)
{
    if (NULL == p)
        return;
    p->vlv_attrinfo->ai_indexmask &= ~INDEX_OFFLINE;
    p->vlv_online = 1;
    vlvIndex_checkforindex(p, be);
}


/*
 * Access Control Check to see if the client is allowed to use this VLV Index.
 */
int
vlvIndex_accessallowed(struct vlvIndex *p, Slapi_PBlock *pb)
{
    if (NULL == p)
        return 0;
    return vlvSearch_accessallowed(p->vlv_search, pb);
}

const Slapi_DN *
vlvIndex_getBase(struct vlvIndex *p)
{
    if (NULL == p)
        return NULL;
    return vlvSearch_getBase(p->vlv_search);
}

int
vlvIndex_getScope(struct vlvIndex *p)
{
    if (NULL == p)
        return 0;
    return vlvSearch_getScope(p->vlv_search);
}

Slapi_Filter *
vlvIndex_getFilter(struct vlvIndex *p)
{
    if (NULL == p)
        return NULL;
    return vlvSearch_getFilter(p->vlv_search);
}

const char *
vlvIndex_getName(struct vlvIndex *p)
{
    if (NULL == p)
        return NULL;
    return p->vlv_name;
}

/*
 *  JCM: Could also match reverse sense of index and use in reverse.
 */
static int
vlvIndex_equal(const struct vlvIndex *p1, const sort_spec *sort_control)
{
    int r = 1;
    const sort_spec *t1 = sort_control;
    LDAPsortkey *t2 = p1->vlv_sortkey[0];
    int n = 1;
    for (; t1 != NULL && t2 != NULL && r; t1 = t1->next, t2 = p1->vlv_sortkey[n], n++) {
        r = (t1->order && t2->sk_reverseorder) || (!t1->order && !t2->sk_reverseorder);
        if (r)
            r = (strcasecmp(t1->type, t2->sk_attrtype) == 0);
        if (r) {
            if (t1->matchrule == NULL && t2->sk_matchruleoid == NULL) {
                r = 1;
            } else if (t1->matchrule != NULL && t2->sk_matchruleoid != NULL) {
                r = (strcasecmp(t1->matchrule, t2->sk_matchruleoid) == 0);
            } else {
                r = 0;
            }
        }
    }
    if (r)
        r = (t1 == NULL && t2 == NULL);
    return r;
}

/*
 * Check if the index file actually exists,
 * and set vlv_enabled appropriately
 */
static void
vlvIndex_checkforindex(struct vlvIndex *p, backend *be)
{
    struct ldbminfo *li = (struct ldbminfo *)be->be_database->plg_private;
    dbi_db_t *db = NULL;


    /* if the vlv index is offline (being generated), don't even look */
    if (!p->vlv_online) {
        /* In lmdb case, always open the dbi */
        if (li->li_flags & LI_LMDB_IMPL) {
            (void) dblayer_get_index_file(be, p->vlv_attrinfo, &db, 0) ;
            dblayer_release_index_file(be, p->vlv_attrinfo, db);
        }
        return;
    }

    if (dblayer_get_index_file(be, p->vlv_attrinfo, &db, 0) == 0) {
        p->vlv_enabled = 1;
        dblayer_release_index_file(be, p->vlv_attrinfo, db);
    } else {
        p->vlv_enabled = 0;
    }
}

int
vlvIndex_isVlvIndexEntry(Slapi_Entry *e)
{
    return slapi_entry_attr_hasvalue(e, "objectclass", "vlvindex");
}

/*
 * Generate the vlv db file name from the vlv name.
 * Return NULL if vlv name cannot be converted to db name
 */
char *
vlvIndex_build_filename(const char *vlvname)
{
    size_t len = strlen(vlvname);
    size_t len_prefix = strlen(file_prefix);
    char *filename = slapi_ch_malloc(len_prefix + len + 1);
    char *pt = filename;
    strcpy(pt, file_prefix);
    pt += len_prefix;
    for (;*vlvname; vlvname++) {
        if (isalnum(*vlvname)) {
            *pt++ = TOLOWER(*vlvname);
        }
    }
    *pt = '\0';
    if (strcmp(pt, file_prefix) == 0) {
        slapi_ch_free_string(&filename);
    }
    return filename;
}

int
vlv_isvlv(char *filename)
{
    if (0 == strncmp(filename, file_prefix, 4))
        return 1;
    return 0;
}

void
internal_ldap_free_sort_keylist(LDAPsortkey **sortKeyList)
{
    ldap_free_sort_keylist((LDAPSortKey **)sortKeyList);
}

int
internal_ldap_create_sort_keylist(LDAPsortkey ***sortKeyList, const char *string_rep)
{
    return ldap_create_sort_keylist((LDAPSortKey ***)sortKeyList, (char *)string_rep);
}
