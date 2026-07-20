/** BEGIN COPYRIGHT BLOCK
 * Copyright (C) 2026 Red Hat, Inc.
 * All rights reserved.
 *
 * License: GPL (version 3 or any later version).
 * See LICENSE for details.
 * END COPYRIGHT BLOCK **/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

/*
 * Per-operation equality-lookup tables for large OR filters.
 *
 * A search filter (|(uid=v1)...(uid=vk)) costs O(result * k) in the
 * per-entry filter test: every candidate entry walks all k components,
 * and each component independently rescans the entry's attributes and
 * re-normalizes its values through the syntax plugin.  For an OR whose
 * components are equality tests on one shared attribute type, the walk
 * can be inverted: normalize the entry's values once and look each one
 * up in a sorted table of the components' (already normalized)
 * assertion values.  A table hit is then re-verified through the same
 * per-component access-check and match calls the linear walk would have
 * made, so the fast path can only ever pick the component to test, not
 * change the outcome of testing it (see vattr_test_filter_or_lookup in
 * filterentry.c for the evaluation-side contract).
 *
 * Tables are built only on the backend's private per-search filter
 * duplicates (ldbm_back_search pre-digest block), after
 * slapi_filter_normalize(PR_TRUE), so assertion values are already in
 * their matching-rule normal form and the objects are owned by a single
 * operation - no locking, no visibility to psearch/sync/plugin filter
 * evaluations, freed with the node in slapi_filter_free.
 *
 * Eligibility is deliberately narrow.  Only components whose equality
 * truth is "normalized bytes compare equal" may be table members: the
 * string-family syntaxes and DN.  This is the same equivalence the
 * equality index itself relies on (an indexed (uid=x) lookup finds an
 * entry iff the normalized forms agree - see grok_filter/
 * can_skip_filter_test, which skip the filter test outright on that
 * basis for single equality filters).  Everything else - other
 * component types, other syntaxes, subtyped attribute descriptions,
 * values that fail normalization - stays on the classic linear walk.
 */

#include "slap.h"
#include "slapi-private.h"

/*
 * Minimum number of same-type equality components before a table is
 * built.  Small ORs gain nothing from a table (the walk is a handful of
 * comparisons) and organic small ORs - SSSD's few-branch shapes, the
 * 14-branch manager OR in large_filter_test.py - should keep today's
 * code path byte for byte.
 */
#define FILTER_OR_LOOKUP_THRESHOLD 16

/* Mirrors FILTER_OPTIMISE_DEPTH_LIMIT (filter.c) for the annotate walk. */
#define FILTER_OR_LOOKUP_DEPTH_LIMIT 256

/*
 * Syntaxes whose EQUALITY semantics are exactly "compare the normalized
 * forms": the plg_syntax_filter_ava implementations for these families
 * normalize both sides with value_normalize_ext (trim + case fold /
 * sign-zero canonicalization / DN case normalization) and compare
 * byte-wise or with an idempotent case fold.  Deliberately absent:
 * octetstring (the default for attribute types unknown to schema),
 * generalizedTime, boolean, bitString, nameAndOptionalUID (the optional
 * "#bitstring" suffix handling has not been audited), and anything
 * served by collation/i18n or out-of-tree matching rules.
 */
static const char *const or_lookup_syntax_oids[] = {
    DIRSTRING_SYNTAX_OID,
    IA5STRING_SYNTAX_OID,
    INTEGER_SYNTAX_OID,
    NUMERICSTRING_SYNTAX_OID,
    TELEPHONE_SYNTAX_OID,
    DN_SYNTAX_OID,
    NULL
};

/*
 * Official matching rules implemented by the in-tree string family.  If
 * the attribute's EQUALITY rule resolved to a matching-rule plugin, it
 * must be one of these (identified by OID; plg_mr_names lists names and
 * OID): a custom or collation rule normalizes differently from the
 * syntax default and its truth may not be byte equality of our keys.
 */
static const char *const or_lookup_mr_oids[] = {
    "2.5.13.1",                  /* distinguishedNameMatch */
    "2.5.13.2",                  /* caseIgnoreMatch */
    "2.5.13.5",                  /* caseExactMatch */
    "2.5.13.8",                  /* numericStringMatch */
    "2.5.13.14",                 /* integerMatch */
    "2.5.13.20",                 /* telephoneNumberMatch */
    "1.3.6.1.4.1.1466.109.114.1", /* caseExactIA5Match */
    "1.3.6.1.4.1.1466.109.114.2", /* caseIgnoreIA5Match */
    NULL
};

struct or_lookup_family {
    const char *type; /* borrowed from the first branch of this family */
    size_t eligible;
};

static int32_t
or_lookup_oid_in_list(const char *const *list, const char *oid)
{
    if (oid == NULL) {
        return 0;
    }
    for (; *list; list++) {
        if (strcmp(*list, oid) == 0) {
            return 1;
        }
    }
    return 0;
}

static int32_t
or_lookup_mr_in_list(char **mr_names)
{
    const char *const *oid;

    if (mr_names == NULL) {
        return 0;
    }
    for (oid = or_lookup_mr_oids; *oid; oid++) {
        char **name;
        for (name = mr_names; *name; name++) {
            if (strcmp(*name, *oid) == 0) {
                return 1;
            }
        }
    }
    return 0;
}

/*
 * A component may join a table for type T iff it is an equality test on
 * exactly T (no attribute options - subtypes are indexed and matched
 * under their base type with different semantics, the same reason
 * grok_filter_not_subtype refuses the bypass) whose assertion value was
 * normalized by slapi_filter_normalize and was not flagged invalid by
 * the schema check.
 */
static int32_t
or_lookup_child_hashable(const struct slapi_filter *fc, const char *type)
{
    if (fc->f_choice != LDAP_FILTER_EQUALITY) {
        return 0;
    }
    if (fc->f_flags & (SLAPI_FILTER_INVALID_ATTR_UNDEFINE | SLAPI_FILTER_INVALID_ATTR_WARN)) {
        return 0;
    }
    if ((fc->f_flags & SLAPI_FILTER_NORMALIZED_VALUE) == 0) {
        return 0;
    }
    if (fc->f_ava.ava_type == NULL || fc->f_ava.ava_value.bv_val == NULL) {
        return 0;
    }
    if (strchr(fc->f_ava.ava_type, ';') != NULL) {
        return 0;
    }
    return (strcasecmp(fc->f_ava.ava_type, type) == 0);
}

/*
 * filter_normalize_ava sets SLAPI_FILTER_NORMALIZED_VALUE even when DN
 * normalization failed (an unparseable DN keeps its raw bytes under the
 * flag).  Entry values probe with the casefolded form, so a raw-byte
 * key could never match - it must stay on the linear walk, which today
 * compares raw-vs-raw.  Accept a key only if re-normalizing it is a
 * fixed point of slapi_dn_normalize_case_ext.  Lengths are strlen-based
 * throughout (see struct slapi_filter_or_key).
 */
static int32_t
or_lookup_dn_key_valid(const char *key, size_t key_len)
{
    char *copy;
    char *dest = NULL;
    size_t dlen = 0;
    int rc;
    int32_t valid = 0;

    copy = slapi_ch_malloc(key_len + 1);
    memcpy(copy, key, key_len);
    copy[key_len] = '\0';

    rc = slapi_dn_normalize_case_ext(copy, key_len, &dest, &dlen);
    if (rc == 0) {
        /* normalized in place; not NUL terminated */
        valid = (dlen == key_len && memcmp(dest, key, key_len) == 0);
    } else if (rc > 0) {
        valid = (dlen == key_len && memcmp(dest, key, key_len) == 0);
        slapi_ch_free_string(&dest);
    }
    slapi_ch_free_string(&copy);
    return valid;
}

/* Sort by key (length, then bytes); equal keys by list position. */
static int
or_lookup_key_cmp(const void *ap, const void *bp)
{
    const struct slapi_filter_or_key *a = (const struct slapi_filter_or_key *)ap;
    const struct slapi_filter_or_key *b = (const struct slapi_filter_or_key *)bp;
    int rc;

    if (a->ok_len != b->ok_len) {
        return (a->ok_len < b->ok_len) ? -1 : 1;
    }
    rc = memcmp(a->ok_key, b->ok_key, a->ok_len);
    if (rc != 0) {
        return rc;
    }
    if (a->ok_ord != b->ok_ord) {
        return (a->ok_ord < b->ok_ord) ? -1 : 1;
    }
    return 0;
}

/* bsearch comparator: probe key against a table slot (keys are unique). */
static int
or_lookup_probe_cmp(const void *keyp, const void *slotp)
{
    const struct berval *key = (const struct berval *)keyp;
    const struct slapi_filter_or_key *slot = (const struct slapi_filter_or_key *)slotp;

    if ((size_t)key->bv_len != slot->ok_len) {
        return ((size_t)key->bv_len < slot->ok_len) ? -1 : 1;
    }
    return memcmp(key->bv_val, slot->ok_key, slot->ok_len);
}

struct slapi_filter *
filter_or_lookup_probe(const struct slapi_filter_or_lookup *ol, const struct berval *key)
{
    const struct slapi_filter_or_key *slot;

    slot = (const struct slapi_filter_or_key *)bsearch(key, ol->ol_tab, ol->ol_tab_len,
                                                       sizeof(struct slapi_filter_or_key),
                                                       or_lookup_probe_cmp);
    return slot ? slot->ok_branch : NULL;
}

void
filter_or_lookup_free(struct slapi_filter_or_lookup **ol)
{
    if (ol == NULL || *ol == NULL) {
        return;
    }
    slapi_ch_free((void **)&(*ol)->ol_tab);
    slapi_ch_free((void **)&(*ol)->ol_rest);
    slapi_ch_free_string(&(*ol)->ol_type);
    slapi_ch_free((void **)ol);
}

/*
 * Try to annotate one OR node for shared type "type".  Returns the
 * number of table members (pre-dedup, i.e. the k the linear walk would
 * have paid) on success, 0 if the node does not qualify for this type.
 */
static int32_t
or_lookup_annotate_type(struct slapi_filter *f, const char *type)
{
    Slapi_Attr sattr = {0};
    struct slapi_filter *fc;
    struct slapi_filter_or_key *tab = NULL;
    struct slapi_filter **rest = NULL;
    struct slapi_filter_or_lookup *ol = NULL;
    const char *syntax_oid = NULL;
    size_t n_children = 0;
    size_t tab_n = 0;
    size_t rest_n = 0;
    size_t uniq;
    size_t i;
    uint32_t ord = 0;
    int32_t is_dn = 0;
    int32_t eligible = 0;

    for (fc = f->f_or; fc != NULL; fc = fc->f_next) {
        n_children++;
        if (or_lookup_child_hashable(fc, type)) {
            eligible++;
        }
    }
    if (eligible < FILTER_OR_LOOKUP_THRESHOLD) {
        return 0;
    }

    /* Resolve the type once; refuse anything outside the audited families. */
    slapi_attr_init(&sattr, type);
    if (sattr.a_plugin == NULL) {
        slapi_attr_init_syntax(&sattr);
    }
    if (sattr.a_plugin != NULL) {
        syntax_oid = sattr.a_plugin->plg_syntax_oid;
    }
    if (!or_lookup_oid_in_list(or_lookup_syntax_oids, syntax_oid)) {
        attr_done(&sattr);
        return 0;
    }
    if (sattr.a_mr_eq_plugin != NULL &&
        !or_lookup_mr_in_list(sattr.a_mr_eq_plugin->plg_mr_names)) {
        attr_done(&sattr);
        return 0;
    }
    is_dn = (strcmp(syntax_oid, DN_SYNTAX_OID) == 0);
    attr_done(&sattr);

    tab = (struct slapi_filter_or_key *)slapi_ch_calloc(n_children, sizeof(*tab));
    rest = (struct slapi_filter **)slapi_ch_calloc(n_children, sizeof(*rest));

    for (fc = f->f_or; fc != NULL; fc = fc->f_next, ord++) {
        /* strlen, not bv_len: filter_normalize_ava normalizes in place
         * without refreshing bv_len when the value shrinks (trimmed
         * blanks, stripped integer zeros), and the classic walk compares
         * NUL-terminated strings. */
        size_t key_len = (or_lookup_child_hashable(fc, type))
                             ? strlen(fc->f_ava.ava_value.bv_val)
                             : 0;

        if (key_len > 0 &&
            (!is_dn || or_lookup_dn_key_valid(fc->f_ava.ava_value.bv_val, key_len))) {
            tab[tab_n].ok_key = fc->f_ava.ava_value.bv_val;
            tab[tab_n].ok_len = key_len;
            tab[tab_n].ok_branch = fc;
            tab[tab_n].ok_ord = ord;
            tab_n++;
        } else {
            rest[rest_n++] = fc;
        }
    }

    /* DN validation may have demoted members below the threshold. */
    if (tab_n < FILTER_OR_LOOKUP_THRESHOLD) {
        slapi_ch_free((void **)&tab);
        slapi_ch_free((void **)&rest);
        return 0;
    }

    qsort(tab, tab_n, sizeof(*tab), or_lookup_key_cmp);
    /* Collapse duplicate keys, keeping the first component in list order
     * (identical (type, value) means identical match and access outcome,
     * so which duplicate "wins" is unobservable). */
    uniq = 0;
    for (i = 1; i < tab_n; i++) {
        if (tab[uniq].ok_len != tab[i].ok_len ||
            memcmp(tab[uniq].ok_key, tab[i].ok_key, tab[i].ok_len) != 0) {
            uniq++;
            if (uniq != i) {
                tab[uniq] = tab[i];
            }
        }
    }

    ol = (struct slapi_filter_or_lookup *)slapi_ch_calloc(1, sizeof(*ol));
    ol->ol_type = slapi_ch_strdup(type);
    ol->ol_type_is_dn = is_dn;
    ol->ol_tab = tab;
    ol->ol_tab_len = uniq + 1;
    ol->ol_rest = rest;
    ol->ol_rest_len = rest_n;
    f->f_or_lookup = ol;

    return (int32_t)tab_n;
}

static int32_t
or_lookup_annotate(struct slapi_filter *f)
{
    struct slapi_filter *fc;
    struct or_lookup_family *families = NULL;
    struct or_lookup_family *family;
    PLHashTable *by_type = NULL;
    size_t n_children = 0;
    size_t n_families = 0;
    size_t i;
    int32_t k = 0;

    if (f->f_or_lookup != NULL) {
        return 0;
    }

    for (fc = f->f_or; fc != NULL; fc = fc->f_next) {
        n_children++;
    }
    if (n_children < FILTER_OR_LOOKUP_THRESHOLD) {
        return 0;
    }

    /* The array preserves first-occurrence order; the private hash only
     * finds an existing family without imposing an arbitrary family limit. */
    families = (struct or_lookup_family *)slapi_ch_calloc(n_children,
                                                           sizeof(*families));
    by_type = PL_NewHashTable((PRUint32)n_children,
                              hashNocaseString,
                              hashNocaseCompare,
                              PL_CompareValues, 0, 0);
    if (by_type == NULL) {
        goto done;
    }

    for (fc = f->f_or; fc != NULL; fc = fc->f_next) {
        const char *type;

        if (fc->f_choice != LDAP_FILTER_EQUALITY || fc->f_ava.ava_type == NULL ||
            strchr(fc->f_ava.ava_type, ';') != NULL) {
            continue;
        }

        type = fc->f_ava.ava_type;
        family = (struct or_lookup_family *)PL_HashTableLookup(by_type, type);
        if (family == NULL) {
            family = &families[n_families];
            family->type = type;
            if (PL_HashTableAdd(by_type, family->type, family) == NULL) {
                goto done;
            }
            n_families++;
        }
        if (or_lookup_child_hashable(fc, family->type)) {
            family->eligible++;
        }
    }

    /* Preserve the existing first-buildable policy for this correction;
     * usable-family ranking is a separate selection decision. */
    for (i = 0; i < n_families; i++) {
        if (families[i].eligible < FILTER_OR_LOOKUP_THRESHOLD) {
            continue;
        }
        k = or_lookup_annotate_type(f, families[i].type);
        if (k > 0) {
            break;
        }
    }

done:
    if (by_type != NULL) {
        PL_HashTableDestroy(by_type);
    }
    slapi_ch_free((void **)&families);
    return k;
}

static int32_t
or_lookup_build_recurse(struct slapi_filter *f, int32_t depth, int32_t *largest)
{
    struct slapi_filter *fc;
    int32_t count = 0;
    int32_t k;

    if (f == NULL || depth >= FILTER_OR_LOOKUP_DEPTH_LIMIT) {
        return 0;
    }

    switch (f->f_choice) {
    case LDAP_FILTER_OR:
        k = or_lookup_annotate(f);
        if (k > 0) {
            count++;
            if (k > *largest) {
                *largest = k;
            }
        }
    /* FALLTHROUGH */
    case LDAP_FILTER_AND:
    case LDAP_FILTER_NOT:
        for (fc = f->f_list; fc != NULL; fc = fc->f_next) {
            count += or_lookup_build_recurse(fc, depth + 1, largest);
        }
        break;
    default:
        break;
    }
    return count;
}

/*
 * Annotate every qualifying OR node under f.  Returns the number of
 * annotated nodes; *largest is updated with the biggest component count
 * seen.  Caller must own f exclusively (per-operation dup).
 */
int32_t
filter_or_lookup_build(struct slapi_filter *f, int32_t *largest)
{
    if (!config_get_enable_or_filter_lookup()) {
        return 0;
    }
    return or_lookup_build_recurse(f, 0, largest);
}
