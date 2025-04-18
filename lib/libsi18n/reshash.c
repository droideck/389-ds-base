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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "reshash.h"

/* ======================== Value with Language list ==================== */
int
ValueAddLanguageItem(ValueNode *node, char *value, char *language)
{
    ValueNode *prev, *pvalue;

    if (node == NULL)
        return 0;
    if (language == NULL || *language == '\0') {
        /*  should be added to default value */
        return 0;
    }

    prev = pvalue = node;
    while (pvalue != NULL) {
        if ((pvalue->language == NULL) ||
            (strcmp(pvalue->language, language) == 0)) {
            /* if value for the language is already there
               replace it with latest one.
             */
            if (pvalue->language == NULL)
                pvalue->language = strdup(language);
            if (pvalue->value)
                free(pvalue->value);
            pvalue->value = strdup(value);
            return 0;
        }
        prev = pvalue;
        pvalue = pvalue->next;
    }
    pvalue = (ValueNode *)malloc(sizeof(ValueNode));
    memset(pvalue, 0, sizeof(ValueNode));

    prev->next = pvalue;

    pvalue->language = strdup(language);
    pvalue->value = strdup(value);
    return 0;
}

const char *
ValueSearchItem(ValueNode *node, char *language)
{
    ValueNode *pvalue;

    if (node == NULL)
        return NULL;

    pvalue = node;
    while (pvalue && pvalue->language) {
        if (strcmp(pvalue->language, language) == 0) {
            return pvalue->value;
        }
        pvalue = pvalue->next;
    }
    return NULL;
}

void
ValueDestroy(ValueNode *node)
{
    ValueNode *p, *current;
    p = node;
    /* free itself and go next  */
    while (p) {
        current = p;
        p = p->next;
        if (current->language)
            free(current->language);
        if (current->value)
            free(current->value);
    }
}

/* ======================== End of Value with Language list ==================== */


/* ======================== Tree List Implementation============================ */

const char *
TreeSearchItem(TreeNode *res, char *key, char *language)
{
    int k;
    const char *result;

    if (res == NULL || res->key == NULL)
        return NULL;

    k = strcmp(key, res->key);

    if (k > 0) {
        return TreeSearchItem(res->right, key, language);
    } else if (k < 0) {
        return TreeSearchItem(res->left, key, language);
    } else {
        /* Add to the current node; */
        if (language == NULL || *language == '\0')
            return res->value;

        result = ValueSearchItem(res->vlist, language);
        if (result)
            return result;
        else /* fallback to default value if there is any */
            return res->value;
    }
}

/*
   TreeAddItem
     Add value for specific language to the resource tree

    Using binary tree now  --> Balanced tree later
 */
int
TreeAddItem(TreeNode *res, char *key, char *value, char *language)
{
    TreeNode *node;
    ValueNode *vnode;
    int k;

    if (res->key == NULL) {
        res->key = strdup(key);
        k = 0;
    } else {
        k = strcmp(key, res->key);
    }

    if (k > 0) {
        if (res->right == NULL) {
            /* Create node and it's value sub list
             */
            node = (TreeNode *)malloc(sizeof(TreeNode));
            memset(node, 0, sizeof(TreeNode));
            vnode = (ValueNode *)malloc(sizeof(ValueNode));
            memset(vnode, 0, sizeof(ValueNode));
            node->vlist = vnode;

            res->right = node;

            /* assign value to node */
            node->key = strdup(key);
            if (language == NULL)
                node->value = strdup(value);
            else
                ValueAddLanguageItem(node->vlist, value, language);
        } else {
            return TreeAddItem(res->right, key, value, language);
        }
    } else if (k < 0) {
        if (res->left == NULL) {
            node = (TreeNode *)malloc(sizeof(TreeNode));
            memset(node, 0, sizeof(TreeNode));
            vnode = (ValueNode *)malloc(sizeof(ValueNode));
            memset(vnode, 0, sizeof(ValueNode));
            node->vlist = vnode;

            res->left = node;

            /* assign value to node */
            node->key = strdup(key);
            if (language == NULL)
                node->value = strdup(value);
            else
                return ValueAddLanguageItem(node->vlist, value, language);
        } else {
            return TreeAddItem(res->left, key, value, language);
        }
    } else {
        /* Add to the current node; */
        if (language == NULL)
            res->value = strdup(value);
        else
            return ValueAddLanguageItem(res->vlist, value, language);
    }
    return 0;
}

void
TreeDestroy(TreeNode *tree)
{
    if (tree == NULL)
        return;
    if (tree->vlist)
        ValueDestroy(tree->vlist);
    if (tree->key)
        free(tree->key);
    if (tree->value)
        free(tree->value);
    if (tree->left)
        TreeDestroy(tree->left);
    if (tree->right)
        TreeDestroy(tree->right);
}

/* ====================== End of Tree implementation ================= */


/* ====================== Tree controller (hash ?) ================ */
ResHash *
ResHashCreate(char *name)
{
    ResHash *pResHash;

    /* Create hash table  */
    pResHash = (ResHash *)calloc(1, sizeof(ResHash));
    if (pResHash == NULL)
        return NULL;

    if (name)
        pResHash->name = strdup(name);

    /* Create initial tree item and it's valuelist to hash table */
    pResHash->treelist = (TreeNode *)calloc(1, sizeof(TreeNode));
    if (pResHash->treelist == NULL)
        goto error;

    pResHash->treelist->vlist = (ValueNode *)calloc(1, sizeof(ValueNode));
    if (pResHash->treelist->vlist == NULL)
        goto error;

    goto done;

error:
    if (pResHash->treelist) {
        free(pResHash->treelist->vlist);
        free(pResHash->treelist);
    }
    free(pResHash->name);
    free(pResHash);

    return NULL;

done:
    return pResHash;
}

int
ResHashAdd(ResHash *res, char *key, char *value, char *language)
{
#if 0
    hash = get hash value from key
    tree = find the tree associated with hash value
#endif
    return TreeAddItem(res->treelist, key, value, language);
}

const char *
ResHashSearch(ResHash *res, char *key, char *language)
{
#if 0
    hash = get hash value from key
    tree = find the tree associated with hash value
#endif
    return TreeSearchItem(res->treelist, key, language);
}

void
ResHashDestroy(ResHash *res)
{
    if (res == NULL)
        return;
    if (res->name)
        free(res->name);
    if (res->treelist)
        TreeDestroy(res->treelist);
}

/* ========================= End of Tree controller  ====================== */
