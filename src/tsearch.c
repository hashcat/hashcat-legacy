
#include "common.h"
#include "tsearch.h"

static void hc_maybe_split_for_insert (hc_node *rootp, hc_node *parentp, hc_node *gparentp, int p_r, int gp_r, int mode)
{
  hc_node root = *rootp;
  hc_node *rp, *lp;
  rp = &(*rootp)->right;
  lp = &(*rootp)->left;

  /* See if we have to split this node (both successors red). */
  if ((mode == 1) || ((*rp) != NULL && (*lp) != NULL && (*rp)->red && (*lp)->red))
  {
    /* This node becomes red, its successors black.  */
    root->red = 1;

    if (*rp) (*rp)->red = 0;
    if (*lp) (*lp)->red = 0;

    /* If the parent of this node is also red, we have to do rotations. */
    if (parentp != NULL && (*parentp)->red)
    {
      hc_node gp = *gparentp;
      hc_node p = *parentp;
      /* There are two main cases:
       1. The edge types (left or right) of the two red edges differ.
       2. Both red edges are of the same type.
       There exist two symmetries of each case, so there is a total of 4 cases. */

      if ((p_r > 0) != (gp_r > 0))
      {
        /* Put the child at the top of the tree, with its parent and grandparent as successors. */
        p->red = 1;
        gp->red = 1;
        root->red = 0;

        if (p_r < 0)
        {
          /* Child is left of parent. */
          p->left = *rp;
          *rp = p;
          gp->right = *lp;
          *lp = gp;
        }
        else
        {
          /* Child is right of parent. */
          p->right = *lp;
          *lp = p;
          gp->left = *rp;
          *rp = gp;
        }

        *gparentp = root;
      }
      else
      {
        *gparentp = *parentp;
        /* Parent becomes the top of the tree, grandparent and child are its successors. */
        p->red = 0;
        gp->red = 1;
        if (p_r < 0)
        {
          /* Left edges. */
          gp->left = p->right;
          p->right = gp;
        }
        else
        {
          /* Right edges.  */
          gp->right = p->left;
          p->left = gp;
        }
      }
    }
  }
}

/*
 * Find or insert datum into search tree.
 * KEY is the key to be located, ROOTP is the address of tree root,
 * COMPAR the ordering function.
 */
void * __hc_tsearch (const void *key, void **vrootp, __hc_compar_fn_t compar)
{
  hc_node q;
  hc_node *parentp = NULL, *gparentp = NULL;
  hc_node *rootp = (hc_node *) vrootp;
  hc_node *nextp;

  int r = 0, p_r = 0, gp_r = 0; /* No they might not, Mr Compiler.  */

  if (rootp == NULL) return NULL;

  /* This saves some additional tests below. */
  if (*rootp != NULL) (*rootp)->red = 0;

  nextp = rootp;
  while (*nextp != NULL)
  {
    hc_node root = *rootp;
    r = (*compar) (key, root->key);

    if (r == 0) return root;

    hc_maybe_split_for_insert (rootp, parentp, gparentp, p_r, gp_r, 0);

    /*
     * If that did any rotations, parentp and gparentp are now garbage.
     * That doesn't matter, because the values they contain are never
     * used again in that case.
     */

    nextp = (r < 0) ? &root->left : &root->right;

    if (*nextp == NULL) break;

    gparentp = parentp;
    parentp = rootp;
    rootp = nextp;

    gp_r = p_r;
    p_r = r;
  }

  q = (struct hc_node_t *) malloc (sizeof (struct hc_node_t));

  if (q != NULL)
  {
    *nextp = q;       /* link new node to old */
    q->key = key;     /* initialize new node  */
    q->red = 1;
    q->left = q->right = NULL;

    /*
    * There may be two red edges in a row now, which we must avoid by
    * rotating the tree.
    */
    if (nextp != rootp) hc_maybe_split_for_insert (nextp, rootp, parentp, r, p_r, 1);
  }

  return q;
}

/* Find datum in search tree.
 * KEY is the key to be located, ROOTP is the address of tree root,
 * COMPAR the ordering function.
 */
void * __hc_tfind (const void *key, void *const *vrootp, __hc_compar_fn_t compar)
{
  int r;
  hc_node *rootp = (hc_node *) vrootp;

  if (rootp == NULL) return NULL;

  while (*rootp != NULL)
  {
    hc_node root = *rootp;

    r = (*compar) (key, root->key);

    if (r == 0) return root;

    rootp = (r < 0) ? &root->left : &root->right;
  }

  return NULL;
}

static void hc_tdestroy_recurse (hc_node root, __hc_free_fn_t freefct)
{
  if (root->left != NULL)  hc_tdestroy_recurse (root->left, freefct);

  if (root->right != NULL) hc_tdestroy_recurse (root->right, freefct);

  (*freefct) ((void *) root->key);

  /* Free the node itself.  */
  free (root);
}

void __hc_tdestroy (void *vroot, __hc_free_fn_t freefct)
{
  hc_node root = (hc_node) vroot;

  if (root != NULL) hc_tdestroy_recurse (root, freefct);
}
