#ifndef TSEARCH_H
#define TSEARCH_H

typedef struct hc_node_t
{
  const void *key;
  struct hc_node_t *left;
  struct hc_node_t *right;
  unsigned int red:1;

} *hc_node;

typedef const struct hc_node_t *hc_const_node;

typedef void (*__hc_free_fn_t) (void *__hc_nodep);

typedef int (*__hc_compar_fn_t) (__const void *, __const void *);

void *
__hc_tsearch (const void *key, void **vrootp, __hc_compar_fn_t compar);

void *
__hc_tfind (const void *key, void *const *vrootp, __hc_compar_fn_t compar);

void
__hc_tdestroy (void *vroot, __hc_free_fn_t freefct);

#endif /* TSEARCH_H */
