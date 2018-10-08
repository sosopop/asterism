#include "asterism.h"
#include "asterism_utils.h"
#include <assert.h>
#include <string.h>

static struct asterism_slist *slist_get_last(struct asterism_slist *list)
{
  struct asterism_slist *item;

  if (!list)
    return 0;

  item = list;
  while (item->next)
  {
    item = item->next;
  }
  return item;
}

struct asterism_slist *asterism_slist_append_nodup(struct asterism_slist *list, char *data)
{
  struct asterism_slist *last;
  struct asterism_slist *new_item;

  new_item = (struct asterism_slist *)AS_MALLOC(sizeof(struct asterism_slist));
  if (!new_item)
    return 0;

  new_item->next = 0;
  new_item->data = data;

  if (!list)
    return new_item;

  last = slist_get_last(list);
  last->next = new_item;
  return list;
}

struct asterism_slist *asterism_slist_append(struct asterism_slist *list,
                                             const char *data)
{
  char *dupdata = as_strdup(data);

  if (!dupdata)
    return 0;

  list = asterism_slist_append_nodup(list, dupdata);
  if (!list)
    AS_FREE(dupdata);

  return list;
}

struct asterism_slist *asterism_slist_duplicate(struct asterism_slist *inlist)
{
  struct asterism_slist *outlist = 0;
  struct asterism_slist *tmp;

  while (inlist)
  {
    tmp = asterism_slist_append(outlist, inlist->data);

    if (!tmp)
    {
      asterism_slist_free_all(outlist);
      return 0;
    }

    outlist = tmp;
    inlist = inlist->next;
  }
  return outlist;
}

void asterism_slist_free_all(struct asterism_slist *list)
{
  struct asterism_slist *next;
  struct asterism_slist *item;

  if (!list)
    return;

  item = list;
  do
  {
    next = item->next;
    AS_SAFEFREE(item->data);
    AS_FREE(item);
    item = next;
  } while (next);
}
