#ifndef __VLIST_H__
#define __VLIST_H__

#if defined(__WIN32__)
#define _MSVC
#endif

struct vlist {
    struct vlist* next;
    struct vlist* prev;
};

#define VLIST_HEAD(list) list = {&list, &list}

#define __offsetof(type, member) ((size_t)&((type*)0)->member)

#ifdef _MSVC
#define container_of(ptr, type, member) ((type *)( (char *)ptr - __offsetof(type,member) ))
#else
#define container_of(ptr, type, member) ({ \
            const typeof( ((type *)0)->member ) *__mptr = (ptr); \
            (type *)( (char *)__mptr - __offsetof(type,member) );})
#endif


#define vlist_entry(ptr, type, member) container_of(ptr, type, member)

#define __vlist_for_each(pos, head) \
            for (pos = (head)->next; pos != (head); pos = pos->next)

#define to_object(node, type) (vlist_entry(node, type, list))

static inline
int vlist_is_empty(struct vlist* head)
{
    return head->next == head;
}

static inline
void vlist_init(struct vlist* list)
{
    list->next = list;
    list->prev = list;
}

static inline
struct vlist* vlist_add_tail(struct vlist* head, struct vlist* new)
{
    head->prev->next = new;
    new->prev = head->prev;
    new->next = head;
    head->prev = new;
    return new;
}

static inline
struct vlist* vlist_del(struct vlist* entry)
{
    entry->next->prev = entry->prev;
    entry->prev->next = entry->next;
    return entry;
}

static inline
struct vlist* vlist_pop_head(struct vlist* head)
{
    if (vlist_is_empty(head)) return 0;
    return vlist_del(head->next);
}

typedef int (*compare_PTR)(struct vlist*, void*);

static inline
struct vlist* vlist_find_node(struct vlist* head, compare_PTR condition, void* argv)
{
    struct vlist* node = 0;
    __vlist_for_each(node, head) {
        if (condition(node, argv)) return node;
    }
    return 0;
}

typedef int (*action_PTR)(struct vlist*, void*);
static inline
void vlist_travel_node(struct vlist* head, action_PTR action, void* argv)
{
    struct vlist* node = 0;
    __vlist_for_each(node, head) {
        action(node, argv);
    }
}

#endif

