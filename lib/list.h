#ifndef _LIST_H_
#define _LIST_H_

#include <stdbool.h>

/*
 * Circular doubly-linked list. The pointer to the list is a list item itself,
 * like in the kernel implementation.
 */
struct linked_list {
	struct linked_list *prev;
	struct linked_list *next;
};

/*
 * An empty list is a list item whose prev and next both point to itself.
 * Returns true if the list is empty.
 */
static inline bool is_list_empty(struct linked_list *p)
{
	return !p->next || !p->prev || p == p->next || p == p->prev;
}

/*
 * Remove the given element from the list, if the list is not already empty.
 * The removed element is returned.
 */
static inline struct linked_list *list_remove(struct linked_list *l)
{
	if (is_list_empty(l))
		return NULL;

	l->prev->next = l->next;
	l->next->prev = l->prev;
	l->prev = l->next = NULL;

	return l;
}

/*
 * Add the given element after the given list head.
 */
static inline void list_add(struct linked_list *head, struct linked_list *li)
{
	assert(li);
	assert(head);
	li->prev = head;
	li->next = head->next;
	head->next->prev = li;
	head->next = li;
}

/*
 * Add the given element before the given list head.
 */
static inline void list_add_tail(struct linked_list *head, struct linked_list *li)
{
	assert(head);
	list_add(head->prev, li);
}

#endif
