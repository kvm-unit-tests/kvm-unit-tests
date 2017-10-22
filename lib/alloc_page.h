/*
 * This work is licensed under the terms of the GNU LGPL, version 2.
 *
 * This is a simple allocator that provides contiguous physical addresses
 * with byte granularity.
 */

#ifndef ALLOC_PAGE_H
#define ALLOC_PAGE_H 1

void *alloc_page();
void *alloc_pages(unsigned long order);
void free_page(void *page);
void free_pages(void *mem, unsigned long size);

#endif
