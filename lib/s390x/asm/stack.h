/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (c) 2017 Red Hat Inc
 *
 * Authors:
 *  Thomas Huth <thuth@redhat.com>
 *  David Hildenbrand <david@redhat.com>
 */
#ifndef _ASMS390X_STACK_H_
#define _ASMS390X_STACK_H_

#ifndef _STACK_H_
#error Do not directly include <asm/stack.h>. Just use <stack.h>.
#endif

#define HAVE_ARCH_BACKTRACE_FRAME
#define HAVE_ARCH_BACKTRACE

#endif
