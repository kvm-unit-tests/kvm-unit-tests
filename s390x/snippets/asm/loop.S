/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Infinite loop snippet with no exit
 *
 * Copyright (c) 2023 IBM Corp
 *
 * Authors:
 *  Janosch Frank <frankja@linux.ibm.com>
 */
.section .text

retry:
j 	retry
