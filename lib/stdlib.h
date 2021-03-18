/*
 * Header for libc stdlib functions
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Library General Public License version 2.
 */
#ifndef _STDLIB_H_
#define _STDLIB_H_

long int strtol(const char *nptr, char **endptr, int base);
unsigned long int strtoul(const char *nptr, char **endptr, int base);

#endif /* _STDLIB_H_ */
