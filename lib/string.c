/*
 * libc string functions
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Library General Public License version 2.
 */

#include "libcflat.h"
#include "stdlib.h"
#include "linux/compiler.h"

size_t strlen(const char *buf)
{
    size_t len = 0;

    while (*buf++)
	++len;
    return len;
}

size_t strnlen(const char *buf, size_t maxlen)
{
    const char *sc;

    for (sc = buf; maxlen-- && *sc != '\0'; ++sc)
        /* nothing */;
    return sc - buf;
}

char *strcat(char *dest, const char *src)
{
    char *p = dest;

    while (*p)
	++p;
    while ((*p++ = *src++) != 0)
	;
    return dest;
}

char *strcpy(char *dest, const char *src)
{
    *dest = 0;
    return strcat(dest, src);
}

int strncmp(const char *a, const char *b, size_t n)
{
    for (; n--; ++a, ++b)
        if (*a != *b || *a == '\0')
            return *a - *b;

    return 0;
}

int strcmp(const char *a, const char *b)
{
    return strncmp(a, b, SIZE_MAX);
}

char *strchr(const char *s, int c)
{
    while (*s != (char)c)
	if (*s++ == '\0')
	    return NULL;
    return (char *)s;
}

char *strrchr(const char *s, int c)
{
    const char *last = NULL;
    do {
        if (*s == (char)c)
            last = s;
    } while (*s++);
    return (char *)last;
}

char *strchrnul(const char *s, int c)
{
    while (*s && *s != (char)c)
        s++;
    return (char *)s;
}

char *strstr(const char *s1, const char *s2)
{
    size_t l1, l2;

    l2 = strlen(s2);
    if (!l2)
	return (char *)s1;
    l1 = strlen(s1);
    while (l1 >= l2) {
	l1--;
	if (!memcmp(s1, s2, l2))
	    return (char *)s1;
	s1++;
    }
    return NULL;
}

void *memset(void *s, int c, size_t n)
{
    size_t i;
    char *a = s;

    for (i = 0; i < n; ++i)
        a[i] = c;

    return s;
}

void *memcpy(void *dest, const void *src, size_t n)
{
    size_t i;
    char *a = dest;
    const char *b = src;

    for (i = 0; i < n; ++i)
        a[i] = b[i];

    return dest;
}

int memcmp(const void *s1, const void *s2, size_t n)
{
    const unsigned char *a = s1, *b = s2;
    int ret = 0;

    while (n--) {
	ret = *a - *b;
	if (ret)
	    break;
	++a, ++b;
    }
    return ret;
}

void *memmove(void *dest, const void *src, size_t n)
{
    const unsigned char *s = src;
    unsigned char *d = dest;

    if (d <= s) {
	while (n--)
	    *d++ = *s++;
    } else {
	d += n, s += n;
	while (n--)
	    *--d = *--s;
    }
    return dest;
}

void *memchr(const void *s, int c, size_t n)
{
    const unsigned char *str = s, chr = (unsigned char)c;

    while (n--)
	if (*str++ == chr)
	    return (void *)(str - 1);
    return NULL;
}

static int isspace(int c)
{
    return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\v' || c == '\f';
}

static unsigned long __strtol(const char *nptr, char **endptr,
                              int base, bool is_signed) {
    unsigned long acc = 0;
    const char *s = nptr;
    int neg, c;

    assert(base == 0 || (base >= 2 && base <= 36));

    while (isspace(*s))
        s++;

    if (*s == '-') {
        neg = 1;
        s++;
    } else {
        neg = 0;
        if (*s == '+')
            s++;
    }

    if (base == 0 || base == 16) {
        if (*s == '0') {
            s++;
            if (*s == 'x' || *s == 'X') {
                 s++;
                 base = 16;
            } else if (base == 0)
                 base = 8;
        } else if (base == 0)
            base = 10;
    }

    while (*s) {
        if (*s >= '0' && *s < '0' + base && *s <= '9')
            c = *s - '0';
        else if (*s >= 'a' && *s < 'a' + base - 10)
            c = *s - 'a' + 10;
        else if (*s >= 'A' && *s < 'A' + base - 10)
            c = *s - 'A' + 10;
        else
            break;

        if (is_signed) {
            long sacc = (long)acc;
            assert(!check_mul_overflow(sacc, base));
            assert(!check_add_overflow(sacc * base, c));
        } else {
            assert(!check_mul_overflow(acc, base));
            assert(!check_add_overflow(acc * base, c));
        }

        acc = acc * base + c;
        s++;
    }

    if (neg)
        acc = -acc;

    if (endptr)
        *endptr = (char *)s;

    return acc;
}

long int strtol(const char *nptr, char **endptr, int base)
{
    return __strtol(nptr, endptr, base, true);
}

unsigned long int strtoul(const char *nptr, char **endptr, int base)
{
    return __strtol(nptr, endptr, base, false);
}

long atol(const char *ptr)
{
    return strtol(ptr, NULL, 10);
}

extern char **environ;

char *getenv(const char *name)
{
    char **envp = environ, *delim;
    int len;

    while (*envp) {
        delim = strchr(*envp, '=');
        assert(delim);
        len = delim - *envp;
        if (memcmp(name, *envp, len) == 0 && !name[len])
            return delim + 1;
        ++envp;
    }
    return NULL;
}

/* Very simple glob matching. Allows '*' at beginning and end of pattern. */
bool simple_glob(const char *text, const char *pattern)
{
	bool star_start = false;
	bool star_end = false;
	size_t n = strlen(pattern);
	char copy[n + 1];

	if (pattern[0] == '*') {
		pattern += 1;
		n -= 1;
		star_start = true;
	}

	strcpy(copy, pattern);

	if (n > 0 && pattern[n - 1] == '*') {
		n -= 1;
		copy[n] = '\0';
		star_end = true;
	}

	if (star_start && star_end)
		return strstr(text, copy);

	if (star_end)
		return strstr(text, copy) == text;

	if (star_start) {
		size_t text_len = strlen(text);
		const char *suffix;

		if (n > text_len)
			return false;
		suffix = text + text_len - n;
		return !strcmp(suffix, copy);
	}

	return !strcmp(text, copy);
}
