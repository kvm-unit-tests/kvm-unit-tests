#include "libcflat.h"

unsigned long strlen(const char *buf)
{
    unsigned long len = 0;

    while (*buf++)
	++len;
    return len;
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

int strcmp(const char *a, const char *b)
{
    while (*a == *b) {
	if (*a == '\0') {
	    break;
	}
	++a, ++b;
    }
    return *a - *b;
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

long atol(const char *ptr)
{
    long acc = 0;
    const char *s = ptr;
    int neg, c;

    while (*s == ' ' || *s == '\t')
        s++;
    if (*s == '-'){
        neg = 1;
        s++;
    } else {
        neg = 0;
        if (*s == '+')
            s++;
    }

    while (*s) {
        if (*s < '0' || *s > '9')
            break;
        c = *s - '0';
        acc = acc * 10 + c;
        s++;
    }

    if (neg)
        acc = -acc;

    return acc;
}
