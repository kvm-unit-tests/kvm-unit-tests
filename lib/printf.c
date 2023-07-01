/*
 * libc printf and friends
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Library General Public License version 2.
 */

#include "libcflat.h"
#include "ctype.h"

#define BUFSZ 2000

typedef struct pstream {
	char *buffer;
	int remain;
	int added;
} pstream_t;

typedef struct strprops {
	char pad;
	int npad;
	bool alternate;
	int precision;
} strprops_t;

static void addchar(pstream_t *p, char c)
{
	if (p->remain) {
		*p->buffer++ = c;
		--p->remain;
	}
	++p->added;
}

static void print_str(pstream_t *p, const char *s, strprops_t props)
{
	const char *s_orig = s;
	int npad = props.npad;

	if (npad > 0) {
		npad -= strlen(s_orig);
		while (npad > 0) {
			addchar(p, props.pad);
			--npad;
		}
	}

	while (*s && props.precision--)
		addchar(p, *s++);

	if (npad < 0) {
		props.pad = ' ';	/* ignore '0' flag with '-' flag */
		npad += strlen(s_orig);
		while (npad < 0) {
			addchar(p, props.pad);
			++npad;
		}
	}
}

/*
 * Adapted from drivers/firmware/efi/libstub/vsprintf.c
 */
static u32 utf16_to_utf32(const u16 **s16)
{
	u16 c0, c1;

	c0 = *(*s16)++;
	/* not a surrogate */
	if ((c0 & 0xf800) != 0xd800)
		return c0;
	/* invalid: low surrogate instead of high */
	if (c0 & 0x0400)
		return 0xfffd;
	c1 = **s16;
	/* invalid: missing low surrogate */
	if ((c1 & 0xfc00) != 0xdc00)
		return 0xfffd;
	/* valid surrogate pair */
	++(*s16);
	return (0x10000 - (0xd800 << 10) - 0xdc00) + (c0 << 10) + c1;
}

/*
 * Adapted from drivers/firmware/efi/libstub/vsprintf.c
 */
static size_t utf16s_utf8nlen(const u16 *s16, size_t maxlen)
{
	size_t len, clen;

	for (len = 0; len < maxlen && *s16; len += clen) {
		u16 c0 = *s16++;

		/* First, get the length for a BMP character */
		clen = 1 + (c0 >= 0x80) + (c0 >= 0x800);
		if (len + clen > maxlen)
			break;
		/*
		 * If this is a high surrogate, and we're already at maxlen, we
		 * can't include the character if it's a valid surrogate pair.
		 * Avoid accessing one extra word just to check if it's valid
		 * or not.
		 */
		if ((c0 & 0xfc00) == 0xd800) {
			if (len + clen == maxlen)
				break;
			if ((*s16 & 0xfc00) == 0xdc00) {
				++s16;
				++clen;
			}
		}
	}

	return len;
}

/*
 * Adapted from drivers/firmware/efi/libstub/vsprintf.c
 */
static void print_wstring(pstream_t *p, const u16 *s, strprops_t props)
{
	const u16 *ws = (const u16 *)s;
	size_t pos = 0, size = p->remain + 1, len = utf16s_utf8nlen(ws, props.precision);

	while (len-- > 0) {
		u32 c32 = utf16_to_utf32(&ws);
		u8 *s8;
		size_t clen;

		if (c32 < 0x80) {
			addchar(p, c32);
			continue;
		}

		/* Number of trailing octets */
		clen = 1 + (c32 >= 0x800) + (c32 >= 0x10000);

		len -= clen;
		s8 = (u8 *)(p->buffer - p->added + pos);

		/* Avoid writing partial character */
		addchar(p, '\0');
		pos += clen;
		if (pos >= size)
			continue;

		/* Set high bits of leading octet */
		*s8 = (0xf00 >> 1) >> clen;
		/* Write trailing octets in reverse order */
		for (s8 += clen; clen; --clen, c32 >>= 6)
			*s8-- = 0x80 | (c32 & 0x3f);
		/* Set low bits of leading octet */
		*s8 |= c32;
	}
}

static char digits[16] = "0123456789abcdef";

static void print_int(pstream_t *ps, long long n, int base, strprops_t props)
{
	char buf[sizeof(long) * 3 + 2], *p = buf;
	int s = 0, i;

	if (n < 0) {
		n = -n;
		s = 1;
	}

	while (n) {
		*p++ = digits[n % base];
		n /= base;
	}

	while (p == buf || (p - buf < props.precision))
		*p++ = '0';
	props.precision = -1;

	if (s)
		*p++ = '-';

	for (i = 0; i < (p - buf) / 2; ++i) {
		char tmp;

		tmp = buf[i];
		buf[i] = p[-1 - i];
		p[-1 - i] = tmp;
	}

	*p = 0;

	print_str(ps, buf, props);
}

static void print_unsigned(pstream_t *ps, unsigned long long n, int base,
			   strprops_t props)
{
	char buf[sizeof(long) * 3 + 3], *p = buf;
	int i;

	while (n) {
		*p++ = digits[n % base];
		n /= base;
	}

	if (p == buf)
		props.alternate = false;

	while (p == buf || (p - buf < props.precision))
		*p++ = '0';
	props.precision = -1;

	if (props.alternate && base == 16) {
		if (props.pad == '0') {
			addchar(ps, '0');
			addchar(ps, 'x');

			if (props.npad > 0)
				props.npad = MAX(props.npad - 2, 0);
		} else {
			*p++ = 'x';
			*p++ = '0';
		}
	}

	for (i = 0; i < (p - buf) / 2; ++i) {
		char tmp;

		tmp = buf[i];
		buf[i] = p[-1 - i];
		p[-1 - i] = tmp;
	}

	*p = 0;

	print_str(ps, buf, props);
}

static int fmtnum(const char **fmt)
{
	const char *f = *fmt;
	int len = 0, num;

	if (*f == '-')
		++f, ++len;

	while (*f >= '0' && *f <= '9')
		++f, ++len;

	num = atol(*fmt);
	*fmt += len;
	return num;
}

/*
 * Adapted from drivers/firmware/efi/libstub/vsprintf.c
 */
static int skip_atoi(const char **s)
{
	int i = 0;

	do {
		i = i*10 + *((*s)++) - '0';
	} while (isdigit(**s));

	return i;
}

/*
 * Adapted from drivers/firmware/efi/libstub/vsprintf.c
 */
static int get_int(const char **fmt, va_list *ap)
{
	if (isdigit(**fmt))
		return skip_atoi(fmt);

	if (**fmt == '*') {
		++(*fmt);
		/* it's the next argument */
		return va_arg(*ap, int);
	}
	return 0;
}

int vsnprintf(char *buf, int size, const char *fmt, va_list va)
{
	pstream_t s;
	va_list args;

	/*
	 * We want to pass our input va_list to helper functions by reference,
	 * but there's an annoying edge case. If va_list was originally passed
	 * to us by value, we could just pass &ap down to the helpers. This is
	 * the case on, for example, X86_32.
	 * However, on X86_64 (and possibly others), va_list is actually a
	 * size-1 array containing a structure. Our function parameter ap has
	 * decayed from T[1] to T*, and &ap has type T** rather than T(*)[1],
	 * which is what will be expected by a function taking a va_list *
	 * parameter.
	 * One standard way to solve this mess is by creating a copy in a local
	 * variable of type va_list and then passing a pointer to that local
	 * copy instead, which is what we do here.
	 */
	va_copy(args, va);

	s.buffer = buf;
	s.remain = size - 1;
	s.added = 0;
	while (*fmt) {
		char f = *fmt++;
		int nlong = 0;
		strprops_t props;
		memset(&props, 0, sizeof(props));
		props.pad = ' ';
		props.precision = -1;

		if (f != '%') {
			addchar(&s, f);
			continue;
		}
morefmt:
		f = *fmt++;
		switch (f) {
		case '%':
			addchar(&s, '%');
			break;
		case 'c':
			addchar(&s, va_arg(args, int));
			break;
		case '\0':
			--fmt;
			break;
		case '.':
			props.pad = ' ';
			props.precision = get_int(&fmt, &args);
			goto morefmt;
		case '#':
			props.alternate = true;
			goto morefmt;
		case '0':
			props.pad = '0';
			++fmt;
			/* fall through */
		case '1' ... '9':
		case '-':
			--fmt;
			props.npad = fmtnum(&fmt);
			goto morefmt;
		case 'l':
			++nlong;
			goto morefmt;
		case 't':
		case 'z':
			/* Here we only care that sizeof(size_t) == sizeof(long).
			 * On a 32-bit platform it doesn't matter that size_t is
			 * typedef'ed to int or long; va_arg will work either way.
			 * Same for ptrdiff_t (%td).
			 */
			nlong = 1;
			goto morefmt;
		case 'd':
			switch (nlong) {
			case 0:
				print_int(&s, va_arg(args, int), 10, props);
				break;
			case 1:
				print_int(&s, va_arg(args, long), 10, props);
				break;
			default:
				print_int(&s, va_arg(args, long long), 10, props);
				break;
			}
			break;
		case 'u':
			switch (nlong) {
			case 0:
				print_unsigned(&s, va_arg(args, unsigned int), 10, props);
				break;
			case 1:
				print_unsigned(&s, va_arg(args, unsigned long), 10, props);
				break;
			default:
				print_unsigned(&s, va_arg(args, unsigned long long), 10, props);
				break;
			}
			break;
		case 'x':
			switch (nlong) {
			case 0:
				print_unsigned(&s, va_arg(args, unsigned int), 16, props);
				break;
			case 1:
				print_unsigned(&s, va_arg(args, unsigned long), 16, props);
				break;
			default:
				print_unsigned(&s, va_arg(args, unsigned long long), 16, props);
				break;
			}
			break;
		case 'p':
			props.alternate = true;
			print_unsigned(&s, (unsigned long)va_arg(args, void *), 16, props);
			break;
		case 's':
			if (nlong)
				print_wstring(&s, va_arg(args, const u16 *), props);
			else
				print_str(&s, va_arg(args, const char *), props);
			break;
		default:
			addchar(&s, f);
			break;
		}
	}
	va_end(args);
	*s.buffer = 0;
	return s.added;
}

int snprintf(char *buf, int size, const char *fmt, ...)
{
	va_list va;
	int r;

	va_start(va, fmt);
	r = vsnprintf(buf, size, fmt, va);
	va_end(va);
	return r;
}

int vprintf(const char *fmt, va_list va)
{
	char buf[BUFSZ];
	int r;

	r = vsnprintf(buf, sizeof(buf), fmt, va);
	puts(buf);
	return r;
}

int printf(const char *fmt, ...)
{
	va_list va;
	char buf[BUFSZ];
	int r;

	va_start(va, fmt);
	r = vsnprintf(buf, sizeof buf, fmt, va);
	va_end(va);
	puts(buf);
	return r;
}

void binstr(unsigned long x, char out[BINSTR_SZ])
{
	int i;
	char *c;
	int n;

	n = sizeof(unsigned long) * 8;
	i = 0;
	c = &out[0];
	for (;;) {
		*c++ = (x & (1ul << (n - i - 1))) ? '1' : '0';
		i++;

		if (i == n) {
			*c = '\0';
			break;
		}
		if (i % 4 == 0)
			*c++ = '\'';
	}
	assert(c + 1 - &out[0] == BINSTR_SZ);
}

void print_binstr(unsigned long x)
{
	char out[BINSTR_SZ];
	binstr(x, out);
	printf("%s", out);
}
