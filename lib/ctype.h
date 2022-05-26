/* SPDX-License-Identifier: LGPL-2.0-or-later */
#ifndef _CTYPE_H_
#define _CTYPE_H_

static inline int isblank(int c)
{
	return c == ' ' || c == '\t';
}

static inline int islower(int c)
{
	return c >= 'a' && c <= 'z';
}

static inline int isupper(int c)
{
	return c >= 'A' && c <= 'Z';
}

static inline int isalpha(int c)
{
	return isupper(c) || islower(c);
}

static inline int isdigit(int c)
{
	return c >= '0' && c <= '9';
}

static inline int isalnum(int c)
{
	return isalpha(c) || isdigit(c);
}

static inline int isspace(int c)
{
        return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\v' || c == '\f';
}

#endif /* _CTYPE_H_ */
