/*
 * Test result reporting
 *
 * Copyright (c) Siemens AG, 2014
 *
 * Authors:
 *  Jan Kiszka <jan.kiszka@siemens.com>
 *  Andrew Jones <drjones@redhat.com>
 *
 * This work is licensed under the terms of the GNU LGPL, version 2.
 */

#include "libcflat.h"
#include "asm/spinlock.h"

static unsigned int tests, failures, xfailures, kfailures, skipped;
static char prefixes[256];
static struct spinlock lock;

#define PREFIX_DELIMITER ": "

void report_passed(void)
{
	spin_lock(&lock);
	tests++;
	spin_unlock(&lock);
}

void report_prefix_pushf(const char *prefix_fmt, ...)
{
	va_list va;
	unsigned int len;
	int start;

	spin_lock(&lock);

	len = strlen(prefixes);
	assert_msg(len < sizeof(prefixes), "%d >= %zu", len, sizeof(prefixes));
	start = len;

	va_start(va, prefix_fmt);
	len += vsnprintf(&prefixes[len], sizeof(prefixes) - len, prefix_fmt,
			 va);
	va_end(va);
	assert_msg(len < sizeof(prefixes), "%d >= %zu", len, sizeof(prefixes));

	assert_msg(!strstr(&prefixes[start], PREFIX_DELIMITER),
		   "Prefix \"%s\" contains delimiter \"" PREFIX_DELIMITER "\"",
		   &prefixes[start]);

	len += snprintf(&prefixes[len], sizeof(prefixes) - len,
			PREFIX_DELIMITER);
	assert_msg(len < sizeof(prefixes), "%d >= %zu", len, sizeof(prefixes));

	spin_unlock(&lock);
}

void report_prefix_push(const char *prefix)
{
	report_prefix_pushf("%s", prefix);
}

static void __report_prefix_pop(void)
{
	char *p, *q;

	if (!*prefixes)
		return;

	for (p = prefixes, q = strstr(p, PREFIX_DELIMITER) + 2;
			*q;
			p = q, q = strstr(p, PREFIX_DELIMITER) + 2)
		;
	*p = '\0';
}

void report_prefix_pop(void)
{
	spin_lock(&lock);
	__report_prefix_pop();
	spin_unlock(&lock);
}

void report_prefix_popn(int n)
{
	spin_lock(&lock);
	while (n--)
		__report_prefix_pop();
	spin_unlock(&lock);
}

static bool va_report(const char *msg_fmt,
		bool pass, bool xfail, bool kfail, bool skip, va_list va)
{
	const char *prefix = skip ? "SKIP"
				  : xfail ? (pass ? "XPASS" : "XFAIL")
				          : kfail ? (pass ? "PASS" : "KFAIL")
					          : (pass ? "PASS"  : "FAIL");

	spin_lock(&lock);

	tests++;
	printf("%s: ", prefix);
	puts(prefixes);
	vprintf(msg_fmt, va);
	puts("\n");
	if (skip)
		skipped++;
	else if (xfail && !pass)
		xfailures++;
	else if (kfail && !pass)
		kfailures++;
	else if (xfail || !pass)
		failures++;

	spin_unlock(&lock);

	return pass || xfail;
}

bool report(bool pass, const char *msg_fmt, ...)
{
	va_list va;
	bool ret;

	va_start(va, msg_fmt);
	ret = va_report(msg_fmt, pass, false, false, false, va);
	va_end(va);

	return ret;
}

void report_pass(const char *msg_fmt, ...)
{
	va_list va;

	va_start(va, msg_fmt);
	va_report(msg_fmt, true, false, false, false, va);
	va_end(va);
}

void report_fail(const char *msg_fmt, ...)
{
	va_list va;

	va_start(va, msg_fmt);
	va_report(msg_fmt, false, false, false, false, va);
	va_end(va);
}

bool report_xfail(bool xfail, bool pass, const char *msg_fmt, ...)
{
	bool ret;

	va_list va;
	va_start(va, msg_fmt);
	ret = va_report(msg_fmt, pass, xfail, false, false, va);
	va_end(va);

	return ret;
}

/*
 * kfail is known failure. If kfail is true then test will succeed
 * regardless of pass.
 */
bool report_kfail(bool kfail, bool pass, const char *msg_fmt, ...)
{
	bool ret;

	va_list va;
	va_start(va, msg_fmt);
	ret = va_report(msg_fmt, pass, false, kfail, false, va);
	va_end(va);

	return ret;
}

void report_skip(const char *msg_fmt, ...)
{
	va_list va;
	va_start(va, msg_fmt);
	va_report(msg_fmt, false, false, false, true, va);
	va_end(va);
}

void report_info(const char *msg_fmt, ...)
{
	va_list va;

	spin_lock(&lock);
	puts("INFO: ");
	puts(prefixes);
	va_start(va, msg_fmt);
	vprintf(msg_fmt, va);
	va_end(va);
	puts("\n");
	spin_unlock(&lock);
}

int report_summary(void)
{
	int ret;
	spin_lock(&lock);

	printf("SUMMARY: %d tests", tests);
	if (failures)
		printf(", %d unexpected failures", failures);
	if (kfailures)
		printf(", %d known failures", kfailures);
	if (xfailures)
		printf(", %d expected failures", xfailures);
	if (skipped)
		printf(", %d skipped", skipped);
	printf("\n");

	if (tests == skipped) {
		spin_unlock(&lock);
		/* Blame AUTOTOOLS for using 77 for skipped test and QEMU for
		 * mangling error codes in a way that gets 77 if we ... */
		return 77 >> 1;
	}

	ret = failures > 0 ? 1 : 0;
	spin_unlock(&lock);
	return ret;
}

void report_abort(const char *msg_fmt, ...)
{
	va_list va;

	spin_lock(&lock);
	puts("ABORT: ");
	puts(prefixes);
	va_start(va, msg_fmt);
	vprintf(msg_fmt, va);
	va_end(va);
	puts("\n");
	spin_unlock(&lock);
	report_summary();
	abort();
}
