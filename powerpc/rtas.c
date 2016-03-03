/*
 * Test the RTAS interface
 */

#include <libcflat.h>
#include <util.h>
#include <asm/rtas.h>

#define DAYS(y,m,d) (365UL * (y) + ((y) / 4) - ((y) / 100) + ((y) / 400) + \
		     367UL * (m) / 12  + \
		     (d))

static unsigned long mktime(int year, int month, int day,
			    int hour, int minute, int second)
{
	unsigned long epoch;

	/* Put February at end of the year to avoid leap day this year */

	month -= 2;
	if (month <= 0) {
		month += 12;
		year -= 1;
	}

	/* compute epoch: substract DAYS(since_March(1-1-1970)) */

	epoch = DAYS(year, month, day) - DAYS(1969, 11, 1);

	epoch = epoch * 24 + hour;
	epoch = epoch * 60 + minute;
	epoch = epoch * 60 + second;

	return epoch;
}

#define DELAY 1
#define MAX_LOOP 10000000

static void check_get_time_of_day(unsigned long start)
{
	int token;
	int ret;
	int now[8];
	unsigned long t1, t2, count;

	token = rtas_token("get-time-of-day");
	report("token available", token != RTAS_UNKNOWN_SERVICE);
	if (token == RTAS_UNKNOWN_SERVICE)
		return;

	ret = rtas_call(token, 0, 8, now);
	report("execution", ret == 0);

	report("second",  now[5] >= 0 && now[5] <= 59);
	report("minute", now[4] >= 0 && now[4] <= 59);
	report("hour", now[3] >= 0 && now[3] <= 23);
	report("day", now[2] >= 1 && now[2] <= 31);
	report("month", now[1] >= 1 && now[1] <= 12);
	report("year", now[0] >= 1970);
	report("accuracy (< 3s)", mktime(now[0], now[1], now[2],
					 now[3], now[4], now[5]) - start < 3);

	ret = rtas_call(token, 0, 8, now);
	t1 = mktime(now[0], now[1], now[2], now[3], now[4], now[5]);
	count = 0;
	do {
		ret = rtas_call(token, 0, 8, now);
		t2 = mktime(now[0], now[1], now[2], now[3], now[4], now[5]);
		count++;
	} while (t1 + DELAY > t2 && count < MAX_LOOP);
	report("running", t1 + DELAY <= t2);
}

static void check_set_time_of_day(void)
{
	int token;
	int ret;
	int date[8];
	unsigned long t1, t2, count;

	token = rtas_token("set-time-of-day");
	report("token available", token != RTAS_UNKNOWN_SERVICE);
	if (token == RTAS_UNKNOWN_SERVICE)
		return;

	/* 23:59:59 28/2/2000 */

	ret = rtas_call(token, 7, 1, NULL, 2000, 2, 28, 23, 59, 59);
	report("execution", ret == 0);

	/* check it has worked */
	ret = rtas_call(rtas_token("get-time-of-day"), 0, 8, date);
	report("re-read", ret == 0);
	t1 = mktime(2000, 2, 28, 23, 59, 59);
	t2 = mktime(date[0], date[1], date[2],
		    date[3], date[4], date[5]);
	report("result", t2 - t1 < 2);

	/* check it is running */
	count = 0;
	do {
		ret = rtas_call(rtas_token("get-time-of-day"), 0, 8, date);
		t2 = mktime(date[0], date[1], date[2],
			    date[3], date[4], date[5]);
		count++;
	} while (t1 + DELAY > t2 && count < MAX_LOOP);
	report("running", t1 + DELAY <= t2);
}

int main(int argc, char **argv)
{
	int len;
	long val;

	report_prefix_push("rtas");

	if (!argc)
		report_abort("no test specified");

	report_prefix_push(argv[0]);

	if (strcmp(argv[0], "get-time-of-day") == 0) {

		len = parse_keyval(argv[1], &val);
		if (len == -1) {
			printf("Missing parameter \"date\"\n");
			abort();
		}
		argv[1][len] = '\0';

		check_get_time_of_day(val);

	} else if (strcmp(argv[0], "set-time-of-day") == 0) {

		check_set_time_of_day();

	} else {
		printf("Unknown subtest\n");
		abort();
	}

	report_prefix_pop();

	report_prefix_pop();

	return report_summary();
}
