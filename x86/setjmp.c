#include "libcflat.h"
#include "setjmp.h"

static const int expected[] = {
	0, 1, 2, 3, 4, 5, 6, 7, 8, 9
};

#define NUM_LONGJMPS ARRAY_SIZE(expected)

int main(void)
{
	volatile int index = 0;
	jmp_buf j;
	int i;

	i = setjmp(j);
	report(expected[index] == i, "actual %d == expected %d",
	       i, expected[index]);
	index++;
	if (i + 1 < NUM_LONGJMPS)
		longjmp(j, i + 1);

	return report_summary();
}
