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
    if (expected[index] != i) {
	    printf("FAIL: actual %d / expected %d\n", i, expected[index]);
	    return -1;
    }
    index++;
    if (i + 1 < NUM_LONGJMPS)
	    longjmp(j, i + 1);

    return 0;
}
