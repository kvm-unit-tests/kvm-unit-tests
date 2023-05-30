#include "libcflat.h"

int main(int argc, char **argv)
{
	/*
	 * scripts/runtime.bash uses this test as a canary to determine if the
	 * basic setup is functional.  Print a magic string to let runtime.bash
	 * know that all is well.
	 */
	printf("Dummy Hello World!");
	return 0;
}
