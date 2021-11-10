#include "libcflat.h"
#include "processor.h"
#include "x86/vm.h"
#include "access.h"

int main(void)
{
    int r;

    printf("starting test\n\n");
    page_table_levels = 4;
    r = ac_test_run();

    if (this_cpu_has(X86_FEATURE_LA57)) {
        page_table_levels = 5;
        printf("starting 5-level paging test.\n\n");
        setup_5level_page_table();
        r = ac_test_run();
    }

    return r ? 0 : 1;
}
