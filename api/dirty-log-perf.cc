#include "kvmxx.hh"
#include "memmap.hh"
#include "identity.hh"
#include <boost/thread/thread.hpp>
#include <stdlib.h>
#include <stdio.h>
#include <sys/time.h>

namespace {

const int page_size		= 4096;
const int64_t nr_total_pages	= 256 * 1024;

// Return the current time in nanoseconds.
uint64_t time_ns()
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * (uint64_t)1000000000 + ts.tv_nsec;
}

// Update nr_to_write pages selected from nr_pages pages.
void write_mem(void* slot_head, int64_t nr_to_write, int64_t nr_pages)
{
    char* var = static_cast<char*>(slot_head);
    int64_t interval = nr_pages / nr_to_write;

    for (int64_t i = 0; i < nr_to_write; ++i) {
        ++(*var);
        var += interval * page_size;
    }
}

using boost::ref;
using std::tr1::bind;

// Let the guest update nr_to_write pages selected from nr_pages pages.
void do_guest_write(kvm::vcpu& vcpu, void* slot_head,
                    int64_t nr_to_write, int64_t nr_pages)
{
    identity::vcpu guest_write_thread(vcpu, bind(write_mem, ref(slot_head),
                                                 nr_to_write, nr_pages));
    vcpu.run();
}

// Check how long it takes to update dirty log.
void check_dirty_log(kvm::vcpu& vcpu, mem_slot& slot, void* slot_head)
{
    slot.set_dirty_logging(true);
    slot.update_dirty_log();

    for (int64_t i = 1; i <= nr_total_pages; i *= 2) {
        do_guest_write(vcpu, slot_head, i, nr_total_pages);

        uint64_t start_ns = time_ns();
        slot.update_dirty_log();
        uint64_t end_ns = time_ns();

        printf("get dirty log: %10lld ns for %10lld dirty pages\n",
               end_ns - start_ns, i);
    }

    slot.set_dirty_logging(false);
}

}

int main(int ac, char **av)
{
    kvm::system sys;
    kvm::vm vm(sys);
    mem_map memmap(vm);

    void* mem_head;
    int64_t mem_size = nr_total_pages * page_size;
    if (posix_memalign(&mem_head, page_size, mem_size)) {
        printf("dirty-log-perf: Could not allocate guest memory.\n");
        exit(1);
    }
    uint64_t mem_addr = reinterpret_cast<uint64_t>(mem_head);

    identity::hole hole(mem_head, mem_size);
    identity::vm ident_vm(vm, memmap, hole);
    kvm::vcpu vcpu(vm, 0);

    mem_slot slot(memmap, mem_addr, mem_size, mem_head);

    // pre-allocate shadow pages
    do_guest_write(vcpu, mem_head, nr_total_pages, nr_total_pages);
    check_dirty_log(vcpu, slot, mem_head);
    return 0;
}
