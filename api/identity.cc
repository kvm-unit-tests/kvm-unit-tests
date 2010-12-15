
#include "identity.hh"
#include <stdio.h>

namespace identity {

typedef unsigned long ulong;

void setup_vm(kvm::vm& vm)
{
    vm.set_memory_region(0, NULL, 0, 3UL << 30);
    vm.set_tss_addr(3UL << 30);
}

void vcpu::setup_sregs()
{
    kvm_sregs sregs = { };
    kvm_segment dseg = { };
    dseg.base = 0; dseg.limit = -1U; dseg.type = 3; dseg.present = 1;
    dseg.dpl = 3; dseg.db = 1; dseg.s = 1; dseg.l = 0; dseg.g = 1;
    kvm_segment cseg = dseg;
    cseg.type = 11;

    sregs.cs = cseg; asm ("mov %%cs, %0" : "=rm"(sregs.cs.selector));
    sregs.ds = dseg; asm ("mov %%ds, %0" : "=rm"(sregs.ds.selector));
    sregs.es = dseg; asm ("mov %%es, %0" : "=rm"(sregs.es.selector));
    sregs.fs = dseg; asm ("mov %%fs, %0" : "=rm"(sregs.fs.selector));
    sregs.gs = dseg; asm ("mov %%gs, %0" : "=rm"(sregs.gs.selector));
    sregs.ss = dseg; asm ("mov %%ss, %0" : "=rm"(sregs.ss.selector));

    uint32_t gsbase;
    asm ("mov %%gs:0, %0" : "=r"(gsbase));
    sregs.gs.base = gsbase;

    sregs.tr.base = reinterpret_cast<ulong>(&*_stack.begin());
    sregs.tr.type = 11;
    sregs.tr.s = 0;
    sregs.tr.present = 1;

    sregs.cr0 = 0x11; /* PE, ET, !PG */
    sregs.cr4 = 0;
    sregs.efer = 0;
    sregs.apic_base = 0xfee00000;
    _vcpu.set_sregs(sregs);
}

void vcpu::thunk(vcpu* zis)
{
    zis->_guest_func();
    asm volatile("outb %%al, %%dx" : : "a"(0), "d"(0));
}

void vcpu::setup_regs()
{
    kvm_regs regs = {};
    regs.rflags = 0x3202;
    regs.rsp = reinterpret_cast<ulong>(&*_stack.end());
    regs.rsp &= ~15UL;
    ulong* sp = reinterpret_cast<ulong *>(regs.rsp);
    *--sp = reinterpret_cast<ulong>((char*)this);
    *--sp = 0;
    regs.rsp = reinterpret_cast<ulong>(sp);
    regs.rip = reinterpret_cast<ulong>(&vcpu::thunk);
    printf("rip %llx\n", regs.rip);
    _vcpu.set_regs(regs);
}

vcpu::vcpu(kvm::vcpu& vcpu, std::tr1::function<void ()> guest_func,
           unsigned long stack_size)
    : _vcpu(vcpu), _guest_func(guest_func), _stack(stack_size)
{
    setup_sregs();
    setup_regs();
}

}
