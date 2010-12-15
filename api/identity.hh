#ifndef API_IDENTITY_HH
#define API_IDENTITY_HH

#include "kvmxx.hh"
#include <tr1/functional>
#include <vector>

namespace identity {

void setup_vm(kvm::vm& vm);

class vcpu {
public:
    vcpu(kvm::vcpu& vcpu, std::tr1::function<void ()> guest_func,
	 unsigned long stack_size = 256 * 1024);
private:
    static void thunk(vcpu* vcpu);
    void setup_regs();
    void setup_sregs();
private:
    kvm::vcpu& _vcpu;
    std::tr1::function<void ()> _guest_func;
    std::vector<char> _stack;
};

}

#endif
