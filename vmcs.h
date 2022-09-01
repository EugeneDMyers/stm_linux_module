#ifndef VMCS_H
#define VMCS_H

struct vmcs_hdr {
        u32 revision_id:31;
        u32 shadow_vmcs:1;
};

struct vmcs {
        struct vmcs_hdr hdr;
        u32 abort;
        char data[];
};

#endif
