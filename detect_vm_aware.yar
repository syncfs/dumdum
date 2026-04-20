rule vm_aware_branching {
    meta:
        description = "ELF reading /proc/cpuinfo and checking for hypervisor string as a VM detection indicator"
    strings:
        $cpuinfo    = "/proc/cpuinfo" ascii
        $hypervisor = "hypervisor" ascii
        $proc_fd    = "/proc/self/fd/" ascii
        $dlopen     = "dlopen" ascii
    condition:
        uint32(0) == 0x464C457F and
        $cpuinfo and
        $hypervisor and
        $proc_fd and
        $dlopen
}

rule dual_payload_loader {
    meta:
        description = "ELF with two packed payload paths indicating environment-conditional loading"
    strings:
        $packed1 = ".so.packed" ascii
        $memfd   = { B8 3F 01 00 00 }
    condition:
        uint32(0) == 0x464C457F and
        #packed1 >= 2 and
        $memfd
}
