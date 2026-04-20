import "math"

rule fileless_memfd_loader {
    meta:
        description = "ELF yang load shared library via memfd_create tanpa disk write"
    strings:
        $memfd_syscall = { B8 3F 01 00 00 }
        $proc_fd = "/proc/self/fd/" ascii
        $dlopen_str = "dlopen" ascii
    condition:
        uint32(0) == 0x464C457F and
        $memfd_syscall and
        $proc_fd and
        $dlopen_str
}

rule high_entropy_elf_section {
    meta:
        description = "ELF dengan entropy tinggi — indikasi packed payload"
    condition:
        uint32(0) == 0x464C457F and
        math.entropy(0, filesize) > 7.0
}

rule high_entropy_packed_blob {
    meta:
        description = "File dengan entropy tinggi tanpa ELF header — indikasi encrypted/packed payload"
    condition:
        uint32(0) != 0x464C457F and
        math.entropy(0, filesize) > 7.0
}
