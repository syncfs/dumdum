rule ldpreload_rtld_next
{
    meta:
        description = "ELF shared library menggunakan RTLD_NEXT — indikator dlsym-based function hooking"
        severity    = "medium"

    strings:
        // ELF64 LE header + e_type=ET_DYN (0x0003) di offset 16
        $elf64_dyn = { 7F 45 4C 46 02 01 01 00 00 00 00 00 00 00 00 00 03 00 }
        $rtld_next = "RTLD_NEXT"
        $dlsym     = "dlsym"

    condition:
        $elf64_dyn at 0 and
        $rtld_next and
        $dlsym
}

rule ldpreload_syscall_trio
{
    meta:
        description = "ELF shared library mengekspor puts + fopen + read sekaligus — pola hooking libc I/O functions"
        severity    = "high"

    strings:
        $elf64_dyn = { 7F 45 4C 46 02 01 01 00 00 00 00 00 00 00 00 00 03 00 }
        $sym_puts  = "puts"  fullword
        $sym_fopen = "fopen" fullword
        $sym_read  = "read"  fullword

    condition:
        $elf64_dyn at 0 and
        all of ($sym_*)
}

rule ldpreload_hook_log_pattern
{
    meta:
        description = "Shared library mengandung string log [HOOKED] — artefak debug/trace dari preload hook"
        severity    = "high"

    strings:
        $elf64_dyn    = { 7F 45 4C 46 02 01 01 00 00 00 00 00 00 00 00 00 03 00 }
        $hooked_tag   = "[HOOKED]"
        $hooked_puts  = "[HOOKED] puts"
        $hooked_fopen = "[HOOKED] fopen"
        $hooked_read  = "[HOOKED] read"

    condition:
        $elf64_dyn at 0 and
        $hooked_tag and
        2 of ($hooked_puts, $hooked_fopen, $hooked_read)
}
