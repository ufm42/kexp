OUTPUT_FORMAT(binary)

SECTIONS
{
    .text : {
        *(.entry)
        *(.text*)
        *(.rodata*)
        *(.data*)
        _elf_start = .;
        *(.elfldr)
        _elf_end = .;
    }
}