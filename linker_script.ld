ENTRY(_start)

/* Define memory regions */
MEMORY
{
    rom (rx)  : ORIGIN = 0x100000, LENGTH = 1M
    ram (rwx) : ORIGIN = 0x200000, LENGTH = 512K
}

/* Define sections */

SECTIONS
{
    .text :
    {
        *(.text)
        *(.text.*)
    } > rom AT > ram

    .rodata :
    {
        *(.rodata)
        *(.rodata.*)
    } > rom

    .data :
    {
        *(.data)
        *(.data.*)
    } > ram AT > rom

    .bss (NOLOAD) :
    {
        *(.bss)
        *(COMMON)
    } > ram

    .stack (NOLOAD) :
    {
        . = ALIGN(16);
        _stack_start = .;
        . += 0x4000;  /* Define stack size */
        _stack_end = .;
    } > ram

    _end = .;
}


