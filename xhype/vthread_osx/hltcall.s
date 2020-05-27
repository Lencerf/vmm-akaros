    .globl _hltcall
_hltcall:
    hlt

    .globl _increas_a
_increas_a:
    movl 0x40f8(%rip), %eax
    addl $2, %eax
    movl %eax,  0x40f8(%rip)
    hlt