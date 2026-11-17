    .section .text
    .code64
    .globl woody_stub_start
    .globl woody_stub_end
    .globl woody_key
    .globl woody_jump_disp
    .globl woody_segment_count
    .globl woody_segment_table
    .type woody_stub_start, @function

woody_stub_start:
.Lwoody_stub_start:
    endbr64
    // Preserve the integer context expected at the original ELF entry
    pushfq
    pushq %rax
    pushq %rbx
    pushq %rcx
    pushq %rdx
    pushq %rsi
    pushq %rdi
    pushq %rbp
    pushq %r8
    pushq %r9
    pushq %r10
    pushq %r11
    pushq %r12
    pushq %r13
    pushq %r14
    pushq %r15

    leaq .Lwoody_banner(%rip), %rsi
    movq $14, %r8
.Lwoody_write_banner:
    movl $1, %eax                  /* SYS_write */
    movl $1, %edi                  /* stdout */
    movq %r8, %rdx
    syscall
    cmpq $-4, %rax                 /* -EINTR */
    je .Lwoody_write_banner
    testq %rax, %rax
    jle woody_stub_fatal
    addq %rax, %rsi
    subq %rax, %r8
    jne .Lwoody_write_banner

    // Verify the runtime page size through the initial process auxv
    leaq 128(%rsp), %rdi           /* original entry RSP */
    movq (%rdi), %rcx              /* argc */
    leaq 8(%rdi,%rcx,8), %rdi      /* argv[argc] */
    addq $8, %rdi                  /* envp[0] */
.Lwoody_skip_env:
    cmpq $0, (%rdi)
    je .Lwoody_auxv_start
    addq $8, %rdi
    jmp .Lwoody_skip_env
.Lwoody_auxv_start:
    addq $8, %rdi                  /* first auxv entry */
.Lwoody_find_pagesz:
    cmpq $6, (%rdi)               /* AT_PAGESZ */
    je .Lwoody_check_pagesz
    cmpq $0, (%rdi)               /* AT_NULL before AT_PAGESZ is invalid */
    je woody_stub_fatal
    addq $16, %rdi
    jmp .Lwoody_find_pagesz
.Lwoody_check_pagesz:
    cmpq $4096, 8(%rdi)
    jne woody_stub_fatal

    // Records carry destination/source deltas, lengths, nonce, prot, CRC and flags
    leaq .Lwoody_segment_count(%rip), %r12
    movq (%r12), %r13
    addq $8, %r12
    testq %r13, %r13
    jz woody_stub_fatal
.Lwoody_segment_loop:
    movq 0(%r12), %rax
    leaq .Lwoody_stub_start(%rip), %r14
    addq %rax, %r14                /* destination runtime address */
    movq 8(%r12), %rax
    leaq .Lwoody_stub_start(%rip), %rbx
    addq %rax, %rbx                /* encrypted payload runtime address */
    movq 16(%r12), %rbp            /* encrypted payload length */
    movq 24(%r12), %r15            /* reconstructed file-backed length */
    testq %rbp, %rbp
    jz woody_stub_fatal
    testq %r15, %r15
    jz woody_stub_fatal

    // Make only the target segment's isolated pages writable
    movq %r14, %rdi
    andq $-4096, %rdi
    movq %r14, %rsi
    addq %r15, %rsi
    jc woody_stub_fatal
    addq $4095, %rsi
    jc woody_stub_fatal
    andq $-4096, %rsi
    subq %rdi, %rsi
    movl $7, %edx                  /* PROT_READ | PROT_WRITE | PROT_EXEC */
    movl $10, %eax                 /* SYS_mprotect */
    syscall
    testq %rax, %rax
    js woody_stub_fatal

    // Verify ciphertext before decrypting it (IEEE CRC-32)
    movq %rbx, %rsi
    movq %rbp, %rcx
    movl $0xFFFFFFFF, %eax
.Lwoody_crc_byte:
    testq %rcx, %rcx
    jz .Lwoody_crc_done
    movzbl (%rsi), %edx
    xorl %edx, %eax
    movl $8, %edi
.Lwoody_crc_bit:
    shrl $1, %eax
    jnc .Lwoody_crc_no_xor
    xorl $0xEDB88320, %eax
.Lwoody_crc_no_xor:
    decl %edi
    jne .Lwoody_crc_bit
    incq %rsi
    decq %rcx
    jmp .Lwoody_crc_byte
.Lwoody_crc_done:
    notl %eax
    cmpl 44(%r12), %eax
    jne woody_stub_fatal

    // XTEA-CTR is symmetric the source may be in the separate data PT_LOAD
    movq %rbx, %rdi
    movq %rbp, %rsi
    leaq .Lwoody_key(%rip), %rdx
    movq 32(%r12), %rcx
    call woody_xtea_ctr

    // Flag bit 0 selects LZSS otherwise the decrypted payload is raw
    testl $1, 48(%r12)
    jz .Lwoody_raw_payload
    movq %rbx, %rdi
    movq %rbp, %rsi
    movq %r14, %rdx
    movq %r15, %rcx
    call .Lwoody_lzss_decompress
    testq %rax, %rax
    js woody_stub_fatal
    jmp .Lwoody_payload_ready
.Lwoody_raw_payload:
    cmpq %rbx, %r14
    je .Lwoody_payload_ready
    cmpq %rbp, %r15
    jne woody_stub_fatal
    movq %rbx, %rsi
    movq %r14, %rdi
    movq %r15, %rcx
    rep movsb
.Lwoody_payload_ready:

    // Restore the original protection flags for this segment
    movq %r14, %rdi
    andq $-4096, %rdi
    movq %r14, %rsi
    addq %r15, %rsi
    jc woody_stub_fatal
    addq $4095, %rsi
    jc woody_stub_fatal
    andq $-4096, %rsi
    subq %rdi, %rsi
    movl 40(%r12), %edx
    movl $10, %eax                 /* SYS_mprotect */
    syscall
    testq %rax, %rax
    js woody_stub_fatal

    addq $56, %r12
    decq %r13
    jne .Lwoody_segment_loop

    // Restore entry context, then jump to the original e_entry
    popq %r15
    popq %r14
    popq %r13
    popq %r12
    popq %r11
    popq %r10
    popq %r9
    popq %r8
    popq %rbp
    popq %rdi
    popq %rsi
    popq %rdx
    popq %rcx
    popq %rbx
    popq %rax
    popfq
    .byte 0xE9
woody_jump_disp:
    .long 0

woody_stub_fatal:
    movl $60, %eax                 /* SYS_exit */
    movl $127, %edi
    syscall
    ud2

// XTEA-CTR implementation system V AMD64 arguments: rdi, rsi, rdx, rcx
    .type woody_xtea_ctr, @function
woody_xtea_ctr:
    pushq %rbp
    pushq %rbx
    pushq %r12
    pushq %r13
    pushq %r14
    pushq %r15
    subq $8, %rsp
    movq %rdi, %r12                /* data */
    movq %rsi, %r13                /* byte length */
    movq %rdx, %r14                /* four 32-bit key words */
    movq %rcx, %r15                /* 64-bit nonce */
    xorq %rbx, %rbx                /* byte offset */

.Lwoody_xtea_block:
    cmpq %r13, %rbx
    jae .Lwoody_xtea_done
    movq %rbx, %r11
    shrq $3, %r11
    addq %r15, %r11                /* nonce + block counter */
    movl %r11d, %eax               /* v0 */
    shrq $32, %r11
    movl %r11d, %edx               /* v1 */
    xorl %esi, %esi                /* sum */
    movl $32, %ecx                 /* rounds */

.Lwoody_xtea_round:
    movl %edx, %ebp
    shll $4, %ebp
    movl %edx, %edi
    shrl $5, %edi
    xorl %edi, %ebp
    addl %edx, %ebp
    movl %esi, %edi
    andl $3, %edi
    movl (%r14,%rdi,4), %edi
    addl %esi, %edi
    xorl %edi, %ebp
    addl %ebp, %eax

    addl $0x9E3779B9, %esi
    movl %eax, %ebp
    shll $4, %ebp
    movl %eax, %edi
    shrl $5, %edi
    xorl %edi, %ebp
    addl %eax, %ebp
    movl %esi, %edi
    shrl $11, %edi
    andl $3, %edi
    movl (%r14,%rdi,4), %edi
    addl %esi, %edi
    xorl %edi, %ebp
    addl %ebp, %edx
    decl %ecx
    jnz .Lwoody_xtea_round

    movl %eax, (%rsp)
    movl %edx, 4(%rsp)
    movq %r13, %r10
    subq %rbx, %r10
    cmpq $8, %r10
    jbe .Lwoody_xtea_byte_count_ready
    movq $8, %r10
.Lwoody_xtea_byte_count_ready:
    xorl %r11d, %r11d
.Lwoody_xtea_xor_byte:
    movzbl (%r12,%rbx), %edi
    xorb (%rsp,%r11), %dil
    movb %dil, (%r12,%rbx)
    incq %rbx
    incq %r11
    decq %r10
    jnz .Lwoody_xtea_xor_byte
    jmp .Lwoody_xtea_block

.Lwoody_xtea_done:
    addq $8, %rsp
    popq %r15
    popq %r14
    popq %r13
    popq %r12
    popq %rbx
    popq %rbp
    ret

// int woody_lzss_decompress(src, src_len, dst, dst_len)
    .globl woody_lzss_decompress
    .type woody_lzss_decompress, @function
woody_lzss_decompress:
.Lwoody_lzss_decompress:
    pushq %rbx
    pushq %rbp
    pushq %r12
    pushq %r13
    pushq %r14
    pushq %r15
    movq %rdi, %r12               /* source cursor */
    movq %rdi, %r13
    addq %rsi, %r13               /* source end */
    jc .Lwoody_lzss_fail
    movq %rdx, %r14               /* destination cursor */
    movq %rdx, %rbx               /* destination start */
    movq %rdx, %r15
    addq %rcx, %r15               /* destination end */
    jc .Lwoody_lzss_fail
    xorl %ebp, %ebp               /* current control byte */
    xorl %r11d, %r11d             /* remaining control bits */
.Lwoody_lzss_loop:
    cmpq %r15, %r14
    je .Lwoody_lzss_done
    testl %r11d, %r11d
    jne .Lwoody_lzss_have_control
    cmpq %r13, %r12
    jae .Lwoody_lzss_fail
    movzbl (%r12), %ebp
    incq %r12
    movl $8, %r11d
.Lwoody_lzss_have_control:
    testb $1, %bpl
    jz .Lwoody_lzss_match
    cmpq %r13, %r12
    jae .Lwoody_lzss_fail
    movb (%r12), %al
    incq %r12
    movb %al, (%r14)
    incq %r14
    jmp .Lwoody_lzss_next_token
.Lwoody_lzss_match:
    leaq 2(%r12), %rax
    cmpq %r13, %rax
    ja .Lwoody_lzss_fail
    movzbl (%r12), %eax
    movzbl 1(%r12), %edx
    addq $2, %r12
    movl %edx, %ecx
    andl $0x0F, %ecx
    addl $3, %ecx               /* match length */
    shrl $4, %edx
    shll $8, %edx
    orl %eax, %edx               /* match distance */
    testl %edx, %edx
    jz .Lwoody_lzss_fail
    movq %r14, %rax
    subq %rbx, %rax
    cmpq %rdx, %rax
    jb .Lwoody_lzss_fail        /* distance exceeds produced output */
    movq %r15, %rax
    subq %r14, %rax
    cmpq %rcx, %rax
    jb .Lwoody_lzss_fail        /* match exceeds requested output */
    movq %r14, %rsi
    subq %rdx, %rsi             /* overlapping back-reference source */
.Lwoody_lzss_copy_match:
    movb (%rsi), %al
    movb %al, (%r14)
    incq %rsi
    incq %r14
    decl %ecx
    jne .Lwoody_lzss_copy_match
.Lwoody_lzss_next_token:
    shrl $1, %ebp
    decl %r11d
    jmp .Lwoody_lzss_loop
.Lwoody_lzss_done:
    cmpq %r13, %r12
    jne .Lwoody_lzss_fail
    xorl %eax, %eax
    jmp .Lwoody_lzss_return
.Lwoody_lzss_fail:
    movq $-1, %rax
.Lwoody_lzss_return:
    popq %r15
    popq %r14
    popq %r13
    popq %r12
    popq %rbp
    popq %rbx
    ret

    .balign 8
woody_key:
.Lwoody_key:
    .long 0, 0, 0, 0
woody_banner:
.Lwoody_banner:
    .ascii "....WOODY....\n"

    .balign 8
woody_segment_count:
.Lwoody_segment_count:
    .quad 0
woody_segment_table:
.Lwoody_segment_table:
    // One descriptor is embedded the packer appends any additional ones
    .quad 0                         /* destination delta from stub base */
    .quad 0                         /* encrypted source delta from stub base */
    .quad 0                         /* encrypted payload length */
    .quad 0                         /* reconstructed file-backed length */
    .quad 0                         /* segment-specific CTR nonce */
    .long 0                         /* original PROT_* flags */
    .long 0                         /* CRC-32 of ciphertext */
    .long 0                         /* flags: bit 0 = LZSS compressed */
    .long 0                         /* reserved */
woody_stub_end:
    .size woody_stub_start, woody_stub_end-woody_stub_start

    .section .note.GNU-stack,"",@progbits
