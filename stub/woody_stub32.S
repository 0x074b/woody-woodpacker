    .section .text
    .code32
    .globl woody32_stub_start
    .globl woody32_stub_end
    .globl woody32_key
    .globl woody32_jump_disp
    .globl woody32_segment_count
    .globl woody32_segment_table

woody32_stub_start:
    pushfl
    pushal

    // Obtain a position independent base address for this injected stub
    call .L32_get_pc
.L32_get_pc:
    popl %ebp
    subl $(.L32_get_pc - woody32_stub_start), %ebp

    // Print the mandatory banner, accounting for EINTR and partial writes
    leal (.L32_banner - woody32_stub_start)(%ebp), %ecx
    movl $14, %edx
.L32_write_banner:
    movl $4, %eax                 /* __NR_write */
    movl $1, %ebx                 /* stdout */
    int $0x80
    cmpl $-4, %eax                /* -EINTR */
    je .L32_write_banner
    testl %eax, %eax
    jle .L32_fatal
    addl %eax, %ecx
    subl %eax, %edx
    jne .L32_write_banner

    // The original entry stack starts 36 bytes above the saved context
    leal 36(%esp), %edi
    movl (%edi), %ecx             /* argc */
    leal 4(%edi,%ecx,4), %esi     /* argv[argc] */
    addl $4, %esi                 /* envp[0] */
.L32_skip_env:
    cmpl $0, (%esi)
    je .L32_auxv_start
    addl $4, %esi
    jmp .L32_skip_env
.L32_auxv_start:
    addl $4, %esi
.L32_find_pagesz:
    cmpl $6, (%esi)               /* AT_PAGESZ */
    je .L32_check_pagesz
    cmpl $0, (%esi)               /* AT_NULL */
    je .L32_fatal
    addl $8, %esi
    jmp .L32_find_pagesz
.L32_check_pagesz:
    cmpl $4096, 4(%esi)
    jne .L32_fatal

    leal (woody32_segment_count - woody32_stub_start)(%ebp), %esi
    movl (%esi), %edi             /* descriptor count */
    addl $4, %esi                /* first descriptor */
    testl %edi, %edi
    jz .L32_fatal
.L32_segment_loop:
    // Descriptor: {dest_delta, length, nonce_lo, nonce_hi, prot, crc32}
    movl 0(%esi), %eax
    addl %ebp, %eax               /* destination */
    movl 4(%esi), %ecx             /* length */
    testl %ecx, %ecx
    jz .L32_fatal

    // Make the target pages writable while checking/decrypting
    movl %eax, %ebx
    andl $-4096, %ebx
    movl %eax, %edx
    addl %ecx, %edx
    jc .L32_fatal
    addl $4095, %edx
    jc .L32_fatal
    andl $-4096, %edx
    subl %ebx, %edx               /* rounded mapping length */
    movl %edx, %ecx               /* arg2: length */
    movl $7, %edx                 /* arg3: PROT_READ | PROT_WRITE | PROT_EXEC */
    movl $125, %eax               /* __NR_mprotect: ebx=addr, ecx=len, edx=prot */
    int $0x80
    testl %eax, %eax
    js .L32_fatal

    // Verify ciphertext integrity before decryption (IEEE CRC-32)
    pushl %esi
    pushl %edi
    movl 0(%esi), %eax
    addl %ebp, %eax
    movl %eax, %esi
    movl 4(%esp), %ecx            /* saved descriptor pointer */
    movl 4(%ecx), %ecx
    movl $0xFFFFFFFF, %eax
.L32_crc_byte:
    testl %ecx, %ecx
    jz .L32_crc_done
    movzbl (%esi), %edx
    xorl %edx, %eax
    movl $8, %edi
.L32_crc_bit:
    shrl $1, %eax
    jnc .L32_crc_no_xor
    xorl $0xEDB88320, %eax
.L32_crc_no_xor:
    decl %edi
    jne .L32_crc_bit
    incl %esi
    decl %ecx
    jmp .L32_crc_byte
.L32_crc_done:
    notl %eax
    movl 4(%esp), %ecx
    cmpl 20(%ecx), %eax
    jne .L32_fatal
    popl %edi
    popl %esi

    // Call the in-stub XTEA-CTR routine (cdecl)
    pushl 12(%esi)                /* nonce high */
    pushl 8(%esi)                 /* nonce low */
    leal (woody32_key - woody32_stub_start)(%ebp), %eax
    pushl %eax                    /* key */
    pushl 4(%esi)                 /* length */
    movl 0(%esi), %eax
    addl %ebp, %eax
    pushl %eax                    /* destination */
    call .L32_xtea_ctr
    addl $20, %esp

    // Restore the original protection flags
    movl 0(%esi), %eax
    addl %ebp, %eax
    movl %eax, %ebx
    andl $-4096, %ebx
    movl 4(%esi), %ecx
    movl %eax, %edx
    addl %ecx, %edx
    jc .L32_fatal
    addl $4095, %edx
    jc .L32_fatal
    andl $-4096, %edx
    subl %ebx, %edx               /* rounded mapping length */
    movl %edx, %ecx               /* arg2: length */
    movl 16(%esi), %edx           /* arg3: original PROT_* flags */
    movl $125, %eax               /* __NR_mprotect */
    int $0x80
    testl %eax, %eax
    js .L32_fatal

    addl $24, %esi
    decl %edi
    jne .L32_segment_loop

    popal
    popfl
    .byte 0xE9
woody32_jump_disp:
    .long 0

.L32_fatal:
    movl $1, %eax                 /* __NR_exit */
    movl $127, %ebx
    int $0x80
    ud2

// void xtea_ctr32(uint8_t *buf, uint32_t len, const uint32_t key[4], uint32_t nonce_lo, uint32_t nonce_hi)
// cdecl uses only 32-bit arithmetic and preserves EBX/ESI/EDI/EBP
.L32_xtea_ctr:
    .globl woody32_xtea_ctr_test
    .type woody32_xtea_ctr_test, @function
woody32_xtea_ctr_test:
    pushl %ebp
    movl %esp, %ebp
    pushl %ebx
    pushl %esi
    pushl %edi
    subl $48, %esp
    movl 8(%ebp), %eax
    movl %eax, -16(%ebp)          /* buffer */
    movl 12(%ebp), %eax
    movl %eax, -20(%ebp)          /* length */
    movl 16(%ebp), %eax
    movl %eax, -24(%ebp)          /* key */
    movl 20(%ebp), %eax
    movl %eax, -28(%ebp)          /* nonce low */
    movl 24(%ebp), %eax
    movl %eax, -32(%ebp)          /* nonce high */
    movl $0, -36(%ebp)            /* byte offset */
.L32_xtea_block:
    movl -36(%ebp), %eax
    cmpl -20(%ebp), %eax
    jae .L32_xtea_done
    shrl $3, %eax
    addl -28(%ebp), %eax
    movl -32(%ebp), %edx
    adcl $0, %edx
    movl %eax, -40(%ebp)          /* v0 */
    movl %edx, -44(%ebp)          /* v1 */
    movl $0, -48(%ebp)            /* sum */
    movl $32, -52(%ebp)           /* rounds */
.L32_xtea_round:
    movl -44(%ebp), %edx
    movl %edx, %esi
    shll $4, %esi
    movl %edx, %edi
    shrl $5, %edi
    xorl %edi, %esi
    addl %edx, %esi
    movl -48(%ebp), %ecx
    movl %ecx, %edi
    andl $3, %edi
    movl -24(%ebp), %ebx
    movl (%ebx,%edi,4), %edi
    addl %ecx, %edi
    xorl %edi, %esi
    addl %esi, -40(%ebp)

    addl $0x9E3779B9, -48(%ebp)

    movl -40(%ebp), %eax
    movl %eax, %esi
    shll $4, %esi
    movl %eax, %edi
    shrl $5, %edi
    xorl %edi, %esi
    addl %eax, %esi
    movl -48(%ebp), %ecx
    movl %ecx, %edi
    shrl $11, %edi
    andl $3, %edi
    movl -24(%ebp), %ebx
    movl (%ebx,%edi,4), %edi
    addl %ecx, %edi
    xorl %edi, %esi
    addl %esi, -44(%ebp)

    decl -52(%ebp)
    jne .L32_xtea_round

    // Store the full keystream contiguously below the local round state
    movl -40(%ebp), %eax
    movl %eax, -60(%ebp)          /* keystream bytes 0..3 */
    movl -44(%ebp), %eax
    movl %eax, -56(%ebp)          /* keystream bytes 4..7 */
    movl -20(%ebp), %ecx
    subl -36(%ebp), %ecx
    cmpl $8, %ecx
    jbe .L32_xtea_count_ready
    movl $8, %ecx
.L32_xtea_count_ready:
    xorl %edi, %edi
.L32_xtea_xor_byte:
    movl -16(%ebp), %esi
    movl -36(%ebp), %edx
    movzbl (%esi,%edx), %eax
    movzbl -60(%ebp,%edi), %ebx
    xorl %ebx, %eax
    movb %al, (%esi,%edx)
    incl -36(%ebp)
    incl %edi
    decl %ecx
    jne .L32_xtea_xor_byte
    jmp .L32_xtea_block
.L32_xtea_done:
    addl $48, %esp
    popl %edi
    popl %esi
    popl %ebx
    leave
    ret
    .size woody32_xtea_ctr_test, .-woody32_xtea_ctr_test

    .balign 4
.L32_key:
woody32_key:
    .long 0, 0, 0, 0
.L32_banner:
    .ascii "....WOODY....\n"
    .balign 4
woody32_segment_count:
    .long 0
woody32_segment_table:
    .long 0                       /* destination delta */
    .long 0                       /* length */
    .long 0                       /* nonce low */
    .long 0                       /* nonce high */
    .long 0                       /* original PROT_* */
    .long 0                       /* CRC-32 of ciphertext */
woody32_stub_end:
    .size woody32_stub_start, woody32_stub_end-woody32_stub_start

    .section .note.GNU-stack,"",@progbits
