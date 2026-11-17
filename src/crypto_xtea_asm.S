    .text
    .code64
    .globl woody_xtea_ctr_asm
    .type woody_xtea_ctr_asm, @function

// void woody_xtea_ctr_asm(uint8_t *buffer, size_t size, const uint32_t key[4], uint64_t nonce)
woody_xtea_ctr_asm:
    pushq %rbx
    pushq %rbp
    pushq %r12
    pushq %r13
    pushq %r14
    pushq %r15
    subq $8, %rsp

    movq %rdi, %r12               /* buffer */
    movq %rsi, %r13               /* size */
    movq %rdx, %r14               /* key[4] */
    movq %rcx, %r15               /* nonce */
    xorq %rbx, %rbx               /* byte offset */

.Lxtea_asm_block:
    cmpq %r13, %rbx
    jae .Lxtea_asm_done

    // coutner = nonce + block index.
    movq %rbx, %r11
    shrq $3, %r11
    addq %r15, %r11
    movl %r11d, %eax              /* v0 */
    shrq $32, %r11
    movl %r11d, %edx              /* v1 */
    xorl %esi, %esi               /* sum */
    movl $32, %r10d               /* rounds */

.Lxtea_asm_round:
    // v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3])
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

    // v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum >> 11) & 3])
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

    decl %r10d
    jnz .Lxtea_asm_round

    // Serialize the 64-bit keystream block in little-endian order.
    movl %eax, 0(%rsp)
    movl %edx, 4(%rsp)
    movq %r13, %r10
    subq %rbx, %r10
    cmpq $8, %r10
    jbe .Lxtea_asm_count_ready
    movq $8, %r10
.Lxtea_asm_count_ready:
    xorl %r11d, %r11d
.Lxtea_asm_xor_byte:
    movzbl (%r12,%rbx), %edi
    xorb (%rsp,%r11), %dil
    movb %dil, (%r12,%rbx)
    incq %rbx
    incq %r11
    decq %r10
    jnz .Lxtea_asm_xor_byte
    jmp .Lxtea_asm_block

.Lxtea_asm_done:
    addq $8, %rsp
    popq %r15
    popq %r14
    popq %r13
    popq %r12
    popq %rbp
    popq %rbx
    ret

    .size woody_xtea_ctr_asm, .-woody_xtea_ctr_asm
    .section .note.GNU-stack,"",@progbits
