/*
#
#    Copyright 2009, Lukas Lueg, lukas.lueg@gmail.com
#    
#    SHA-1 SSE2 Copyright 2008, 2009, Alvaro Salmador, naplam33@msn.com
#    ported from SHA-1 MMX by Simon Marechal, simon@banquise.net
#
#    This file is part of Pyrit.
#
#    Pyrit is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    Pyrit is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with Pyrit.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "_cpyrit_cpu.h"

#ifdef COMPILE_SSE2

#define ctxa %xmm0
#define ctxb %xmm1
#define ctxc %xmm2
#define ctxd %xmm3
#define ctxe %xmm4
#define tmp1 %xmm5
#define tmp2 %xmm6
#define tmp3 %xmm7
#define tmp4 ctxa
#define tmp5 ctxb

#ifdef __x86_64__
    #define _reloc(x) x(%rip)
    #define eax_rdi %rdi
    #define ebx_rbx %rbx
    #define ecx_rcx %rcx
    #define ecx_rdx %rdx
    #define edx_rdx %rdx
    #define edx_rsi %rsi
#else
    #define _reloc(x) x
    #define eax_rdi %eax
    #define ebx_rbx %ebx
    #define ecx_rcx %ecx
    #define ecx_rdx %ecx
    #define edx_rdx %edx
    #define edx_rsi %edx
#endif

#define F0(x,y,z)       \
    movdqa  x, tmp2;    \
    movdqa  x, tmp1;    \
    pand    y, tmp2;    \
    pandn   z, tmp1;    \
    por     tmp2, tmp1; 

#define F1(x,y,z)       \
    movdqa  z, tmp1;    \
    pxor    y, tmp1;    \
    pxor    x, tmp1;

#define F2(x,y,z)       \
    movdqa  x, tmp1;    \
    movdqa  x, tmp2;    \
    pand    y, tmp1;    \
    por     y, tmp2;    \
    pand    z, tmp2;    \
    por     tmp2, tmp1;

#define subRoundX(a, b, c, d, e, f, k, data)    \
    f(b,c,d);                           \
    movdqa  a, tmp2;                    \
    movdqa  a, tmp3;                    \
    paddd   tmp1, e;                    \
    pslld   $5, tmp2;                   \
    psrld   $27, tmp3;                  \
    por     tmp3, tmp2;                 \
    paddd   tmp2, e;                    \
    movdqa  b, tmp2;                    \
    pslld   $30, b;                     \
    paddd   k, e;                       \
    psrld   $2, tmp2;                   \
    por     tmp2, b;                    \
    movdqa  (data*16)(edx_rsi), tmp1;   \
    movdqa  tmp1, tmp2;                 \
    pand    _reloc(const_ff00), tmp1;   \
    pand    _reloc(const_00ff), tmp2;   \
    psrld   $8, tmp1;                   \
    pslld   $8, tmp2;                   \
    por     tmp2, tmp1;                 \
    movdqa  tmp1, tmp2;                 \
    psrld   $16, tmp1;                  \
    pslld   $16, tmp2;                  \
    por     tmp2, tmp1;                 \
    movdqa  tmp1, (data*16)(ecx_rdx);   \
    paddd   tmp1, e;

#define subRoundY(a, b, c, d, e, f, k, data)\
    movdqa  ((data- 3)*16)(ecx_rdx), tmp1;  \
    pxor    ((data- 8)*16)(ecx_rdx), tmp1;  \
    pxor    ((data-14)*16)(ecx_rdx), tmp1;  \
    pxor    ((data-16)*16)(ecx_rdx), tmp1;  \
    movdqa  tmp1, tmp2;                     \
    pslld   $1, tmp1;                       \
    psrld   $31, tmp2;                      \
    por     tmp2, tmp1;                     \
    movdqa  tmp1, (data*16)(ecx_rdx);       \
    paddd   tmp1, e;                        \
    f(b,c,d);                               \
    movdqa  a, tmp2;                        \
    movdqa  a, tmp3;                        \
    paddd   tmp1, e;                        \
    pslld   $5, tmp2;                       \
    psrld   $27, tmp3;                      \
    por     tmp3, tmp2;                     \
    paddd   tmp2, e;                        \
    movdqa  b, tmp2;                        \
    pslld   $30, b;                         \
    paddd   k, e;                           \
    psrld   $2, tmp2;                       \
    por     tmp2, b;
 

.globl sse2_sha1_finalize;
.globl sse2_sha1_update;
.globl detect_sse2;


.data

.align(16)
const_stage0:   .long 0x5A827999, 0x5A827999, 0x5A827999, 0x5A827999
const_stage1:   .long 0x6ED9EBA1, 0x6ED9EBA1, 0x6ED9EBA1, 0x6ED9EBA1
const_stage2:   .long 0x8F1BBCDC, 0x8F1BBCDC, 0x8F1BBCDC, 0x8F1BBCDC
const_stage3:   .long 0xCA62C1D6, 0xCA62C1D6, 0xCA62C1D6, 0xCA62C1D6
const_ff00:     .long 0xFF00FF00, 0xFF00FF00, 0xFF00FF00, 0xFF00FF00
const_00ff:     .long 0x00FF00FF, 0x00FF00FF, 0x00FF00FF, 0x00FF00FF

 
.text

// arg 1 (eax) (64bit: rdi): context (4*20 bytes)
// arg 2 (edx) (64bit: rsi) : digests (4*20 bytes)
sse2_sha1_finalize:

    movdqa    0(eax_rdi), ctxa
    movdqa   16(eax_rdi), ctxb
    movdqa   32(eax_rdi), ctxc
    movdqa   48(eax_rdi), ctxd
    movdqa   64(eax_rdi), ctxe

    movdqa   _reloc(const_ff00), tmp3
    movdqa   ctxa, tmp1
    movdqa   ctxb, tmp2
    pand     tmp3, ctxa
    pand     tmp3, ctxb
    movdqa   _reloc(const_00ff), tmp3
    pand     tmp3, tmp1
    pand     tmp3, tmp2
    psrld    $8, ctxa
    psrld    $8, ctxb
    pslld    $8, tmp1
    pslld    $8, tmp2
    por      tmp1, ctxa
    por      tmp2, ctxb
    movdqa   ctxa, tmp1
    movdqa   ctxb, tmp2
    psrld    $16, ctxa
    psrld    $16, ctxb
    pslld    $16, tmp1
    pslld    $16, tmp2
    por      tmp1, ctxa
    por      tmp2, ctxb 
    movdqa   ctxa,  0(edx_rsi)
    movdqa   ctxb,  16(edx_rsi)

    movdqa   _reloc(const_ff00), tmp5
    movdqa   ctxc, tmp1
    movdqa   ctxd, tmp2
    movdqa   ctxe, tmp3
    pand     tmp5, ctxc
    pand     tmp5, ctxd
    pand     tmp5, ctxe
    movdqa   _reloc(const_00ff), tmp5
    pand     tmp5, tmp1
    pand     tmp5, tmp2
    pand     tmp5, tmp3
    psrld    $8, ctxc
    psrld    $8, ctxd
    psrld    $8, ctxe
    pslld    $8, tmp1
    pslld    $8, tmp2
    pslld    $8, tmp3
    por      tmp1, ctxc
    por      tmp2, ctxd
    por      tmp3, ctxe
    movdqa   ctxc, tmp1
    movdqa   ctxd, tmp2
    movdqa   ctxe, tmp3
    psrld    $16, ctxc
    psrld    $16, ctxd
    psrld    $16, ctxe
    pslld    $16, tmp1
    pslld    $16, tmp2
    pslld    $16, tmp3
    por      tmp1, ctxc
    por      tmp2, ctxd
    por      tmp3, ctxe

    movdqa   ctxc, 32(edx_rsi)
    movdqa   ctxd, 48(edx_rsi)
    movdqa   ctxe, 64(edx_rsi)

    ret

// arg 1 (eax) (64bit: rdi): context     (4*20 bytes)
// arg 2 (edx) (64bit: rsi): input data (4*64 bytes)
// arg 3 (ecx) (64bit: rdx): workspace  (1280 bytes)
sse2_sha1_update:

    movdqa    0(eax_rdi), ctxa
    movdqa   16(eax_rdi), ctxb
    movdqa   32(eax_rdi), ctxc
    movdqa   48(eax_rdi), ctxd
    movdqa   64(eax_rdi), ctxe

round0:

    prefetchnta (edx_rsi)

    subRoundX( ctxa, ctxb, ctxc, ctxd, ctxe, F0, _reloc(const_stage0),  0 );
    subRoundX( ctxe, ctxa, ctxb, ctxc, ctxd, F0, _reloc(const_stage0),  1 );
    subRoundX( ctxd, ctxe, ctxa, ctxb, ctxc, F0, _reloc(const_stage0),  2 );
    subRoundX( ctxc, ctxd, ctxe, ctxa, ctxb, F0, _reloc(const_stage0),  3 );
    subRoundX( ctxb, ctxc, ctxd, ctxe, ctxa, F0, _reloc(const_stage0),  4 );
    subRoundX( ctxa, ctxb, ctxc, ctxd, ctxe, F0, _reloc(const_stage0),  5 );
    subRoundX( ctxe, ctxa, ctxb, ctxc, ctxd, F0, _reloc(const_stage0),  6 );
    subRoundX( ctxd, ctxe, ctxa, ctxb, ctxc, F0, _reloc(const_stage0),  7 );
    subRoundX( ctxc, ctxd, ctxe, ctxa, ctxb, F0, _reloc(const_stage0),  8 );
    subRoundX( ctxb, ctxc, ctxd, ctxe, ctxa, F0, _reloc(const_stage0),  9 );
    subRoundX( ctxa, ctxb, ctxc, ctxd, ctxe, F0, _reloc(const_stage0), 10 );
    subRoundX( ctxe, ctxa, ctxb, ctxc, ctxd, F0, _reloc(const_stage0), 11 );
    subRoundX( ctxd, ctxe, ctxa, ctxb, ctxc, F0, _reloc(const_stage0), 12 );
    subRoundX( ctxc, ctxd, ctxe, ctxa, ctxb, F0, _reloc(const_stage0), 13 );
    subRoundX( ctxb, ctxc, ctxd, ctxe, ctxa, F0, _reloc(const_stage0), 14 );
    subRoundX( ctxa, ctxb, ctxc, ctxd, ctxe, F0, _reloc(const_stage0), 15 );
    subRoundY( ctxe, ctxa, ctxb, ctxc, ctxd, F0, _reloc(const_stage0), 16 );
    subRoundY( ctxd, ctxe, ctxa, ctxb, ctxc, F0, _reloc(const_stage0), 17 );
    subRoundY( ctxc, ctxd, ctxe, ctxa, ctxb, F0, _reloc(const_stage0), 18 );
    subRoundY( ctxb, ctxc, ctxd, ctxe, ctxa, F0, _reloc(const_stage0), 19 );

round1:

    subRoundY( ctxa, ctxb, ctxc, ctxd, ctxe, F1, _reloc(const_stage1), 20 );
    subRoundY( ctxe, ctxa, ctxb, ctxc, ctxd, F1, _reloc(const_stage1), 21 );
    subRoundY( ctxd, ctxe, ctxa, ctxb, ctxc, F1, _reloc(const_stage1), 22 );
    subRoundY( ctxc, ctxd, ctxe, ctxa, ctxb, F1, _reloc(const_stage1), 23 );
    subRoundY( ctxb, ctxc, ctxd, ctxe, ctxa, F1, _reloc(const_stage1), 24 );
    subRoundY( ctxa, ctxb, ctxc, ctxd, ctxe, F1, _reloc(const_stage1), 25 );
    subRoundY( ctxe, ctxa, ctxb, ctxc, ctxd, F1, _reloc(const_stage1), 26 );
    subRoundY( ctxd, ctxe, ctxa, ctxb, ctxc, F1, _reloc(const_stage1), 27 );
    subRoundY( ctxc, ctxd, ctxe, ctxa, ctxb, F1, _reloc(const_stage1), 28 );
    subRoundY( ctxb, ctxc, ctxd, ctxe, ctxa, F1, _reloc(const_stage1), 29 );
    subRoundY( ctxa, ctxb, ctxc, ctxd, ctxe, F1, _reloc(const_stage1), 30 );
    subRoundY( ctxe, ctxa, ctxb, ctxc, ctxd, F1, _reloc(const_stage1), 31 );
    subRoundY( ctxd, ctxe, ctxa, ctxb, ctxc, F1, _reloc(const_stage1), 32 );
    subRoundY( ctxc, ctxd, ctxe, ctxa, ctxb, F1, _reloc(const_stage1), 33 );
    subRoundY( ctxb, ctxc, ctxd, ctxe, ctxa, F1, _reloc(const_stage1), 34 );
    subRoundY( ctxa, ctxb, ctxc, ctxd, ctxe, F1, _reloc(const_stage1), 35 );
    subRoundY( ctxe, ctxa, ctxb, ctxc, ctxd, F1, _reloc(const_stage1), 36 );
    subRoundY( ctxd, ctxe, ctxa, ctxb, ctxc, F1, _reloc(const_stage1), 37 );
    subRoundY( ctxc, ctxd, ctxe, ctxa, ctxb, F1, _reloc(const_stage1), 38 );
    subRoundY( ctxb, ctxc, ctxd, ctxe, ctxa, F1, _reloc(const_stage1), 39 );

round2:

    subRoundY( ctxa, ctxb, ctxc, ctxd, ctxe, F2, _reloc(const_stage2), 40 );
    subRoundY( ctxe, ctxa, ctxb, ctxc, ctxd, F2, _reloc(const_stage2), 41 );
    subRoundY( ctxd, ctxe, ctxa, ctxb, ctxc, F2, _reloc(const_stage2), 42 );
    subRoundY( ctxc, ctxd, ctxe, ctxa, ctxb, F2, _reloc(const_stage2), 43 );
    subRoundY( ctxb, ctxc, ctxd, ctxe, ctxa, F2, _reloc(const_stage2), 44 );
    subRoundY( ctxa, ctxb, ctxc, ctxd, ctxe, F2, _reloc(const_stage2), 45 );
    subRoundY( ctxe, ctxa, ctxb, ctxc, ctxd, F2, _reloc(const_stage2), 46 );
    subRoundY( ctxd, ctxe, ctxa, ctxb, ctxc, F2, _reloc(const_stage2), 47 );
    subRoundY( ctxc, ctxd, ctxe, ctxa, ctxb, F2, _reloc(const_stage2), 48 );
    subRoundY( ctxb, ctxc, ctxd, ctxe, ctxa, F2, _reloc(const_stage2), 49 );
    subRoundY( ctxa, ctxb, ctxc, ctxd, ctxe, F2, _reloc(const_stage2), 50 );
    subRoundY( ctxe, ctxa, ctxb, ctxc, ctxd, F2, _reloc(const_stage2), 51 );
    subRoundY( ctxd, ctxe, ctxa, ctxb, ctxc, F2, _reloc(const_stage2), 52 );
    subRoundY( ctxc, ctxd, ctxe, ctxa, ctxb, F2, _reloc(const_stage2), 53 );
    subRoundY( ctxb, ctxc, ctxd, ctxe, ctxa, F2, _reloc(const_stage2), 54 );
    subRoundY( ctxa, ctxb, ctxc, ctxd, ctxe, F2, _reloc(const_stage2), 55 );
    subRoundY( ctxe, ctxa, ctxb, ctxc, ctxd, F2, _reloc(const_stage2), 56 );
    subRoundY( ctxd, ctxe, ctxa, ctxb, ctxc, F2, _reloc(const_stage2), 57 );
    subRoundY( ctxc, ctxd, ctxe, ctxa, ctxb, F2, _reloc(const_stage2), 58 );
    subRoundY( ctxb, ctxc, ctxd, ctxe, ctxa, F2, _reloc(const_stage2), 59 );

round3:

    subRoundY( ctxa, ctxb, ctxc, ctxd, ctxe, F1, _reloc(const_stage3), 60 );
    subRoundY( ctxe, ctxa, ctxb, ctxc, ctxd, F1, _reloc(const_stage3), 61 );
    subRoundY( ctxd, ctxe, ctxa, ctxb, ctxc, F1, _reloc(const_stage3), 62 );
    subRoundY( ctxc, ctxd, ctxe, ctxa, ctxb, F1, _reloc(const_stage3), 63 );
    subRoundY( ctxb, ctxc, ctxd, ctxe, ctxa, F1, _reloc(const_stage3), 64 );
    subRoundY( ctxa, ctxb, ctxc, ctxd, ctxe, F1, _reloc(const_stage3), 65 );
    subRoundY( ctxe, ctxa, ctxb, ctxc, ctxd, F1, _reloc(const_stage3), 66 );
    subRoundY( ctxd, ctxe, ctxa, ctxb, ctxc, F1, _reloc(const_stage3), 67 );
    subRoundY( ctxc, ctxd, ctxe, ctxa, ctxb, F1, _reloc(const_stage3), 68 );
    subRoundY( ctxb, ctxc, ctxd, ctxe, ctxa, F1, _reloc(const_stage3), 69 );
    subRoundY( ctxa, ctxb, ctxc, ctxd, ctxe, F1, _reloc(const_stage3), 70 );
    subRoundY( ctxe, ctxa, ctxb, ctxc, ctxd, F1, _reloc(const_stage3), 71 );
    subRoundY( ctxd, ctxe, ctxa, ctxb, ctxc, F1, _reloc(const_stage3), 72 );
    subRoundY( ctxc, ctxd, ctxe, ctxa, ctxb, F1, _reloc(const_stage3), 73 );
    subRoundY( ctxb, ctxc, ctxd, ctxe, ctxa, F1, _reloc(const_stage3), 74 );
    subRoundY( ctxa, ctxb, ctxc, ctxd, ctxe, F1, _reloc(const_stage3), 75 );
    subRoundY( ctxe, ctxa, ctxb, ctxc, ctxd, F1, _reloc(const_stage3), 76 );
    subRoundY( ctxd, ctxe, ctxa, ctxb, ctxc, F1, _reloc(const_stage3), 77 );
    subRoundY( ctxc, ctxd, ctxe, ctxa, ctxb, F1, _reloc(const_stage3), 78 );
    subRoundY( ctxb, ctxc, ctxd, ctxe, ctxa, F1, _reloc(const_stage3), 79 );

    paddd    0(eax_rdi), ctxa
    paddd   16(eax_rdi), ctxb
    paddd   32(eax_rdi), ctxc
    paddd   48(eax_rdi), ctxd
    paddd   64(eax_rdi), ctxe

    movdqa    ctxa,  0(eax_rdi)
    movdqa    ctxb, 16(eax_rdi)
    movdqa    ctxc, 32(eax_rdi)
    movdqa    ctxd, 48(eax_rdi)
    movdqa    ctxe, 64(eax_rdi)

    ret

// returns 1 if SSE2 is supported, 0 otherwise
detect_sse2:
#ifndef __x86_64__
    pushfl
    pushfl
    popl    %eax
    movl    %eax, %ecx
    xorl    $0x200000, %eax
    push    %eax
    popfl
    pushfl
    popl    %eax
    popfl
    xorl    %ecx, %eax
    jnz     do_cpuid
    ret
do_cpuid:
#endif
    push ebx_rbx
    push ecx_rcx
    push edx_rdx

    movl    $1, %eax
    cpuid
    testl   $(0x00800000 | 0x04000000), %edx  // bits 23 and 26 (MMX/SSE2)
    jz      no_sse2
    movl    $1, %eax
    jmp     cpuid_exit
no_sse2:
    xorl    %eax, %eax
cpuid_exit:
    
    pop edx_rdx
    pop ecx_rcx
    pop ebx_rbx

    ret

#endif // COMPILE_SSE2

