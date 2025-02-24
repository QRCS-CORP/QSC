; ================================================================
; MASM version of basemul_avx using AVX2 instructions
; Compatible with a Visual Studio C project.
;
; NOTE:
;   • This file assumes a 64‐bit build.
;   • Ensure your project settings enable AVX2.
; ================================================================

;-------------------------------------------------
; Constant definitions (from the original #defines)
;-------------------------------------------------
_16XQ           EQU 0
_16XQINV        EQU 16
_16XV           EQU 32
_16XFLO         EQU 48
_16XFHI         EQU 64
_16XMONTSQLO    EQU 80
_16XMONTSQHI    EQU 96
_16XMASK        EQU 112
_REVIDXB        EQU 128
_REVIDXD        EQU 144
_ZETAS_EXP      EQU 160
_16XSHIFT       EQU 624

;-------------------------------------------------
; Macro: schoolbook
; Parameter: off (an immediate constant such as 0,1,2,3)
;
; For each memory operand we precompute the displacement.
; The original expressions like (64*off+16)*2 become:
;      64*off*2 + 16*2 = 128*off + 32
; Thus, we write addresses in the form:
;      [rsi + 128*off + constant]
; which MASM accepts.
;-------------------------------------------------
schoolbook MACRO off
    ; Load constant vector from RCX.
    vmovdqa ymm0, [rcx + _16XQINV*2]      ; _16XQINV*2 = 16*2 = 32

    ; Load a0, b0, a1, b1 from RSI.
    vmovdqa ymm1, [rsi + 128*off]          ; (64*off+0)*2 = 128*off + 0
    vmovdqa ymm2, [rsi + 128*off + 32]       ; (64*off+16)*2 = 128*off + 32
    vmovdqa ymm3, [rsi + 128*off + 64]       ; (64*off+32)*2 = 128*off + 64
    vmovdqa ymm4, [rsi + 128*off + 96]       ; (64*off+48)*2 = 128*off + 96

    ; Multiply low words.
    vpmullw ymm9,  ymm0, ymm1              ; a0.lo
    vpmullw ymm10, ymm0, ymm2              ; b0.lo
    vpmullw ymm11, ymm0, ymm3              ; a1.lo
    vpmullw ymm12, ymm0, ymm4              ; b1.lo

    ; Load c0 and d0 from RDX.
    vmovdqa ymm5, [rdx + 128*off]          ; (64*off+0)*2
    vmovdqa ymm6, [rdx + 128*off + 32]       ; (64*off+16)*2

    ; Multiply high words (first pair).
    vpmulhw ymm13, ymm5, ymm1              ; a0c0.hi
    vpmulhw ymm1,  ymm6, ymm1              ; a0d0.hi  (overwrite ymm1)
    vpmulhw ymm14, ymm5, ymm2              ; b0c0.hi
    vpmulhw ymm2,  ymm6, ymm2              ; b0d0.hi  (overwrite ymm2)

    ; Load c1 and d1 from RDX.
    vmovdqa ymm7, [rdx + 128*off + 64]       ; (64*off+32)*2
    vmovdqa ymm8, [rdx + 128*off + 96]       ; (64*off+48)*2

    ; Multiply high words (second pair).
    vpmulhw ymm15, ymm7, ymm3              ; a1c1.hi
    vpmulhw ymm3,  ymm8, ymm3              ; a1d1.hi  (overwrite ymm3)
    vpmulhw ymm0,  ymm7, ymm4              ; b1c1.hi
    vpmulhw ymm4,  ymm8, ymm4              ; b1d1.hi  (overwrite ymm4)

    ; Save original a0c0.hi (in ymm13) to the stack.
    vmovdqa [rsp], ymm13

    ; Multiply low words.
    vpmullw ymm13, ymm5, ymm9              ; a0c0.lo
    vpmullw ymm9,  ymm6, ymm9              ; a0d0.lo
    vpmullw ymm5,  ymm5, ymm10             ; b0c0.lo
    vpmullw ymm10, ymm6, ymm10             ; b0d0.lo

    vpmullw ymm6,  ymm7, ymm11             ; a1c1.lo
    vpmullw ymm11, ymm8, ymm11             ; a1d1.lo
    vpmullw ymm7,  ymm7, ymm12             ; b1c1.lo
    vpmullw ymm12, ymm8, ymm12             ; b1d1.lo

    ; Reload constant vector from RCX.
    vmovdqa ymm8, [rcx + _16XQ*2]          ; _16XQ*2 = 0*2 = 0

    ; Multiply high parts by constant.
    vpmulhw ymm13, ymm8, ymm13
    vpmulhw ymm9,  ymm8, ymm9
    vpmulhw ymm5,  ymm8, ymm5
    vpmulhw ymm10, ymm8, ymm10
    vpmulhw ymm6,  ymm8, ymm6
    vpmulhw ymm11, ymm8, ymm11
    vpmulhw ymm7,  ymm8, ymm7
    vpmulhw ymm12, ymm8, ymm12

    ; Subtract saved values.
    vpsubw  ymm13, ymm13, [rsp]           ; -a0c0
    vpsubw  ymm9,  ymm1,  ymm9            ; a0d0
    vpsubw  ymm5,  ymm14, ymm5            ; b0c0
    vpsubw  ymm10, ymm2,  ymm10           ; b0d0

    vpsubw  ymm6,  ymm15, ymm6            ; a1c1
    vpsubw  ymm11, ymm3,  ymm11           ; a1d1
    vpsubw  ymm7,  ymm0,  ymm7            ; b1c1
    vpsubw  ymm12, ymm4,  ymm12           ; b1d1

    ; Process extra terms from memory at R9.
    vmovdqa ymm0, [r9]
    vmovdqa ymm1, [r9 + 32]
    vpmullw ymm2, ymm0, ymm10
    vpmullw ymm3, ymm0, ymm12
    vpmulhw ymm10, ymm1, ymm10
    vpmulhw ymm12, ymm1, ymm12
    vpmulhw ymm2,  ymm8, ymm2
    vpmulhw ymm3,  ymm8, ymm3
    vpsubw  ymm10, ymm10, ymm2           ; rb0d0
    vpsubw  ymm12, ymm12, ymm3           ; rb1d1

    ; Final combine operations.
    vpaddw  ymm9,  ymm9, ymm5
    vpaddw  ymm11, ymm11, ymm7
    vpsubw  ymm13, ymm10, ymm13
    vpsubw  ymm6,  ymm6, ymm12

    ; Write results back to memory pointed to by RDI.
    vmovdqa [rdi + 128*off],       ymm13
    vmovdqa [rdi + 128*off + 32],    ymm9
    vmovdqa [rdi + 128*off + 64],    ymm6
    vmovdqa [rdi + 128*off + 96],    ymm11
ENDM

;-------------------------------------------------
; Procedure: basemul_avx
; Exports the symbol "basemul_avx" (using the C calling convention).
;-------------------------------------------------
.code
public basemul_avx
basemul_avx PROC
    ; Save original stack pointer and align the stack.
    mov    r8, rsp
    and    rsp, -32
    sub    rsp, 32

    ; Compute pointer for extra constants:
    ; R9 = RCX + ((_ZETAS_EXP + 176)*2)
    lea    r9, [rcx + (_ZETAS_EXP + 176)*2]

    ; Call the schoolbook macro for four blocks.
    schoolbook 0

    add    r9, 64            ; 32*2 = 64 bytes
    schoolbook 1

    add    r9, 384           ; 192*2 = 384 bytes
    schoolbook 2

    add    r9, 64            ; 32*2 = 64 bytes
    schoolbook 3

    ; Restore stack and return.
    mov    rsp, r8
    ret
basemul_avx ENDP

END
