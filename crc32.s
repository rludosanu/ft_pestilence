%define CRC32_S
%include "pestilence.lst"

section .text
	global	_crc32

_opcode:
	dq 0x0303030303030303

;; -----------------------------------------------------------------------------------
;; NAME
;;		_crc32
;;
;; SYNOPSIS
;;		int		_crc32(void *mem, size_t len)
;;
;; DESCRIPTION
;;		CRC-32 algorithm implementation.
;;		http://www.hackersdelight.org/hdcodetxt/crc.c.txt - crc32b C implementation.
;;
;; STACK USAGE
;;		rsp			: crc
;;		rsp + 4		: mask
;; -----------------------------------------------------------------------------------

_crc32:
	enter	8, 0

	mov		dword [rsp], 0xffffffff		; crc
	mov		dword [rsp + 0x4], 0x0		; mask

_crc32_getbyte:
	;; if (len == 0) return (~crc)
	cmp		rsi, 0x0
	je		_crc32_end

	;; crc = crc ^ byte
	mov		al, byte [rdi]
	movzx	eax, al
	mov		edx, dword [rsp]
	xor		edx, eax
	mov		dword [rsp], edx

	;; j = 8
	mov		rcx, 0x8

;; while (j > 0)
_crc32_loopbyte:
	cmp		rcx, 0x0
	je		_crc32_nextbyte

	;; mask = -(crc & 1)
	mov		eax, dword [rsp]
	and		eax, 0x1
	neg		eax
	mov		dword [rsp + 0x4], eax

	;; crc = (crc >> 1) ^ (0xEDB88320 & mask)
	mov		edx, dword [rsp]
	shr		edx, 0x1
	mov		eax, 0xEDB88320
	and		eax, dword [rsp + 0x4]
	xor		edx, eax
	mov		dword [rsp], edx

	;; j -= 1
	dec		rcx
	jmp		_crc32_loopbyte

_crc32_nextbyte:
	;; ptr += 1
	dec		rsi
	inc		rdi
	jmp		_crc32_getbyte

_crc32_end:
	JUNK 5
	mov		eax, dword [rsp]
	xor		eax, 0xffffffff
	movsx	rax, eax

	leave
	ret

%undef CRC32_S
