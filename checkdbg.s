%define CHECKDBG_S
%include "pestilence.lst"

section	.text
	global	_checkdbg

_opcode:
	dq 0x0101010101010101

;; -----------------------------------------------------------------------------------
;; NAME
;;		_checkdbg
;;
;; SYNOPSIS
;;		int		_checkdbg(void)
;;
;; DESCRIPTION
;;		Checks whether a tracing session exists for this process. If a session is
;;		found, this function returns 1, 0 otherwise.
;; -----------------------------------------------------------------------------------
_checkdbg:
	;; Save up registers
	enter	16, 0

	;; Calling ptrace(PTRACE_TRACEME)
	mov		rax, SYS_PTRACE
	mov		rdi, PTRACE_TRACEME
	mov		rsi, 0
	mov		rdx, 0
	mov		r10, 0
	syscall

	;; On error, a tracing session is already ongoing
	cmp		rax, -1
	je		_checkdbg_false
	jmp		_checkdbg_true

_checkdbg_true:
	mov		rax, 0
	jmp		_checkdbg_end

_checkdbg_false:
	mov		rax, 1
	jmp		_checkdbg_end

_checkdbg_end:
	;; Restore registers
	leave
	ret

%undef CHECKDBG_S
