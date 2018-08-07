%define CHECKDBG_BY_STATUS_S
%include "pestilence.lst"

section .text
	global _checkdbg_by_status_file

_opcode:
	dq 0x0606060606060606

;; -----------------------------------------------------------------------------------
;; NAME
;;		_checkdbg_by_status_file
;;
;; SYNOPSIS
;;		int		_checkdbg_by_status_file(void)
;;
;; DESCRIPTION
;;		Checks whether a tracing session exists for this process. If a session is
;;		found, this function returns 1, 0 otherwise
;;
;; STACK_USAGE:
;;		rsp + 0: pid
;;		rsp + 8: fd
;;		rsp + 16: TracerPid
;;		rsp + 24: pointer to tracerpid str in our file
;;		rsp + 32: return value
;;		rsp + 40: buff of 32 bytes for our concatenated str -> /proc/<pid>/status
;;		rsp + 72: buff of 256 bytes for read from our file
;; -----------------------------------------------------------------------------------
_checkdbg_by_status_file:
	enter 352, 0
	
	; GetPid
	mov rax, SYS_GETPID
	syscall
	mov QWORD [rsp], rax

_create_string_path:
	; Mov /pro on stack
	lea rdi, [rsp + 40]
	lea rsi, [rel _proc.string]
	mov rcx, _proc.len
	cld
	rep movsb

	; add / at the end 
	mov BYTE [rdi], '/'
	inc rdi

	; mov our pid converted to string after our /
	mov rsi, rdi
	mov rdi, QWORD [rsp]
	mov QWORD [rsi], 0
	push rsi
_call_ft_itoa:
	call _ft_itoa
	pop rdi
	
	; go to the end of the string
	.go_to_zero cmp BYTE [rdi], 0
	je .finish_string_path
	inc rdi
	jmp .go_to_zero

	; put /
	.finish_string_path mov BYTE [rdi], '/'
	inc rdi

	; put status
	lea rsi, [rel _status.string]
	mov rcx, _status.len
	cld
	rep movsb

	; put \0
	mov BYTE [rdi], 0

_open_path:
	JUNK 5
	mov QWORD [rsp + 32], 1
	mov rax, SYS_OPEN
	lea rdi, [rsp + 40]
	mov rsi, O_RDONLY
	xor rdx, rdx
	syscall
	cmp rax, 0
	jl _exit
	mov QWORD [rsp + 8], rax

_read_from_file:
	; bzero buff
	.init lea rdi, [rsp + 72]
	mov rcx, 257
	rep stosb

	; read(fd, rsp + 72, 256);
	.read mov rax, SYS_READ
	mov rdi, QWORD [rsp + 8]
	lea rsi, [rsp + 72]
	mov rdx, 256
	syscall

_find_str_on_buff:
	; Just call _ft_strstr
	lea rdi, [rsp + 72]
	lea rsi, [rel _tracer_str.string]
	call _ft_strstr
	mov QWORD [rsp + 24], rax
	mov rdi, QWORD [rsp + 24]
	add rdi, _tracer_str.len
;	lea r10, [rel _ft_atoi]
;	add r10, 1
;	call r10
	call _ft_atoi+1
	mov QWORD [rsp + 16], rax
	JUNK 5
	cmp QWORD [rsp + 16], 0
	jne _close
	mov QWORD [rsp + 32], 0

_close:
	mov rax, SYS_CLOSE
	mov rdi, QWORD [rsp + 8]
	syscall

_exit:
	mov rax, QWORD [rsp + 32]
	leave
	ret

_tracer_str:
	.string db 'TracerPid:', 0
	.len equ $ - _tracer_str.string

_proc:
	.string db '/proc'
	.len equ $ - _proc.string

_status:
	.string db 'status'
	.len equ $ - _status.string

%undef CHECKDBG_BY_STATUS_S
