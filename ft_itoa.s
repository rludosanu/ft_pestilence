%define FT_ITOA_S
%include "pestilence.lst"

section .text
	global _ft_itoa

_opcode:
	dq 0x0505050505050505

;; -----------------------------------------------------------------------------------
;; int		_ft_itoa(int nb, char *addr)
;; -----------------------------------------------------------------------------------
_ft_itoa:
	enter 40, 0
	cmp rsi, 0
	je _exit
	mov QWORD [rsp], rdi
	mov QWORD [rsp + 8], rsi
	
_check_nb:
	cmp rdi, 10
	jl _concatene_character
	mov rcx, 10
	mov rax, QWORD [rsp]
	xor rdx, rdx
	div rcx
	mov QWORD [rsp + 16], rax
	mov QWORD [rsp + 24], rdx
	mov rdi, QWORD [rsp + 16]
	mov rsi, QWORD [rsp + 8]
	call _ft_itoa
	mov QWORD [rsp + 8], rax
	mov rdi, QWORD [rsp + 24]
	mov rsi, QWORD [rsp + 8]
	call _ft_itoa
	mov QWORD [rsp + 8], rax
	jmp _exit

_concatene_character:
	JUNK 5
	mov rdi, QWORD [rsp + 8]
	lea rsi, [rel _characters]
	mov r11, QWORD [rsp]
	xor r10, r10
	mov r10b, BYTE [rsi + r11]
	mov BYTE [rdi], r10b
	inc QWORD [rsp + 8]

_exit:
	mov rax, QWORD [rsp + 8]
	leave
	ret

_characters:
	db '0123456789'

%undef FT_ITOA_S
