%define FT_ATOI_S
%include "pestilence.lst"

section .text
	global _ft_atoi

_opcode:
	dq 0x0404040404040404

_ft_atoi:
	db 0xc5
	enter 32, 0

	xor rcx, rcx
	.loop cmp BYTE [rdi], 32
	jg .take_len
	inc rdi
	jmp .loop
	.take_len push rdi
	call _number_len_in_str
	push rax
	JUNK 5

_loop_convert:
	.init mov rcx, QWORD [rsp]
	dec rcx
	mov QWORD [rsp + 16], 0
	mov QWORD [rsp + 24], 1
	.loop cmp rcx, 0
	jl _ret_value
_bp2:
	mov rsi, QWORD [rsp + 8]
	xor rax, rax
	mov al, BYTE [rsi + rcx]
	sub al, '0'
	mov rdi, QWORD [rsp + 24]
	mul rdi
	add QWORD [rsp + 16], rax
	mov rax, QWORD [rsp + 24]
	mov rdi, 10
	mul rdi
	mov QWORD [rsp + 24], rax
	dec rcx
	jmp _loop_convert.loop

_ret_value:
	mov rax, QWORD [rsp + 16]
	leave
	ret

_number_len_in_str:
	enter 24, 0
	mov QWORD [rsp], 0
	.loop cmp BYTE [rdi], '0'
	jl _ret_num_len
	cmp BYTE [rdi], '9'
	jg _ret_num_len
	inc QWORD [rsp]
	inc rdi
	jmp .loop

_ret_num_len:
	mov rax, QWORD [rsp]
	leave
	ret

%undef FT_ATOI_S
