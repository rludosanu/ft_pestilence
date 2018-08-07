%define FT_IS_INTEGER_STRING_S
%include "pestilence.lst"

section .text
	global _ft_is_integer_string

_opcode:
	dq 0x0909090909090909

_ft_is_integer_string:
	enter 32, 0
	push rdi
	xor rcx, rcx

_loop_cmp:
	.loop cmp BYTE [rdi + rcx], 0
	je _ok_ret
	cmp BYTE [rdi + rcx], '0'
	jl _not_ok_ret
	cmp BYTE [rdi + rcx], '9'
	jg _not_ok_ret
	inc rcx
	jmp _loop_cmp.loop
	JUNK 5

_not_ok_ret:
	mov rax, 0
	jmp _ret

_ok_ret:
	mov rax, 1

_ret:
	pop rdi
	leave
	ret

%undef FT_IS_INTEGER_STRING_S
