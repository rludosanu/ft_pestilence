%define FT_STRLEN_S
%include "pestilence.lst"

section .text
	global	_ft_strlen

_opcode:
	dq 0x0808080808080808

_ft_strlen:
	enter	0, 0
	push	rdi
	JUNK 5
	xor		rax, rax
	xor		rcx, rcx
	cmp		rdi, 0
	je		_ft_strlen_end

_ft_strlen_loop:
	mov		rdi, QWORD [rsp]
	cmp		byte [rdi], 0
	je		_ft_strlen_end
	inc		rcx
	inc		QWORD [rsp]
	jmp		_ft_strlen_loop

_ft_strlen_end:
	mov		rax, rcx
	pop		rdi
	leave
	ret

%undef FT_STRLEN_S
