%define FT_STREQU_S
%include "pestilence.lst"

section	.text
	global	_ft_strequ

_opcode:
	dq 0x0202020202020202

_ft_strequ:
	enter	0, 0
	push	rdi
	push	rsi
	push	r10

	JUNK 5
    mov     rdi, QWORD [rsp + 16]
    mov     rsi, QWORD [rsp + 8]
    mov     r10, QWORD [rsp]
	xor		rax, rax
	mov		rax, 1

_ft_strequ_loop:
	mov		r10b, byte [rdi]
	cmp		r10b, byte [rsi]
	jne		_ft_strequ_error

	cmp		byte [rdi], 0
	je		_ft_strequ_end
	
	inc		rdi
	inc		rsi
	jmp		_ft_strequ_loop

_ft_strequ_error:
	xor		rax, rax

_ft_strequ_end:
	pop		r10
	pop		rsi
	pop		rdi
	leave
	ret

%undef FT_STREQU_S
