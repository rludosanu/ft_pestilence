%define FT_STRSTR_S
%include "pestilence.lst"

section .text
	global	_ft_strstr
	global	_ft_strxequ

_opcode:
	dq 0x0707070707070707

;; -----------------------------------------------------------------------------------
;; int		_ft_strstr(const char *haystack, const char *needle)
;; -----------------------------------------------------------------------------------
_ft_strstr:
	enter	8, 0
	push	rdi
	push	rsi
	
	xor		rax, rax

_ft_strstr_loop:
	cmp		byte [rdi], 0
	je		_ft_strstr_end

	call	_ft_strxequ
	mov QWORD [rsp], rdi
	cmp		rax, 1
	je		_ft_strstr_end
	
	inc		rdi
	jmp		_ft_strstr_loop

_ft_strstr_end:
	JUNK 5
	mov rax, QWORD [rsp]
	pop		rsi
	pop		rdi
	leave
	ret

;; -----------------------------------------------------------------------------------
;; int		_ft_strxequ(const char *s1, const char *s2)
;; -----------------------------------------------------------------------------------
_ft_strxequ:
	enter	0, 0
	push	rdi
	push	rsi

	xor		rax, rax
	mov		rax, 1

_ft_strxequ_loop:
	cmp		byte [rdi], 0
	je		_ft_strxequ_end

	cmp		byte [rsi], 0
	je		_ft_strxequ_end

	mov		cl, byte [rdi]
	cmp		cl, byte [rsi]
	jne		_ft_strxequ_error

	inc		rdi
	inc		rsi
	jmp		_ft_strxequ_loop

_ft_strxequ_error:
	mov		rax, 0

_ft_strxequ_end:
	JUNK 5
	pop		rsi
	pop		rdi
	leave
	ret

%undef FT_STRSTR_S
