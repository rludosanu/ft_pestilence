%define JUMP_TO_FUNCTION_S
%include "pestilence.lst"

section .text
	global _jump_to_function
	global _functions_offset_from_start

_functions_offset_from_start:
	dq 0x0000000000000000 ; _checkproctest;
	dq 0x0000000000000000 ; _checkdbg;
	dq 0x0000000000000000 ; _crc32;
	dq 0x0000000000000000 ; _checkdbg_by_status_file;

_jump_to_function:
	enter 16, 0
	.init:
	mov QWORD [rsp], 0
	mov QWORD [rsp + 8], 0
	.loop:
		cmp QWORD [rsp], 4
		jge _check_sub_functions_jump ; if we reach the end of the table, we are probably checking for sub functions
		lea r14, [rel _start]
		lea r15, [rel _functions_offset_from_start]
		add r15, QWORD [rsp + 8]
		add r14, QWORD [r15]
		cmp QWORD [r14 - 8], r12
		je _call_specified_function
		inc QWORD [rsp]
		add QWORD [rsp + 8], 8
		jmp _jump_to_function.loop

_call_specified_function:
	call r14
	leave
	ret

_check_sub_functions_jump:
	.init:
	mov QWORD [rsp], 0
	mov QWORD [rsp + 8], 0
	.loop:
		cmp QWORD [rsp], 4
		jge _failed_call
		lea r14, [rel _start]
		lea r15, [rel _functions_offset_from_start]
		add r15, QWORD [rsp + 8]
		add r14, QWORD [r15]
		lea r13, [rel _ft_strlen]
		lea r11, [rel _checkproc]
		sub r13, r11
		add r14, r13
		cmp QWORD [r14 - 8], r12
		je _call_specified_function
		inc QWORD [rsp]
		add QWORD [rsp + 8], 8
		jmp .loop

_failed_call:
	mov rax, -1
	leave
	ret

%undef JUMP_TO_FUNCTION_S
