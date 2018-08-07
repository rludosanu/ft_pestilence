%define CHECKPROC_S
%include "pestilence.lst"

section .text
	global _checkproc

_opcode:
	dq 0x0000000000000000

;; -----------------------------------------------------------------------------------
;; NAME
;;		_checkproc
;;
;; SYNOPSIS
;;		int		_checkproc(char *procname)
;;
;; DESCRIPTION
;;		Sets up and launches the _readproc function.
;;
;; RETURN VALUE
;;		Returns the value of _readproc. See description above.
;; -----------------------------------------------------------------------------------
_checkproc:
	enter	0, 0

	mov r10, rdi
	;; Copy the base directory path under %rsp
	lea		rsi, [rel _dirname.string]
	mov		rdi, rsp
	sub		rdi, _dirname.len
	sub		rdi, 1
	mov		rcx, _dirname.len
	cld
	rep		movsb
	mov		byte [rdi], 0

	;; Move %rsp down by size of the path + 1
	sub		rsp, _dirname.len
	sub		rsp, 1
	mov		rax, 0
	push	rax

	;; Run readproc
	mov rdi, r10
	cmp rdi, 0
	jne .call
	lea rdi, [rel _procname.string]
	.call:
		call	_readproc
	mov		rcx, rax

	;; Restore %rsp
	pop		rax
	add		rsp, _dirname.len
	add		rsp, 1

	mov		rax, rcx
	leave
	ret

;; -----------------------------------------------------------------------------------
;; STRINGS
;; -----------------------------------------------------------------------------------

_dirname:
	.string db '/proc', 0
	.len equ $ - _dirname.string

_procfile:
	.string db 'comm', 0
	.len equ $ - _procfile.string

_procname:
	.string db 'ptdr', 10, 0
	.len equ $ - _procname.string

;; -----------------------------------------------------------------------------------
;; NAME
;;		_isproc
;;
;; SYNOPSIS
;;		int		_isproc(char *full_path, char *proc_name)
;;
;; DESCRIPTION
;;		Searches for _procname.string into /proc/<PID>/comm. Returns 1 if found, 0
;;		otherwise.
;;
;; STACK USAGE
;;		rsp			: full_path save
;;		rsp + 8		: proc_name save
;;		rsp + 16	: return value
;;		rsp + 24	: file fd
;;		rsp + 32	: string readed from file
;; -----------------------------------------------------------------------------------
_isproc:
	enter 40, 0
; We allocate our stack according to our _procname_len
	sub rsp, _procname.len
	push rsi
	push rdi
	mov QWORD [rsp + 16], 0

; Open file
	mov rax, SYS_OPEN
	mov rsi, O_RDONLY
	mov rdx, 0
	syscall
	cmp rax, 0
	jle _ret_is_proc
	mov QWORD [rsp + 24], rax

	mov rdi, QWORD [rsp + 8]
	call _ft_strlen
	mov QWORD [rsp], rax
	inc QWORD [rsp]
	JUNK 5

; Read the proname size on file
	mov rax, SYS_READ
	mov rdi, QWORD [rsp + 24]
	mov rsi, rsp
	add rsi, 32
	mov rdx, QWORD [rsp]
	syscall
	mov rdi, rsp
	add rdi, 32
	add rdi, QWORD [rsp]
	sub rdi, 1
	mov BYTE [rdi], 0

; Close file
	mov rax, SYS_CLOSE
	mov rdi, QWORD [rsp + 24]
	syscall

; Compare strings
	mov rdi, rsp
	add rdi, 32
	mov rsi, QWORD [rsp + 8]
	call _ft_strequ
	cmp rax, 0
	je _ret_is_proc

_proc_ok:
	mov QWORD [rsp + 16], 1

_ret_is_proc:
	mov rax, QWORD [rsp + 16]
	pop rdi
	leave
	ret

;; -----------------------------------------------------------------------------------
;; NAME
;;		_readproc
;;
;; SYNOPSIS
;;		int		_readproc(char *procname)
;;
;; DESCRIPTION
;;		Opens the directory /proc and browses it recursively looking for
;;		/proc/<PID>/comm file. When found it then calls _isproc to see if the
;;		_procname string is found in it.
;;
;; RETURN VALUE
;;		Returns 1 if _procname is found, 0 otherwise.
;;
;; NOTES
;;		It writes the full path of the file/directory under %rsp, moves %rsp down
;;		by its size before call to _readproc or _isproc and restores it afterwards.
;;		This way the stack offsets are preserved and the path is not overwritten
;;		by the stack frame of the next function call.
;;
;;		;----------------------------; < %rbp
;;		;     actual stack frame     ;
;;		;----------------------------; < %rsp (base)
;;		;  full file/directory path  ;
;;		;----------------------------;
;;		;        size of path        ;
;;		;----------------------------; < %rsp (temporary)
;;		;     next function call     ;
;;		;----------------------------;
;;
;;		The idea here is for the next function to read the path at %rbp + 24.
;;
;; STACK USAGE
;;		rsp + 0		: directory fd
;;		rsp + 8		: buffer
;;		rsp + 288	: base path len
;;		rsp + 296	: directory name len
;;		rsp + 304	: full path len
;;		rsp + 312	: buffer head
;;		rsp + 320	: buffer tail
;;		rsp + 328	: return value
;;		rsp + 336	: save proc_name
;; -----------------------------------------------------------------------------------
_readproc:
	enter	352, 0
	mov QWORD [rsp + 336], rdi

_readproc_open:
	;; Set up default return value
	mov		qword [rsp + 328], 0

	;; Open base directory
	mov		rax, SYS_OPEN
	lea		rdi, [rbp + 24]
	mov		rsi, 0
	mov		rdx, 0
	syscall
	cmp		rax, -1
	jle		_readproc_end
	mov		qword [rsp], rax
	
	;; Save up base path len
	lea		rdi, [rbp + 24]
	call	_ft_strlen
	mov		qword [rsp + 288], rax
	JUNK 5

_readproc_loop:
	;; Get directory content
	mov		rax, SYS_GETDENTS64
	mov		rdi, qword [rsp]
	lea		rsi, [rsp + 8]
	mov		rdx, 280
	syscall
	cmp		rax, 0
	jle		_readproc_close

	;; Buffer head
	lea		r10, [rsp + 8]
	mov		qword [rsp + 312], r10

	;; Buffer tail
	lea		r10, [r10 + rax]
	mov		qword [rsp + 320], r10

_readproc_loop_file:
	;; Check if we reached the last dirent64 in the buffer
	mov		r10, qword [rsp + 312]
	cmp		r10, qword [rsp + 320]
	jge		_readproc_loop
	
	;; If file/directory is '.' or '..' move on to next dirent64
	lea		rdi, [r10 + 19]
	cmp		word [rdi], 0x002e
	je		_readproc_next_file
	cmp		word [rdi], 0x2e2e
	je		_readproc_next_file
	
	;; If file/directory is not just numbers, move on to next dirent64
	call	_ft_is_integer_string
	cmp 	rax, 0
	je 		_readproc_next_file

	;; If it's not a directory 
	xor r8, r8
	mov		r8b, byte [r10 + 18]
	cmp		r8b, DT_DIR
	jne		_readproc_next_file

	;; Save file/directory len
	lea		rdi, [r10 + 19]
	call	_ft_strlen
	mov		qword [rsp + 296], rax

	;; Write full path under %rsp (base path + '/' + directory name + '/comm' + '\0')
	xor		r8, r8
	mov		r8, 2
	add		r8, qword [rsp + 288]
	add		r8, qword [rsp + 296]
	add 	r8, _procfile.len
	mov		qword [rsp + 304], r8

	;; Move under %rsp to write full path
	mov		rdi, rsp
	sub		rdi, qword [rsp + 304]

	;; Write base path
	lea		rsi, [rbp + 24]
	mov		rcx, qword [rsp + 288]
	cld
	rep		movsb

	;; Write '/'
	mov		byte [rdi], 0x2f
	add		rdi, 1

	;; Write directory/file name
	lea		rsi, [r10 + 19]
	mov		rcx, qword [rsp + 296]
	cld
	rep		movsb
	
	;; Write '/'
	mov		byte [rdi], 0x2f
	add		rdi, 1

	;; Write comm \0
	lea		rsi, [rel _procfile.string]
	mov		rcx, _procfile.len
	cld
	rep 	movsb
	jmp		_readproc_proc_file

	;; Move on to the next dirent64
	jmp		_readproc_next_file

_readproc_proc_file:
	JUNK 5
	mov rsi, QWORD [rsp + 336]

	;; Move down %rsp by file path len
	mov		rax, qword [rsp + 304]
	sub		rsp, rax
	mov rdi, rsp 
	push	rax

;	lea rsi, [rel _procname.string]
	call	_isproc
	mov		rcx, rax
	
	jmp		_readproc_reset_stack

_readproc_reset_stack:
	;; Restore %rsp at position before _readproc/_isproc call
	pop		rax
	add		rsp, rax

	;; If string was not found in file move on to the next dirent64
	mov		qword [rsp + 328], rcx
	JUNK 5
	cmp		qword [rsp + 328], 0
	je		_readproc_next_file

	;; Otherwise return
	jmp		_readproc_close

_readproc_next_file:
	;; Move in buffer by dirent64->d_reclen
	xor		rcx, rcx
	mov		r10, qword [rsp + 312]
	mov		cx, word [r10 + 16]
	lea		r10, [r10 + rcx]
	mov		qword [rsp + 312], r10

	jmp		_readproc_loop_file

_readproc_close:
	;; Close directory fd
	mov		rax, 3
	mov		rdi, qword [rsp]
	syscall

_readproc_end:
	;; Set up return value, destroy stack frame and return
	JUNK 5
	mov		rax, qword [rsp + 328]
	leave
	ret

%undef CHECKPROC_S
