;; For more details about this algorithm: it's an RC8 algorithme with a base key of 256 bytes
%define ENCRYPT_S
%include "pestilence.lst"

section .text
	global _encrypt_zone
	
_u_random:
	.string db '/dev/urandom', 0

_get_random_key:
	enter 40, 0

	mov QWORD [rsp], 0
	mov rax, SYS_OPEN
	lea rdi, [rel _u_random.string]
	mov rsi, O_RDONLY
	syscall
; Here we don't check for now if the open worked, we just store fd on stack
	mov QWORD [rsp + 8], rax

_mmap_key:
	mov rax, SYS_MMAP
	mov rdi, 0
	mov rsi, 256
	mov rdx, PROT_READ | PROT_WRITE
	mov r10, MAP_ANONYMOUS | MAP_PRIVATE
	mov r8, -1
	mov r9, 0
	syscall
	test rax, rax
	jz _close_file
; Now we know if we have our mmap, and our fd opened
	mov QWORD [rsp + 16], rax
; If our fd is valid, we get our key on /dev/urandom. Else, we get it with timestamp
	cmp QWORD [rsp + 8], 0
	jle _random_key_from_stack

_loop_read:
	cmp QWORD [rsp], 256
	jge _close_file
	mov rax, SYS_READ
	mov rdi, QWORD [rsp + 8]
	mov rsi, QWORD [rsp + 16]
	add rsi, QWORD [rsp]
	mov rdx, 256
	sub rdx, QWORD [rsp]
	syscall
	mov rdi, QWORD [rsp + 16]
	mov r12, 0x0808080808080808
	call _jump_to_function
;	call _ft_strlen
	mov QWORD [rsp], rax
	jmp _loop_read

_random_key_from_stack:
	.init xor rcx, rcx
	mov rdi, QWORD [rsp + 16]
	.loop cmp rcx, 256
	jge _ret_random_key
	rdtsc
	mov r10, 256
	xor rdx, rdx
	div r10
	mov BYTE [rdi + rcx], dl
	inc rcx
	jmp .loop	
	
_close_file:
	mov rax, SYS_CLOSE
	mov rdi, QWORD [rsp + 8]
	syscall

_ret_random_key:
	mov rax, QWORD [rsp + 16]
	leave
	ret

_encrypt_zone: ; char *encrypt_zone((void*)zone rdi, (int)zone_size rsi, (void*)new_zone rdx, (void*)key r10)
	enter 1072, 0

	mov QWORD [rsp + 0x428], rdx ; zone
	mov QWORD [rsp + 0x418], rdi ; zone
	mov QWORD [rsp + 0x420], rsi ; zone size
;	syscall
	mov QWORD [rsp + 0x400], r10 ; key
	cmp QWORD [rsp + 0x400], 0
	jne _create_table
	call _get_random_key
	mov QWORD [rsp + 0x400], rax

_create_table:
	.init mov rcx, 0
	mov QWORD [rsp + 0x408], 0

	.loop cmp rcx, 0x100
	jge _sort_table.init
	mov rdi, QWORD [rsp + 0x408]
	mov DWORD [rsp + rdi], ecx
	add QWORD [rsp + 0x408], 4
	inc rcx
	jmp .loop

_sort_table:
	.init mov QWORD [rsp + 0x408], 0
	mov QWORD [rsp + 0x410], 0
	xor rcx, rcx

	.loop cmp rcx, 0x100
	jge _encrypt_loop.init
	xor r12, r12
	mov r12, 4
	mov rax, rcx
	mul r12

; j += tab[i]
	xor rsi, rsi
	mov esi, DWORD [rsp + rax]
	add QWORD [rsp + 0x408], rsi

; j += key[i]
	mov rsi, QWORD [rsp + 0x400]
	xor rdi, rdi
	mov dil, BYTE [rsi + rcx]
	add QWORD [rsp + 0x408], rdi

;j = j % 256
	and QWORD [rsp + 0x408], 255

	lea rdi, [rel rsp + rax]
	mov rax, QWORD [rsp + 0x408]
	mov r12, 4
	mul r12
	lea rsi, [rel rsp + rax]
	lea r10, [rel _sort_table.continue]
	push r10
	jmp _swap
	.continue inc rcx
	jmp _sort_table.loop

_swap:
; a = a + b
	xor r10, r10
	mov r10d, DWORD [rsi]
	add DWORD [rdi], r10d

; b = a + b
	mov r10d, DWORD [rsi]
	xor r11, r11
	mov r11d, DWORD [rdi]
	mov DWORD [rsi], r11d
	sub DWORD [rsi], r10d

; a = a - b
	mov r10d, DWORD [rsi]
	sub DWORD [rdi], r10d
_swap_end:
	pop r10
	jmp r10
	
_encrypt_loop:
	.init xor rcx, rcx
	mov QWORD [rsp + 0x408] , 0 ; i
	mov QWORD [rsp + 0x410] , 0 ; j

	.loop cmp rcx, QWORD [rsp + 0x420]
	jge _encryption_finished

; i = (i + 1) % 256
	add QWORD [rsp + 0x408], 1
	and QWORD [rsp + 0x408], 255

; j = (j + tab[i]) % 256
	mov r12, 4
	mov rax, QWORD [rsp + 0x408] ; take i
	mul r12
	xor r10, r10
	mov r10d, DWORD [rsp + rax]
	add QWORD [rsp + 0x410], r10
	and QWORD [rsp + 0x410], 255

; swap(tab[i], tab[j])
	lea rdi, [rel rsp + rax]
	mov rax, QWORD [rsp + 0x410]
	mov r12, 4
	mul r12
	lea rsi, [rel rsp + rax]
	lea r10, [rel _encrypt_loop.continue]
	push rdi
	push rsi
	push r10
	jmp _swap

; j = (tab[i] + tab[j]) % 256
	.continue pop rsi
	pop rdi
	xor r10, r10
	mov r10d, DWORD [rdi]
	mov QWORD [rsp + 0x410], r10
	xor r10, r10
	mov r10d, DWORD [rsi]
	add QWORD [rsp + 0x410], r10
	and QWORD [rsp + 0x410], 255

; zone[rcx] = zone[rcx] ^ tab[j]
	mov r12, 4
	mov rax, QWORD [rsp + 0x410]
	mul r12
	xor r11, r11
	mov r11d, DWORD [rsp + rax]
	mov r10, QWORD [rsp + 0x418]
	mov rdi, QWORD [rsp + 0x428]
	xor r12, r12
	mov r12b, BYTE [r10 + rcx]
	mov BYTE [rdi + rcx], r12b
	xor BYTE [rdi + rcx], r11b
	inc rcx
	jmp _encrypt_loop.loop

_encryption_finished:
	mov rax, QWORD [rsp + 0x400]
	leave
	ret

%undef ENCRYPT_S
