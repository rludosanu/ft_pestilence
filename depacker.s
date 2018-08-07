;; For more details about this algorithm: it's an RC8 algorithme with a base key of 256 bytes
%define DEPACKER_S
%include "pestilence.lst"

section .text
	global _decrypt
	global _end_decrypt
	global _checksum
;	global _text_section_vaddr
;	global _total_size_to_checksum

;; -----------------------------------------------------------------------------------
;; NAME
;;		_decrypt
;;
;; SYNOPSIS
;;							rdi			rsi				rdx				r10
;;		void	_decrypt((void*)key, (void*)zone, (int)zone_size, void* new_zone)
;;
;; DESCRIPTION
;;		Decrypt zone_size(rdx) bytes from zone(rsi) with the key(rdi), and store the
;;		decrypted result on new_zone(r10).
;;
;; STACK USAGE
;;		rsp							: table (256 * sizeof(int)) bytes
;;		rsp + 0x410					: i, just a variable to browse our table
;;		rsp + 0x418					: j, it will store an index calculated with
;;										previous values, to make some swaps
;;		rsp + 0x420 -> rsp + 0x488	: padding to store all values, to save it from
;;										polimorph modifications.
;;		rsp + 0x490					: zone_size (rdx)
;;		rsp + 0x498					: zone (rsi)
;;		rsp + 0x4a0					: key (rdi)
;;		rsp + 0x4a8					: new_zone (r10)
;; -----------------------------------------------------------------------------------
_decrypt: 
	db 0xa9
; allocate necessary stack memory
    push rbp
    mov rbp, rsp
	push r10
	push rdi
	push rsi
	push rdx
    sub rsp, 0x490 ;0x12c
    xor rcx, rcx
	JUNK 5
	mov QWORD [rsp + 0x420], 0
	mov QWORD [rsp + 0x428], 4
	jmp _init_table+1

_init_table:
	db 0xdd
; while (rcx < 256) {
;   (int*)rsp[rcx] = rcx;
;   rcx++;
;}
    cmp QWORD [rsp + 0x420], 0x100
    jge _init_sorting
	JUNK 5
    mov rax, QWORD [rsp + 0x420]
    mul QWORD [rsp + 0x428]
	mov rcx, QWORD [rsp + 0x420]
    mov DWORD [rsp + rax], ecx
	inc QWORD [rsp + 0x420]
    jmp _init_table+1

_init_sorting:
    xor rcx, rcx
    mov QWORD [rsp + 0x410], 0
    mov QWORD [rsp + 0x420], 0
	JUNK 5
    mov QWORD [rsp + 0x428], 4
	jmp _sorting+1

_sorting:
	db 0xa0
; while (rcx < 256)
    cmp QWORD [rsp + 0x420], 0x100
    jge _init_decrypt_loop
; we take our index. we work with integers, that take 4 bytes so:
; we multiply our index by our integer size to take our offset in table
    xor rax, rax
    mov rax, QWORD [rsp + 0x420]
	JUNK 5
    mul QWORD [rsp + 0x428]

; j += tab[i]
    xor r10, r10
    mov r10d, DWORD [rsp + rax]
    add QWORD [rsp + 0x410], r10

; j += key[i]
    xor r11, r11
    mov r11, QWORD [rsp + 0x4a0]
    xor r10, r10
	JUNK 5
	mov rcx, QWORD [rsp + 0x420]
    mov r10b, BYTE [r11 + rcx]
    add QWORD [rsp + 0x410], r10

; j = j % 256 is equal j = j & 255
    and QWORD [rsp + 0x410], 255

; swap tab[i] with tab[j]
    lea rdi, [rel rsp + rax]
    xor r10, r10
    mov r10b, BYTE [rsp + 0x410]
	JUNK 5
    xor rax, rax
    mov rax, r10
    mul QWORD [rsp + 0x428]
    lea rsi, [rel rsp + rax]
	jmp _swap+1

_swap:
	db 0x69
    xor r10, r10
    xor r11, r11
    mov r10d, DWORD [rdi]
    mov r11d, DWORD [rsi]
    add DWORD [rdi], r11d
    mov r10d, DWORD [rdi]
    sub r10, r11
    mov DWORD [rsi], r10d
    mov r11d, DWORD [rsi]
    sub DWORD [rdi], r11d
	JUNK 5
    inc QWORD [rsp + 0x420]
    jmp _sorting+1

_init_decrypt_loop:
	mov QWORD [rsp + 0x410], 0
	mov QWORD [rsp + 0x418], 0
	mov QWORD [rsp + 0x420], 0
	mov QWORD [rsp + 0x428], 4
	xor rcx, rcx
	jmp _decrypt_loop+1

_decrypt_loop:
	db 0x72
    xor r10, r10
    mov r10, QWORD [rsp + 0x490]
	cmp QWORD [rsp + 0x420], r10
	jge _end_decrypt
	add QWORD [rsp + 0x410], 1
	and QWORD [rsp + 0x410], 255
	JUNK 5
	xor r10, r10
	mov r10, QWORD [rsp + 0x410]
    xor rax, rax
    mov rax, r10
    mul QWORD [rsp + 0x428]
	lea rdi, [rel rsp + rax]
	xor r10, r10
	JUNK 5
	mov r10d, DWORD [rdi]
	add QWORD [rsp + 0x418], r10
	and QWORD [rsp + 0x418], 255
	xor r10, r10
	mov r10, QWORD [rsp + 0x418]
    xor rax, rax
    mov rax, r10
	JUNK 5
    mul QWORD [rsp + 0x428]
	lea rsi, [rel rsp + rax]
	jmp _swap2+1

_swap2:
	db 0x09
    xor r10, r10
    xor r11, r11
    mov r10d, DWORD [rdi]
    mov r11d, DWORD [rsi]
    add DWORD [rdi], r11d
    mov r10d, DWORD [rdi]
    sub r10, r11
    mov DWORD [rsi], r10d
    mov r11d, DWORD [rsi]
    sub DWORD [rdi], r11d

_continue:
	mov QWORD [rsp + 0x418], 0
	xor r10, r10
	mov r10d, DWORD [rdi]
	xor r11, r11
	mov r11d, DWORD [rsi]
	JUNK 5
	add QWORD [rsp + 0x418], r10
	add QWORD [rsp + 0x418], r11
	and QWORD [rsp + 0x418], 255
	xor r11, r11
	mov r11, QWORD [rsp + 0x418]
    xor rax, rax
    mov rax, r11
    mul QWORD [rsp + 0x428]
	xor r10, r10
	mov r10d, DWORD [rsp + rax]
	JUNK 5
    xor r11, r11
    mov r11, QWORD [rsp + 0x498]
	mov rdi, QWORD [rsp + 0x4a8]
	xor rsi, rsi
	mov rcx, QWORD [rsp + 0x420]
	mov sil, BYTE [r11 + rcx]
	mov BYTE [rdi + rcx], sil
	xor BYTE [rdi + rcx], r10b
	inc QWORD [rsp + 0x420]
	JUNK 5
	jmp _decrypt_loop+1

_end_decrypt:
	leave
	ret

_checksum:
	dd 0x00000000

%undef DEPACKER_S
