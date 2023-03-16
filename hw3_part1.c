#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <signal.h>
#include <syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/reg.h>
#include <sys/user.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdbool.h>
#include "hw3_part1.h"
#include "elf64.h"

#define ET_NONE 0 // No file type
#define ET_REL 1  // Relocatable file
#define ET_EXEC 2 // Executable file
#define ET_DYN 3  // Shared object file
#define ET_CORE 4 // Core file

/* symbol_name		- The symbol (maybe function) we need to search for.
 * exe_file_name	- The file where we search the symbol in.
 * error_val		- If  1: A global symbol was found, and defined in the given executable.
 * 			- If -1: Symbol not found.
 *			- If -2: Only a local symbol was found.
 * 			- If -3: File is not an executable.
 * 			- If -4: The symbol was found, it is global, but it is not defined in the executable.
 * return value		- The address which the symbol_name will be loaded to, if the symbol was found and is global.
 */

unsigned long find_symbol(const char *symbol_name, const char *exe_file_name, int *error_val){
	FILE *elf_file = fopen(exe_file_name, "r");
	if (!elf_file){
		return 0;
	}
	Elf64_Ehdr elf_header;
	fread(&elf_header, sizeof(Elf64_Ehdr), 1, elf_file);
	if (elf_header.e_type != ET_EXEC){
		*error_val = -3;
		fclose(elf_file);
		return 0;
	}
	Elf64_Shdr *section_header = malloc(elf_header.e_shnum * sizeof(Elf64_Shdr));
	if (!section_header){
		fclose(elf_file);
		return 0;
	}
	Elf64_Shdr *symtab_entry = NULL, *strtab_entry = NULL;

	/*support dyn*/
	Elf64_Shdr *dynsym_entry = NULL,*dynstr_entry = NULL,*rela_plt_entry = NULL;
	int flag_dynsym =0, flag_rela=0;

	fseek(elf_file, elf_header.e_shoff, SEEK_SET);
	fread(section_header,sizeof(Elf64_Shdr), elf_header.e_shnum, elf_file); // found section header
	int flag_strtab = 0, flag_symtab = 0;
	Elf64_Shdr sh_strtab = section_header[elf_header.e_shstrndx]; // found sh_strtab
	Elf64_Off offset_sh_strtab = sh_strtab.sh_offset;
	Elf64_Word section_name;
	char strtab_name[8];
	for (int i = 0; i < elf_header.e_shnum; i++){
		
		/*support dyn*/
		if(section_header[i].sh_type == 11){
			dynsym_entry = &section_header[i];
			flag_dynsym = 1;
			dynstr_entry = &section_header[dynsym_entry->sh_link];
		}
		if(section_header[i].sh_type == 4){
			rela_plt_entry = &section_header[i];
			flag_rela = 1;
		}

		if (section_header[i].sh_type == 2){ // found symtab
			symtab_entry = &section_header[i];
			flag_symtab = 1;
		}
		if (section_header[i].sh_type == 3){
			section_name = section_header[i].sh_name;
			fseek(elf_file, section_name + offset_sh_strtab, SEEK_SET); // we got the section name in sh stratab
			fread(strtab_name, 8, 1, elf_file);
			if (strcmp(strtab_name, ".strtab") == 0){// found strtab
				strtab_entry = &section_header[i];
				flag_strtab = 1;
			}
		}
		if (flag_symtab == 1 && flag_strtab == 1 && flag_dynsym==1 && flag_rela==1){
			break;
		}
	}
	int num_symbol_entries = symtab_entry->sh_size / symtab_entry->sh_entsize; // size of symbol table
	Elf64_Sym *symbol_table = malloc(num_symbol_entries * sizeof(Elf64_Sym));
	fseek(elf_file, symtab_entry->sh_offset, SEEK_SET); // we got the section name in sh stratab
	fread(symbol_table, symtab_entry->sh_entsize, num_symbol_entries, elf_file);
	int bind_flag = 0, def = 0;
	Elf64_Word index = 0;
	Elf64_Addr virt_add = 0;
	Elf64_Off offset_strtab = strtab_entry->sh_offset;
	int required_name_size = strlen(symbol_name), flag_name = 0;
	char get_name[required_name_size+1];
	for (int j = 0; j < num_symbol_entries; j++){
		virt_add = symbol_table[j].st_value; 
		def = (symbol_table[j].st_shndx == SHN_UNDEF);
		index = symbol_table[j].st_name;
		fseek(elf_file, index + offset_strtab, SEEK_SET); // we got the section name in stratab
		fread(get_name, required_name_size+1, 1, elf_file);
		if (strcmp(get_name, symbol_name) == 0){ // found strtab
			flag_name = 1;
			if (ELF64_ST_BIND(symbol_table[j].st_info) == 1){
				bind_flag =1;
				break;
			}
		}
	}
	if (flag_name == 1){ // found the name
		if (bind_flag == 1){ // symbol is global
			if (def == 0){
				*error_val = 1;
			}
			else{
				*error_val = -4;
			}
		}
		else{
			*error_val = -2;
		}
	}
	else{
		*error_val = -1;
	}

	/*support dyn*/
	if(def == 1){
		int dyn_index = -1;
		int num_dyn_symbol_entries = dynsym_entry->sh_size / dynsym_entry->sh_entsize; // size of dyn_symbol table
		Elf64_Sym *dyn_symbol_table = malloc(num_dyn_symbol_entries * sizeof(Elf64_Sym));
		fseek(elf_file, dynsym_entry->sh_offset, SEEK_SET); // we got the section name in sh stratab
		fread(dyn_symbol_table, dynsym_entry->sh_entsize, num_dyn_symbol_entries, elf_file);
		Elf64_Word index1 = 0;
		Elf64_Off offset_dyn_strtab = dynstr_entry->sh_offset;
		int required_name_size = strlen(symbol_name);
		char get_name[required_name_size+1];
		for (int j = 0; j < num_dyn_symbol_entries; j++){
			index1 = dyn_symbol_table[j].st_name;
			fseek(elf_file, index1 + offset_dyn_strtab, SEEK_SET); // we got the section name in stratab
			fread(get_name, required_name_size+1, 1, elf_file);
			if (strcmp(get_name, symbol_name) == 0){ // found strtab
				dyn_index = j;
				break;
			}
		}
		int num_rela_symbol_entries = rela_plt_entry->sh_size / rela_plt_entry->sh_entsize;
		Elf64_Rela *rela_table = malloc(num_rela_symbol_entries * sizeof(Elf64_Rela));
		fseek(elf_file, rela_plt_entry->sh_offset, SEEK_SET); // we got the section name in sh stratab
		fread(rela_table, rela_plt_entry->sh_entsize, num_rela_symbol_entries, elf_file);
		for (int j = 0; j < num_rela_symbol_entries; j++){
			if(ELF64_R_SYM(rela_table[j].r_info) == dyn_index){
				virt_add=rela_table[j].r_offset;
				break;
			}
		}
		free(dyn_symbol_table);
		free(rela_table);
	}


	fclose(elf_file);
	free(section_header);
	free(symbol_table);
	return virt_add;
}