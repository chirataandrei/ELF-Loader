// SPDX-License-Identifier: BSD-3-Clause

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <elf.h>

void *map_elf(const char *filename)
{
	// This part helps you store the content of the ELF file inside the buffer.
	struct stat st;
	void *file;
	int fd;

	fd = open(filename, O_RDONLY);
	if (fd < 0) {
		perror("open");
		exit(1);
	}

	fstat(fd, &st);

	file = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (file == MAP_FAILED) {
		perror("mmap");
		close(fd);
		exit(1);
	}

	return file;
}

void load_and_run(const char *filename, int argc, char **argv, char **envp)
{
	// Contents of the ELF file are in the buffer: elf_contents[x] is the x-th byte of the ELF file.
	void *elf_contents = map_elf(filename);

	// Verify if the file is ELF64
	Elf64_Ehdr *header = (Elf64_Ehdr *) elf_contents;
	if (header->e_ident[0] != 0x7f || header->e_ident[1] != 'E' || header->e_ident[2] != 'L' || header->e_ident[3] != 'F') {
		fprintf(stderr, "Not a valid ELF file");
		exit(3);
	}

	if (header->e_ident[4] != ELFCLASS64) {
		fprintf(stderr, "Not a 64-bit ELF");
		exit(4);
	}
	
	/**
	 * TODO: Load PT_LOAD segments
	 * For minimal syscall-only binaries.
	 * For each PT_LOAD segment:
	 * - Map the segments in memory. Permissions can be RWX for now.
	 */
	Elf64_Phdr *phdr = (Elf64_Phdr *) ((char *) elf_contents + header->e_phoff);
	int page_size = getpagesize();
	for (size_t i = 0; i < header->e_phnum; i++) {
		if (phdr[i].p_type == PT_LOAD) {
			void *vaddr = (void *)phdr[i].p_vaddr;
			int filesz = phdr[i].p_filesz;
			int memsz = phdr[i].p_memsz;
			int offset = phdr[i].p_offset;
			void *aligned = vaddr - ((long long)vaddr % page_size);
			void *mem = mmap(aligned, memsz + (vaddr - aligned), PROT_EXEC | PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED, -1, 0);

			memcpy(vaddr, (char *)elf_contents + offset, filesz);
			if (memsz > filesz) {
				memset((char *)vaddr + filesz, 0, memsz - filesz);
			}
		}
 	}

	/**
	 * TODO: Load Memory Regions with Correct Permissions
	 * For each PT_LOAD segment:
	 *	- Set memory permissions according to program header p_flags (PF_R, PF_W, PF_X).
	 *	- Use mprotect() or map with the correct permissions directly using mmap().
	 */

	for (size_t i = 0; i < header->e_phnum; i++) {
		if (phdr[i].p_type == PT_LOAD) {
			void *vaddr = (void *)phdr[i].p_vaddr;
			int memsz = phdr[i].p_memsz;
			void *aligned = vaddr - ((long long)vaddr % page_size);
			int prot = 0;

			if (phdr[i].p_flags & PF_X) {
				prot = prot | PROT_EXEC;
			}
			if (phdr[i].p_flags & PF_W) {
				prot = prot | PROT_WRITE;
			}
			if (phdr[i].p_flags & PF_R) {
				prot = prot | PROT_READ;
			}

			mprotect(aligned + load_base, memsz + (vaddr - aligned), prot);
		}
	}

	/**
	 * TODO: Support Static Non-PIE Binaries with libc
	 * Must set up a valid process stack, including:
	 *	- argc, argv, envp
	 *	- auxv vector (with entries like AT_PHDR, AT_PHENT, AT_PHNUM, etc.)
	 * Note: Beware of the AT_RANDOM, AT_PHDR entries, the application will crash if you do not set them up properly.
	 */
	void *sp = NULL;

	/**
	 * TODO: Support Static PIE Executables
	 * Map PT_LOAD segments at a random load base.
	 * Adjust virtual addresses of segments and entry point by load_base.
	 * Stack setup (argc, argv, envp, auxv) same as above.
	 */

	// TODO: Set the entry point and the stack pointer
	void (*entry)() = NULL;

	// Transfer control
	__asm__ __volatile__(
			"mov %0, %%rsp\n"
			"xor %%rbp, %%rbp\n"
			"jmp *%1\n"
			:
			: "r"(sp), "r"(entry)
			: "memory"
			);
}

int main(int argc, char **argv, char **envp)
{
	if (argc < 2) {
		fprintf(stderr, "Usage: %s <static-elf-binary>\n", argv[0]);
		exit(1);
	}

	load_and_run(argv[1], argc - 1, &argv[1], envp);
	return 0;
}
