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
	size_t stack_size = 8 * 1024 * 1024;
	void *stack = mmap(NULL, stack_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (stack == MAP_FAILED) {
		perror("mmap stack");
		exit(1);
	}

	char *p = (char *)stack + stack_size;

	// copy argv strings
	char *argv_addr[argc];
	for (size_t i = 0; i < argc; i++) {
		size_t len = strlen(argv[i]) + 1;
		p -= len;
		memcpy(p, argv[i], len);
		argv_addr[i] = p;
	}
	
	// copy envp strings
	size_t envc = 0;
	while (envp[envc] != NULL) {
		envc++;
	}

	char *envp_addr[envc];
	for (size_t i = 0; i < envc; i++) {
		size_t len = strlen(argv[i]) + 1;
		p -= len;
		memcpy(p, envp[i], len);
		envp_addr[i] = p;
	}

	// alloc buffer for AT_RANDOM
	p -= 16;
	void *rdn_bytes = (void *)p;
	int rnd_fd = open("/dev/urandom", O_RDONLY);
	if (rnd_fd >= 0) {
		if (read(rnd_fd, rnd_bytes, 16) != 16) {
			memset(rdn_bytes, 0x41, 16);
		}
		close(rnd_fd);
	} else {
		memset(rdn_bytes, 0x41, 16);
	}

	// find AT_PHDR
	uintptr_t at_phdr = 0;
	for (size_t i = 0; i < header->e_phnum; i++) {
		if (phdr[i].p_type == PT_LOAD) {
			if (header->e_phoff >= phdr[i].p_offset && header->e_phoff < phdr[i].p_offset + phdr[i].p_filesz) {
				at_phdr = phdr[i].p_vaddr + (header->e_phoff - phdr[i].p_offset);
				break;
			}
		}
	}

	typedef struct {
		uint64_t key, value;
	} aux_entry_t;

	aux_entry_t aux[] = {
        {AT_PHDR, at_phdr},
        {AT_PHENT, header->e_phentsize},
        {AT_PHNUM, header->e_phnum},
        {AT_PAGESZ, page_size},
        {AT_RANDOM, (uint64_t)random_bytes},
        {AT_EXECFN, (uint64_t)argv_addr[0]},
        {AT_ENTRY, load_base + header->e_entry},
        {AT_NULL, 0}
    };
    size_t auxc = sizeof(aux) / sizeof(aux[0]);

	// calculate total words for alignment
	size_t total = 1 + argc + 1 + envc + 1 + auxc * 2;
	// aligned at 16 bytes 
	p = (char *)((uintptr_t)p & ~0xFULL);
	uint64_t *st = (uint64_t *)p;

	if (total % 2 != 0) {
		st--;
		*st = 0;
	}

	for (size_t i = auxc - 1; i >= 0; i--) {
		st--;
		*st = aux[i].val;
		st--;
		*st = aux[i].key;
	}
	st--;
	*st = (uint64_t)0;

	for (size_t i = envc - 1; i >= 0; i--) {
		st--;
		*st = (uint64_t)env_addr[i];
	}
	st--;
	*st = (uint64_t)0;

	for (size_t i = argc - 1; i >= 0; i--) {
		st--;
		*st = (uint64_t)argv_addr[i];
	}

	st--;
	*st = (uint64_t)argc;
	p = (void *)st;


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
