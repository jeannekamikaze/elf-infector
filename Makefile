all: infector.s
	nasm -f elf infector.s
	ld -o infector infector.o

clean:
	@rm -f ./*.o
	@rm -f infector
	
