
main:

	mov		eax, 0
	add		eax, 4
	jmp		testing

	nop
	nop
	nop

testing:
	sub		eax, 4

	cmp		eax, 0
	je		main

asdf:

	add		eax, 10
