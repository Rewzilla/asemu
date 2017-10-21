push	10
push	20
pop	eax
pop	ebx
push	0x55667788
pop	ecx
call	test
mov	eax, 75		; A
mov	ebx, 100
inc	eax			; B
inc	ebx
;int	0x80		; do the thing
mov ecx, 0
inc ecx
cmp ecx, 10
jle -4
