push	10
push	20
call	func

add		esp, 8

nop
nop
nop

func:
push	ebp
mov		ebp, esp
sub		esp, 4

mov		eax, [ebp + 8]
mov		[ebp - 4], eax

mov		eax, [ebp + 12]
add		[ebp - 4], eax

mov		eax, [ebp - 4]
mov		esp, ebp
pop		ebp
ret

nop
nop
nop
