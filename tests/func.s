
main:
	push    10
	push    20
	call    func
	add     esp, 8
	ret

do_nothing:
	ret

func:
	push    ebp
	mov     ebp, esp
	sub     esp, 4

	call    do_nothing

	mov     eax, [ebp + 8]
	mov     [ebp - 4], eax

	mov     eax, [ebp + 12]
	add     [ebp - 4], eax

	mov     eax, [ebp - 4]
	mov     esp, ebp
	pop     ebp
	ret
