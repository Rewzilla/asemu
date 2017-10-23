main:
	push    10
	push    20
	call    add_them_up
	add     esp, 8

	push    eax

	push    30
	push    40
	call    add_them_up
	add     esp, 8

	push    eax

	call    mul_them_up
	add     esp, 8

	ret

add_them_up:
	push    ebp
	mov     ebp, esp
	sub     esp, 4

	mov     eax, [ebp + 8]
	mov     [ebp - 4], eax
	mov     eax, [ebp + 12]
	add     [ebp - 4], eax

	mov     eax, [ebp - 4]
	mov     esp, ebp
	pop     ebp
	ret

mul_them_up:
	push    ebp
	mov     ebp, esp
	sub     esp, 4

	mov     eax, [ebp + 8]
	mov     ebx, [ebp + 12]
	mul     ebx
	mov     [ebp - 4], eax

	mov     eax, [ebp - 4]
	mov     esp, ebp
	pop     ebp
	ret
