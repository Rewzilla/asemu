%define hello "hello"
%define fiftyfive 55
%define c 'c'

segment .data
	dfirst db hello," World",10,0
	dsecond db 99,98,fiftyfive,100,101,32h,0x33," testing ", 0xa, 0h
	dthird dd 6789
	dfourth dd fiftyfive
	dfifth db "%d %s %c %x", 0
	dsixth db "54321",0

segment .bss
	bfirst resd 10
	bsecond resb 10

segment .text
	global asm_main
	extern printf, scanf, strlen, atoi
	extern strcmp, read_char, read_int
	extern print_nl, print_int, print_char
	extern print_string, putchar, getchar, puts, gets

asm_main:
	push ebp
	mov ebp, esp

	;printf test
	push 'b'
	push 'c' ; does not work, need to use characters not defines for characters
	push dfirst
	push dword [dfourth]
	push dword dfifth
	call printf
	add esp, 20

	;scanf test
	push bfirst
	push bsecond
	push bsecond+1
	push bfirst +4
	push dfifth
	call scanf;scanf test
	add esp, 20

	push dword [bfirst]
	push bsecond
	push bsecond+1
	push dword [bfirst + 4]
	push dfifth
	call printf
	add esp, 20
	
	;strlen
	push dsecond
	call strlen
	add esp, 4

	;atoi
	push dsixth
	call atoi
	add esp, 4

	;strcmp
	push dfirst
	push dsecond
	call strcmp
	add esp, 8

	;homemade
	call read_char
	call print_char
	call read_int
	call print_int
	mov eax, dfirst
	call print_string

	;getchar
	call getchar

	;putchar
	push eax
	call putchar
	add esp, 4
	
	;gets
	push bsecond
	call gets
	add esp, 4

	;puts
	push bsecond
	call puts
	add esp, 4
	
	mov esp, ebp
	pop ebp
	ret	
