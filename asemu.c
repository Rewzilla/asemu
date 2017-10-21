#include <ncurses.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <stdlib.h>
#include <capstone/capstone.h>
#include <keystone/keystone.h>
#include <unicorn/unicorn.h>

#define EIP_START 0x04000000
#define ESP_START 0x2b000000
#define EBP_START ESP_START

#define PAGE_SZ 4*1024*1024

// WITH the border
#define CONSOLE_HEIGHT (5 + 2)
#define REGISTER_WIDTH (20 + 2)
#define STACK_WIDTH (22 + 2)

#define REGISTERS_FMT \
	"EAX:    %08x\n" \
	"EBX:    %08x\n" \
	"ECX:    %08x\n" \
	"EDX:    %08x\n" \
	"ESI:    %08x\n" \
	"EDI:    %08x\n" \
	"EBP:    %08x\n" \
	"ESP:    %08x\n" \
	"EIP:    %08x\n" \
/* TODO
	"EFLAGS: %08x\n"
	" CF:%d PF:%d AF:%d ZF:%d\n" \
	" SF:%d TF:%d IF:%d DF:%d\n" \
	" OF:%d NT:%d RF:%d VM:%d\n"
*/

typedef struct window {
	int width;
	int height;
	char title[32];
	WINDOW *border;
	WINDOW *content;
} window_t;

typedef struct instruction {
	char text[32];
	char opcodes[16];
	size_t opcode_len;
	unsigned int address;
	struct instruction *prev;
	struct instruction *next;
} instruction_t;

typedef struct registers {
	int eax;
	int ebx;
	int ecx;
	int edx;
	int esi;
	int edi;
	int ebp;
	int esp;
	int eip;
} registers_t;

window_t registers, stack, code, console;
int parent_y, parent_x;

instruction_t *inst;
registers_t regs;

ks_engine *ks;
uc_engine *uc;

void init_window(window_t *w, int y, int x, int height, int width, char *title) {

	w->width = width - 2;
	w->height = height - 2;
	strncpy(w->title, title, 31);
	w->border = newwin(height, width, y, x);
	w->content = newwin(height - 2, width -2, y + 1, x + 1);

}

void draw_window(window_t *w) {

	box(w->border, 0, 0);
	mvwprintw(w->border, 0, 2, "[%s]", w->title);
	wrefresh(w->border);
	wrefresh(w->content);

}

void init_regs() {

	regs.eax = 0x00000000;
	regs.ebx = 0x00000000;
	regs.ecx = 0x00000000;
	regs.edx = 0x00000000;
	regs.esi = 0x00000000;
	regs.edi = 0x00000000;
	regs.ebp = EBP_START;
	regs.esp = ESP_START;
	regs.eip = EIP_START;

	uc_reg_write(uc, UC_X86_REG_EAX, &regs.eax);
	uc_reg_write(uc, UC_X86_REG_EBX, &regs.ebx);
	uc_reg_write(uc, UC_X86_REG_ECX, &regs.ecx);
	uc_reg_write(uc, UC_X86_REG_EDX, &regs.edx);
	uc_reg_write(uc, UC_X86_REG_ESI, &regs.esi);
	uc_reg_write(uc, UC_X86_REG_EDI, &regs.edi);
	uc_reg_write(uc, UC_X86_REG_EBP, &regs.ebp);
	uc_reg_write(uc, UC_X86_REG_ESP, &regs.esp);
	uc_reg_write(uc, UC_X86_REG_EIP, &regs.eip);


}

void init_instructions(char *file, int entrypoint) {

	FILE *fp;
	char buff[1024];
	unsigned char *opcodes;
	size_t size, count;
	int i;
	instruction_t *tmp;

	fp = fopen(file, "r");
	if(!fp) {
		inst = NULL;
		return;
	}

	tmp = inst;

	while(fgets(buff, 1024, fp)) {

		for(i=0; i<strlen(buff); i++) {
			if(buff[i] == ';' || buff['i'] == '\n') {
				buff[i] = '\0';
				break;
			}
		}

		if(ks_asm(ks, buff, 0, &opcodes, &size, &count) != KS_ERR_OK) {
			printf("ERROR: Failed to assemble instruction '%s'\n", buff);
			return;
		}

		if(size == 0)
			continue;

		if(inst == NULL) {
			inst = malloc(sizeof(instruction_t));
			inst->prev = NULL;
			inst->next = NULL;
			inst->address = entrypoint;
			memcpy(inst->opcodes, opcodes, size);
			inst->opcode_len = size;
			strncpy(inst->text, buff, 32);
		} else {
			if(!tmp)
				tmp = inst;
			tmp->next = malloc(sizeof(instruction_t));
			tmp = tmp->next;
			tmp->prev = tmp;
			tmp->next = NULL;
			tmp->address = entrypoint;
			memcpy(tmp->opcodes, opcodes, size);
			tmp->opcode_len = size;
			strncpy(tmp->text, buff, 32);
		}

		entrypoint += size;

		free(opcodes);

	}

	fclose(fp);

}

void init_memory() {

	instruction_t *tmp;

	uc_mem_map(uc, regs.eip, PAGE_SZ, UC_PROT_ALL);

	for(tmp=inst; tmp; tmp=tmp->next) {
		uc_mem_write(uc, tmp->address, tmp->opcodes, tmp->opcode_len);
	}

	uc_mem_map(uc, regs.esp - PAGE_SZ, PAGE_SZ, UC_PROT_ALL);

}

void usage(char *arg0) {

	printf("Usage: %s [OPTIONS] <file.s>\n", arg0);
	printf("A simple 32-bit x86 emulator\n");
	printf("\n");
	printf("  %-10s %s\n", "-h", "Print this help menu");
	printf("\n");
	printf("(c)opyleft Andrew Kramer, 2017, <andrew@jmpesp.org>\n");

}

void render() {

	int i, j;
	char opcode[4], opcodes[32], mem[4], ptrstr[10] = {0};
	instruction_t *tmp;

	uc_reg_read(uc, UC_X86_REG_EAX, &regs.eax);
	uc_reg_read(uc, UC_X86_REG_EBX, &regs.ebx);
	uc_reg_read(uc, UC_X86_REG_ECX, &regs.ecx);
	uc_reg_read(uc, UC_X86_REG_EDX, &regs.edx);
	uc_reg_read(uc, UC_X86_REG_ESI, &regs.esi);
	uc_reg_read(uc, UC_X86_REG_EDI, &regs.edi);
	uc_reg_read(uc, UC_X86_REG_EBP, &regs.ebp);
	uc_reg_read(uc, UC_X86_REG_ESP, &regs.esp);
	uc_reg_read(uc, UC_X86_REG_EIP, &regs.eip);

	mvwprintw(registers.content, 0, 0, REGISTERS_FMT,
		regs.eax, regs.ebx, regs.ecx, regs.edx,
		regs.esi, regs.edi, regs.ebp, regs.esp,
		regs.eip);
	draw_window(&registers);

	for(i=stack.height-1,j=ESP_START; i>=0; i--,j-=4) {
		if(j==ESP_START) {
			memset(mem, '\0', 4);
		} else {
			uc_mem_read(uc, j, mem, 4);
		}
		if(j == regs.esp && regs.esp == regs.ebp) {
			strcpy(ptrstr, "B>S>");
		} else if(j == regs.esp) {
			strcpy(ptrstr, "  S>");
		} else if(j == regs.ebp) {
			strcpy(ptrstr, "B>");
		} else {
			ptrstr[0] = '\x00';
		}
		mvwprintw(stack.content, i, 0, "%-5s%08x %02hhx%02hhx%02hhx%02hhx",
			ptrstr, j, mem[0], mem[1], mem[2], mem[3]);
	}
	draw_window(&stack);

	for(i=0,tmp=inst; tmp; i++,tmp=tmp->next) {
		memset(opcodes, '\0', 32);
		for(j=0; j<tmp->opcode_len; j++) {
			sprintf(opcode, "%02hhx ", tmp->opcodes[j]);
			strcat(opcodes, opcode);
		}
		mvwprintw(code.content, i, 0,
			"%c %08x %-16s %s\n",
			(tmp->address==regs.eip ? '>' : ' '),
			tmp->address, opcodes, tmp->text);
	}
	draw_window(&code);

	draw_window(&console);

	wmove(console.content, 0, 0);

}

int main(int argc, char *argv[]) {

	int opt;

	set_tabsize(4);

	while((opt = getopt(argc, argv, "h")) != -1) {
		switch(opt) {

			case 'h':	// help
				usage(argv[0]);
				return 0;

			default:
				printf("unknown option '-%c'\n", opt);
				return 0;

		}
	}

	if(optind >= argc) {
		printf("ERROR: filename required\n");
		usage(argv[0]);
		return 0;
	}

	if(ks_open(KS_ARCH_X86, KS_MODE_32, &ks) != KS_ERR_OK) {
		printf("ERROR: Failed to initialize Keystone engine\n");
		return 0;
	}

	if(uc_open(UC_ARCH_X86, UC_MODE_32, &uc) != UC_ERR_OK) {
		printf("ERROR: Failed to initialize Unicorn engine\n");
		return 0;
	}

	initscr();

	getmaxyx(stdscr, parent_y, parent_x);

	init_window(&registers, 0, 0, parent_y - CONSOLE_HEIGHT, REGISTER_WIDTH, "REGISTERS");
	init_window(&stack, 0, parent_x - STACK_WIDTH, parent_y - CONSOLE_HEIGHT, STACK_WIDTH, "STACK");
	init_window(&code, 0, REGISTER_WIDTH, parent_y - CONSOLE_HEIGHT, parent_x - REGISTER_WIDTH - STACK_WIDTH, "CODE");
	init_window(&console, parent_y - CONSOLE_HEIGHT, 0, CONSOLE_HEIGHT, parent_x, "CONSOLE");

	init_regs();

	inst = NULL;
	init_instructions(argv[optind], regs.eip);

	if(!inst) {
		printf("ERROR: failed to parse instructions\n");
		return 0;
	}

	init_memory();

	uc_err err;
	char buff[1024];
	for(;;) {

		render();

		wgetnstr(console.content, buff, 1024);

		err = uc_emu_start(uc, regs.eip, 0xffffffff, 0, 1);
		if (err) {
			printf("Failed on uc_emu_start() with error returned %u: %s\n", err, uc_strerror(err));
		}
	}

	return 0;

}
