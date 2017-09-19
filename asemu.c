#include <ncurses.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <stdlib.h>

// WITH the border
#define CONSOLE_HEIGHT (5 + 2)
#define REGISTER_WIDTH (20 + 2)
#define STACK_WIDTH (20 + 2)

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
	"EFLAGS: %08x\n"
/* TODO
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

void init_regs(registers_t *regs) {

	regs->eax = 0x00000000;
	regs->ebx = 0x00000000;
	regs->ecx = 0x00000000;
	regs->edx = 0x00000000;
	regs->esi = 0x00000000;
	regs->edi = 0x00000000;
	regs->ebp = 0xffffffff;
	regs->esp = 0xffffffff;
	regs->eip = 0x00400000;

}

void init_instructions(instruction_t **inst, char *file, int entrypoint) {

	FILE *fp;
	char buff[1024];
	int i;
	instruction_t *tmp;

	fp = fopen(file, "r");
	if(!fp) {
		*inst = NULL;
		return;
	}

	tmp = *inst;

	while(fgets(buff, 1024, fp)) {

		for(i=0; i<strlen(buff); i++) {
			if(buff[i] == ';' || buff['i'] == '\n') {
				buff[i] = '\0';
				break;
			}
		}

		if(*inst == NULL) {
			*inst = malloc(sizeof(instruction_t));
			(*inst)->prev = NULL;
			(*inst)->next = NULL;
			(*inst)->address = entrypoint++;
			strncpy((*inst)->opcodes, "\x41\x42\x43", 4);
			(*inst)->opcode_len = 3;
			strncpy((*inst)->text, buff, 32);
		} else {
			if(!tmp)
				tmp = *inst;
			tmp->next = malloc(sizeof(instruction_t));
			tmp = tmp->next;
			tmp->prev = tmp;
			tmp->next = NULL;
			tmp->address = entrypoint++;
			strncpy(tmp->opcodes, "\x41\x42\x43", 4);
			tmp->opcode_len = 3;
			strncpy(tmp->text, buff, 32);
		}

	}

	fclose(fp);

}

void usage(char *arg0) {

	printf("Usage: %s [OPTIONS] <file.s>\n", arg0);
	printf("A simple 32-bit x86 interpreter\n");
	printf("\n");
	printf("  %-10s %s\n", "-h", "Print this help menu");
	printf("\n");
	printf("(c)opyleft Andrew Kramer, 2017, <andrew@jmpesp.org>\n");

}

int main(int argc, char *argv[]) {

	instruction_t *inst, *tmp;
	registers_t regs;
	int opt;
	int i, j;
	char opcode[4], opcodes[32];

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

	initscr();

	getmaxyx(stdscr, parent_y, parent_x);

	init_window(&registers, 0, 0, parent_y - CONSOLE_HEIGHT, REGISTER_WIDTH, "REGISTERS");
	init_window(&stack, 0, parent_x - STACK_WIDTH, parent_y - CONSOLE_HEIGHT, STACK_WIDTH, "STACK");
	init_window(&code, 0, REGISTER_WIDTH, parent_y - CONSOLE_HEIGHT, parent_x - REGISTER_WIDTH - STACK_WIDTH, "CODE");
	init_window(&console, parent_y - CONSOLE_HEIGHT, 0, CONSOLE_HEIGHT, parent_x, "CONSOLE");

	init_regs(&regs);

	inst = NULL;
	init_instructions(&inst, argv[optind], regs.eip);

	if(!inst) {
		printf("ERROR: failed to parse instructions\n");
		return 0;
	}

	char buff[1024];
	for(;;) {

		mvwprintw(registers.content, 0, 0, REGISTERS_FMT,
			regs.eax, regs.ebx, regs.ecx, regs.edx,
			regs.esi, regs.edi, regs.ebp, regs.esp,
			regs.eip);
		draw_window(&registers);

		draw_window(&stack);

		for(i=0,tmp=inst; tmp; i++,tmp=tmp->next) {
			memset(opcodes, '\0', 32);
			for(j=0; j<tmp->opcode_len; j++) {
				sprintf(opcode, "%02hhx ", tmp->opcodes[j]);
				strcat(opcodes, opcode);
			}
			mvwprintw(code.content, i, 0,
				"%c %08x %16s %s\n",
				(tmp->address==regs.eip ? '>' : ' '),
				tmp->address, opcodes, tmp->text);
		}
		draw_window(&code);

		draw_window(&console);

		wmove(console.content, 0, 0);
		wgetnstr(console.content, buff, 1024);

	}

	return 0;

}