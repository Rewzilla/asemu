
#include <ctype.h>
#include <stdio.h>
#include <ncurses.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <stdlib.h>
#include <capstone/capstone.h>
#include <keystone/keystone.h>
#include <unicorn/unicorn.h>

#define PROMPT "(asemu)>"

char *trim(char* tmp); // fix later
void render();
int datasegment(FILE **fp, char *buff);
int bsssegment(FILE **fp, char *buff);
void resize();
void printsegments(int x);

#define EIP_START 0x04000000
#define ESP_START 0x2b000000
#define EBP_START ESP_START

#define PAGE_SZ 4*1024*1024

// WITH the border
#define CONSOLE_HEIGHT (5 + 2)
#define REGISTER_WIDTH (14 + 2)
#define STACK_WIDTH (21 + 2)

#define REGISTERS_FMT \
	"EAX: %08x\n" \
	"EBX: %08x\n" \
	"ECX: %08x\n" \
	"EDX: %08x\n" \
	"ESI: %08x\n" \
	"EDI: %08x\n" \
	"EBP: %08x\n" \
	"ESP: %08x\n" \
	"EIP: %08x\n" \
/* *TODO
	"EFLAGS: %08x\n" \
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
	char text[64];
	char opcodes[16];
	size_t opcode_len;
	bool breakpoint;
	unsigned int address;
	int index;
	bool ext;
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

typedef struct label {
	char text[1024];
	int index;
	int offset;
} label_t;

typedef struct segments {//used for data and bss segments
	unsigned int address;
	char name[32];
	int size;
	int type; //Currently int or string
	char* string;
	char* original;
	int value;
	struct segments *next;
}Segments;

struct arguments{//used for external functions
	int type;
	char character;
	int integer;
	char string[64];
	unsigned int address;
	struct arguments* next;
	struct arguments* prev;
};

struct define{
	char name[32];
	int type;
	char* string;
	char character;
	int integer;
	struct define* next;
};

typedef struct text{//text segment; only printing out for now
	int index;
	char *string;
}Text; 

window_t registers, stack, code, console;
int parent_y, parent_x;

instruction_t *inst;
registers_t regs;
registers_t oldregs;

label_t labels[1024];
Segments *dataseg;
Segments *bssseg;
Text text[64];
struct define *define;

unsigned int data_size;

int label_count;
int data_count;
int bss_count;
int text_count;
int ind;

instruction_t* inst_index;

ks_engine *ks;
uc_engine *uc;

void crash_handler(int sig) {

	endwin();
	printf(
		"\033[1;31mUh oh! asemu crashed. :(\033[0m Error code: %d\n"
		"If this crash is reproducable and you have time, please email\n"
		"andrew@jmpesp.org with details so it can be fixed.\n"
		"Thanks in advance!\n", sig
	);
	ks_close(ks);
	uc_close(uc);
	exit(0);
}

void error(const char *msg) {

	wattron(console.content, COLOR_PAIR(3));
	mvwprintw(console.content, 0, 8,  "ERROR: %s\n", msg);
	wattroff(console.content, COLOR_PAIR(3));
	mvwprintw(console.content, 1, 0, "(ENTER to quit)");
}

bool checkbreakformat(char *buff){//checks string for hex format for breakpoint

	strcpy(buff, trim(buff));

	if(((buff[0] == '0' || buff[0] == '\\') && buff[1] == 'x' && strlen(buff) == 10) || strlen(buff) == 8)
		if(buff[1] == 'x')
			buff+=2;
		for(int i = 0; i < strlen(buff);i++){
			buff[i] = tolower(buff[i]);
			if(buff[i] < '0' ||( buff[i] > '9' && buff[i] < 'a' )|| buff[i] > 'f')
			       return 0;	
		return 1;
		}
	return 0;
}

bool checkscroll(char *buff){//checks string for scroll

	if(!strncasecmp(buff, "scroll", 6))
	{
		return 1;
	}
	return 0;
}

bool checkrun(char *buff){//check string for run

	if(!strncasecmp(buff, "run",3) || buff[0] == 'r' || buff[0] == 'R' || !strncasecmp(buff, "continue", 8) || !strncasecmp(buff, "go", 2) || buff[0] == 'g')
		return 1;
	return 0;
}

bool checknext(char *buff){//check string for next

	if(!strcasecmp(buff, "next") || !strcasecmp(buff, "Step") || buff[0] == 'n' || buff[0] == 'N' || strlen(buff) == 0)
		return 1;
	return 0;
}

bool checkbreakpoint(char *buff){//check if breakpoint is possible

	bool size = 0;

	if(!strncasecmp(buff, "breakpoint", 10))
		size = 1;
	else if(!strncasecmp(buff, "break", 5))
		size = 1;
	else if(!strncasecmp(buff, "bp", 2))
		size = 1;
	else if(buff[0] == 'b' || buff[0] == 'B')
		size = 1;
	else return 0;
		return size;
}

int islabel(char *line) { // checks to see if colon is last valuable character, could cause problems with accessing from different segments.

	int i;

	for(i=0; i<strlen(line); i++) {
		if(line[i] >= 'a' && line[i] <= 'z'
		|| line[i] >= 'A' && line[i] <= 'Z'
		|| line[i] >= '0' && line[i] <= '9'
		|| line[i] == '_'
		|| line[i] == ' ' || line[i] == '\t') {
			// ok
		} else {
			break;
		}
	}

	if(line[i] == ':') {
		return 1;
	} else {
		return 0;
	}
}

int isbranch(char *line) {//checks if command is a jump or call

	int i;

	for(i=0; i<strlen(line); i++) {
		if(line[i] == ' ' || line[i] == '\t')
			continue;
		// dirty hack for jmp's, oh jeez, TODO :(
		else if(strncasecmp(&line[i], "call", 4) == 0 || line[i] == 'j'){
			return 1;
		}
		else
			return 0;
	}
	return 0;
}

char *trim(char *line) {//grabs first word with special characters

	int i;
	static char s[1024];
	
	while(*line == ' ' || *line == '\t' || *line == '%' || *line == '\n' || *line == '\'' || *line == '"')
		line++;

	i = 0;
	while(*line >= 'a' && *line <= 'z'
		||*line >= 'A' && *line <= 'Z'
		||*line >= '0' && *line <= '9'
		||*line == '_'
		||*line == '/'
		||*line == '\\'
		||*line == '.')
		s[i++] = *line++;

	s[i] = '\0';
	
	return s;
}



char *get_label(char *line) {//grabs second word

	int i;
	static char label[1024];

	while(*line == ' ' || *line == '\t')
		line++;

	while(*line != ' ' && *line != '\t')
		line++;

	while(*line == ' ' || *line == '\t')
		line++;
	i = 0;
	label[i] = '\0';
	while(*line >= 'a' && *line <= 'z'
		||*line >= 'A' && *line <= 'Z'
		||*line >= '0' && *line <= '9'
		||*line == '_' || *line == '-')
		label[i++] = *line++;

	label[i] = '\0';

	return label;
}

char *get_mnemonic(char *line) {//grab first word

	int i;
	static char mnemonic[1024];

	while(*line == ' ' || *line == '\t')
		line++;

	i = 0;

	while(*line >= 'a' && *line <= 'z'
		||*line >= 'A' && *line <= 'Z'
		||*line >= '0' && *line <= '9'
		||*line == '_' || *line == '%')
		mnemonic[i++] = *line++;

	mnemonic[i] = '\0';

	return mnemonic;
}

unsigned char at_interupt() {//interupt

	unsigned char mem[2];

	uc_mem_read(uc, regs.eip, mem, 2);

	if(mem[0] == 0xcd)
		return mem[1];
	else
		return 0;
}

int handle_interupt(unsigned char interupt) {//handles the interrupt

	int i = regs.eax;
	char c;
	long long rsi, rax, rdx, rdi;
		char *string;
	regs.eip += 2;
	uc_reg_write(uc, UC_X86_REG_EIP, &regs.eip);
	endwin();
	system("clear");
	printf("Syscall\n");
	switch(interupt) {
		case 0x80:
			switch(i){
				case 0x1://exit
					rax = 60;
					rdi = regs.ebx;
					break;
				case 0x3://read
					string = malloc(regs.ebx);	
					rsi = (long long)string;
					rdi = regs.ebx;
					rax = 0;
					rdx = regs.edx;
					break;
				case 0x4://write
					string = malloc(regs.ebx);
					uc_mem_read(uc, regs.ecx, string, regs.edx);
					rsi = (long long)string;
					rdi = regs.ebx;
					rax = 1;
					rdx = regs.edx;
					break;
				default://not implemented
					error("system call instruction not yet implemented");
						return 0;
			}
			__asm__(
				"movq %0, %%rax;"
				"movq %1, %%rdi;"
				"movq %2, %%rsi;"
				"movq %3, %%rdx;"
				"syscall"
				:
				:"m" (rax), "m" (rdi), "m" (rsi), "m" (rdx)
				:"%rax", "%rbx", "%rcx", "%rdx"
			);
			switch(i){
				case 0x3://write back to emulator
					uc_mem_write(uc, regs.ecx, string, regs.edx);
					break;
				default:
					break;
			}
			break;
		default:
			error("Interupt not yet supported");
			return 0;
	}
	char complicatedname[1];
	printf("Press enter to exit syscall\n");//so syscall does not end right away if displaying data
	scanf("%c", &complicatedname[0]);
	initscr();
	resize();
	return 1;
}

int count_instructions(instruction_t *inst) {//returns number of instructions
	
	int c = 0;
	
	while(inst != NULL) {
		c++;
		inst = inst->next;
	}

	return c;
}

instruction_t *get_inst_index(int instruction) {//returns pointer to current instruction
	
	instruction_t *tmp = inst;

	while(tmp && tmp->address != instruction) {
		tmp = tmp->next;
	}

	if(!tmp)
		return NULL;
	else
		return tmp;
}

unsigned int next_inst_addr() {//grabs next address
	
	instruction_t *tmp = inst;

	while(tmp && tmp->address != regs.eip) {
		tmp = tmp->next;
	}

	if(tmp->next)
		return tmp->next->address;
	else
		return -1;
}

void init_window(window_t *w, int y, int x, int height, int width, char *title) {

	w->width = width - 2;
	w->height = height - 2;
	strncpy(w->title, title, 31);
	w->border = newwin(height, width, y, x);
	w->content = newwin(height - 2, width -2, y + 1, x + 1);
}

void draw_window(window_t *w) {
	wattron(w->border, COLOR_PAIR(1));
	box(w->border, 0, 0);
	wattroff(w->border, COLOR_PAIR(1));
	wattron(w->border, COLOR_PAIR(2));
	mvwprintw(w->border, 0, 2, "[%s]", w->title);
	wattroff(w->border, COLOR_PAIR(2));
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

	oldregs = regs;
}

void getdefine(char*buff){//grabs defined data

	while(*buff == '\t' || *buff == ' ')
		buff++;
	while(*buff != '\t' && *buff != ' ')
		buff++;
	while(*buff == '\t' || *buff == ' ')
		buff++;

	if(define == NULL){
		define = malloc(sizeof(struct define));
		define->next = NULL;
	}
	
	struct define* walk = define;
	
	while(walk->next != NULL)
		walk=walk->next;
	walk->next = malloc(sizeof(struct define));
	walk = walk->next;
	walk->next = NULL;

	strncpy(walk->name, get_mnemonic(buff), 31);
	buff+=strlen(get_mnemonic(buff));

	while(*buff == '\t' || *buff == ' ')
		buff++;	
	switch(*buff){
		case '\'':
			walk->type = 3;
			walk->character = buff[1];
			break;
		case '"':
			buff++;
			walk->type = 2;
			walk->string = malloc(strlen(buff));
			strncpy(walk->string, trim(buff), strlen(trim(buff)));
			break;
		default:
			walk->type = 1;
			walk->integer = atoi(trim(buff));
	
	}
}

bool isdefine(char* buff){

	if(!strcmp(get_mnemonic(buff), "%define")){
		return 1;
	}
	return 0;
}

int issegment(char *buff) {//checks for data, bss, or text segment

	if(!strncmp(buff, "segment", 7) || !strncmp(buff, "Segment", 7)){
		buff += 8;

		if(!strncmp(buff, ".data", 5))
			return 1; //data section
		else if(!strncmp(buff, ".bss", 4))
			return 2; //bss section
		else if(!strncmp(buff, ".text", 5))
			return 3; //text section
	}
	else
		return 0;

}

void getText(char *buff){//grabs text data
	
	text[text_count].string = malloc(strlen(buff));
	strcpy(text[text_count].string, buff);
	//text[text_count].index = ind++;
	text_count++;
	
}

void getbss(char *buff){//grabs bss data
	
	int i = 0;
	while(*buff == ' ' || *buff == '\t')
		buff++;
	if(*buff == '\0'){
		printf("Your Bss segment is broken please try to fix at \"%s\" variable\n", buff);
		exit(0);
	}
	if(bssseg == NULL){
		bssseg = malloc(sizeof(Segments));
		bssseg->next = NULL;
	}
	Segments *bsswalk = bssseg;
	for(;bsswalk->next != NULL; bsswalk=bsswalk->next);
	if(bss_count > 0){
		bsswalk->next = malloc(sizeof(Segments));
		bsswalk = bsswalk->next;
		bsswalk->next = NULL;	
	}
	strncpy(bsswalk->name, get_mnemonic(buff), 64);
	buff+= strlen(get_mnemonic(buff));
	while(*buff == ' ' || *buff == '\t')
		buff++;
	if(!strncasecmp(buff, "resb", 4))
	{
		buff += 4;
		bsswalk->type = 2; //chars
		if(get_mnemonic(buff)[0] >= '0' && get_mnemonic(buff)[0] <= '9')
			bsswalk->size = atoi(get_mnemonic(buff));
		else{
			struct define *definewalk = define;
			while(definewalk!= NULL)
			{
				if(!strcmp(definewalk->name, get_mnemonic(buff))){
					if(definewalk->type == 1)
						bsswalk->size = definewalk->integer;
					else if(definewalk->type == 3)
						bsswalk->size = (int)definewalk->character;
					break;
				}
				definewalk= definewalk->next;
			}
		}
		bsswalk->value = 0;
	}	
	else if(!strncasecmp(buff, "resd", 4))
	{
		buff +=4;
		bsswalk->type = 1;
		bsswalk->value = 0;
		if(get_mnemonic(buff)[0] >= '0' && get_mnemonic(buff)[0] <= '9')
			bsswalk->size = atoi(get_mnemonic(buff));
		else{
			struct define *definewalk = define;
			while(definewalk!= NULL)
			{
				
				if(!strcmp(definewalk->name, get_mnemonic(buff))){
					if(definewalk->type == 1)
						bsswalk->size = definewalk->integer;
					else if(definewalk->type == 3)
						bsswalk->size = (int)definewalk->character;
					break;
				}
				definewalk=definewalk->next;
			}
		}

	}
	bsswalk->address = EIP_START+PAGE_SZ+PAGE_SZ+data_size;
		if(uc_mem_write(uc, bsswalk->address, &bsswalk->value, (bsswalk->type == 1 ? bsswalk->size * 4 : bsswalk->size)) != UC_ERR_OK)
			printf("Memory for the bss section could not be made please document what happened and how\n");
	data_size += bsswalk->size;
	bss_count++;
}

void getdata(char *buff){//grabs data data

	int i = 0, j, tmp = 0;
	while(*buff == ' ' || *buff == '\t')
		buff++;
	
	if(buff[i] == '\0'){
		printf("Your Data segment is broken please try to fix at \"%s\" variable\n", buff);
		exit(0);
	}
	if(dataseg == NULL)
	{
		dataseg = malloc(sizeof(Segments));
		dataseg->next = NULL;
	}
	Segments *datawalk = dataseg;
	for(;datawalk->next != NULL; datawalk = datawalk->next);
	if(data_count != 0){
		datawalk->next = malloc(sizeof(Segments));
		datawalk = datawalk->next;
		datawalk->next = NULL;
	}
	strncpy(datawalk->name, get_mnemonic(buff), 31);
	datawalk->name[31] = '\0';
	buff+= strlen(get_mnemonic(buff));
	
	while(*buff == ' ' || *buff == '\t')
		buff++;
	if(!strncasecmp(buff, "db", 2))//character or string
	{
		buff += 2;
		while(*buff == ' ' || *buff == '\t')
		{
			buff++;
		}
		datawalk->original = (strlen(buff) > 128 ? malloc(128) : malloc(strlen(buff)+1));
		strncpy(datawalk->original, buff, (strlen(buff) > 128 ? 127 : strlen(buff)+1));
		if(strlen(buff) > 128);
		datawalk->original[127] = '\0';
		datawalk->string = malloc(sizeof(datawalk->original));
		j = 0, i = 0;
		int a = 0, b = 0, c = 0;
		int jk;
		char inte[3];
		struct define *definewalk;
		while(1){//fixes string if set up with ints and quotes
			if(buff[b] == ' ' || buff[b] == '\t'){
				b++;
				continue;
			}
			if(buff[b] == '"')//checks if character is a string else its a number
			{
				b++;
				for(; a < 128 && b < strlen(buff);a++, b++)
				{
					if(buff[b] == '"')
					{
						b++;
						break;
					}
					datawalk->string[a] = buff[b];
				}
			}
			else if(sscanf(trim(buff+b), "%i", &jk) == 1){
				b+= strlen(trim(buff+b));
				datawalk->string[a] = (char)jk;
				a++;
			}
			else if((buff[b] >='a' && buff[b] <= 'z') || (buff[b] >= 'A' && buff[b] <= 'Z'))//is a defined value
			{
				definewalk = define;
				while(definewalk != NULL){
					if(!strncmp(definewalk->name, buff+b, strlen(definewalk->name)) && !strncmp(definewalk->name, buff+b, strlen(trim(buff+b))))
					{
						switch(definewalk->type){
							case 1:
								datawalk->string[a] = definewalk->integer;
								a++;
								break;
							case 2:
								for(int i = 0; i < strlen(definewalk->string) && a < 128;i++, a++)
									datawalk->string[a] = definewalk->string[i];
								break;
							case 3:
								datawalk->string[a] = definewalk->character;
								a++;
						}
						b += strlen(definewalk->name);
					}
					definewalk = definewalk->next;
				}
			}
			else
				b++;
			if(a >= 128 || b >= strlen(buff))
				break;
		}
		datawalk->type = 2; //string
		datawalk->size = a;
		datawalk->value = 0;
	}
	else if(!strncasecmp(buff, "dd", 2)){
		
		buff += 2;
		while(*buff == ' ' || *buff == '\t')
		{
			buff++;
		}

		datawalk->type = 1; //int
		datawalk->size = 4;
		if((*buff >= 'a' && *buff <='z') || (*buff >= 'A' && *buff <= 'Z'))
		{
			struct define *definewalk = define;
			while(definewalk!=NULL)
			{
				if(!strncmp(definewalk->name, buff, strlen(definewalk->name))&& strlen(definewalk->name)>0){
					if(definewalk->type == 1)
						datawalk->value = definewalk->integer;
					else if(definewalk->type == 3)
						datawalk->value = definewalk->character;
					else 
						datawalk->value = 0;
					break;				
				}
				definewalk = definewalk->next;
			}
		}
		else{
			datawalk->value = atoi(trim(buff));
		}
	}
	else{
		printf("Hopefully you see this and realize there was a problem with reading the data section good luck figuring it out, currently only Defined Bytes and Defined Doublewords are allowed\n");
	}
	datawalk->address = EIP_START+PAGE_SZ+data_size;
	
	if(datawalk->type == 1)
		uc_mem_write(uc, datawalk->address, &datawalk->value, 4);
	else
		if(uc_mem_write(uc, datawalk->address, datawalk->string, datawalk->size) != UC_ERR_OK)
			printf("Memory for the data section could not be made please document what happened and how");
	data_size += datawalk->size;
	data_count++;
	return;
}

bool isother(char *buff){
	if(strlen(buff) == 0 || strlen(buff) == 1)
		return 1;
	while(*buff == ' ' || *buff == '\t')
		buff++;
	if(buff[0] == '\0' || buff[0] == ';')
		return 1;
	return 0;
}

int textsegment(FILE **fp, char *buff){

	int i;
	text_count = 0;
	while(1){
		fgets(buff, 1024, *fp);
		if(i = issegment(buff)){
			if(i == 1){
				return datasegment(fp, buff);
			}
			else{
				return bsssegment(fp, buff);
			}
		}
		else if(isother(buff)){//whitespace or comment
			continue;
		}
		else if(islabel(buff)){
			return 0;
		}
		else{
			getText(buff);
		}
	}
	return 1;
}

int bsssegment(FILE **fp, char *buff){
	
	uc_mem_map(uc, regs.eip+PAGE_SZ+PAGE_SZ, PAGE_SZ, UC_PROT_ALL); //allocates bss memory after data large chunk though
	int i;
	bss_count = 0;
	
	while(1){
		fgets(buff, 1024, *fp);
		if(i = issegment(buff)){
			if(i == 1)
			{
				return datasegment(fp, buff);
			}
			else{
				return textsegment(fp, buff);
			}
		}
		else if(isother(buff)){//whitespace or comment
			continue;
		}
		else if(islabel(buff)){
			return 0;
		}
		else{
			getbss(buff);
		}

	}
	return 1;
}

int datasegment(FILE **fp, char *buff){
	
	data_count = 0;
	uc_mem_map(uc, regs.eip+PAGE_SZ, PAGE_SZ, UC_PROT_ALL);//allocates data segment, large chunk though
	int i;
	
	while(1){
		fgets(buff, 1024, *fp);
		if(i = issegment(buff)){
			if(i == 2)
				return bsssegment(fp, buff);
			else
				return textsegment(fp, buff);
		}
		else if(isother(buff)){//whitespace or comment
			continue;
		}
		else if(islabel(buff)){
			return 0;
		}
		else{//not label or new segment means it is a variable.
			getdata(buff);
		}
	}
	return 1;
}

char* get_end(char *buff){//don't necisarily need this
	
	while(*buff == ' ' || *buff == '\t')
		buff++;
	while(*buff != ' ' && *buff != '\t')
		buff++;
	while(*buff == ' ' || *buff == '\t')
		buff++;
	return buff;
}

int sym_resolver(const char *symbol, uint64_t *value){
	
	Segments *walk = dataseg;
	while(walk != NULL){
		if(!strcmp(symbol, walk->name))
		{
			*value = walk->address;
			break;
		}
		walk = walk->next;
	}
	if(walk != NULL)
		return 1;
	walk = bssseg;
	while(walk != NULL){
		if(!strcmp(symbol, walk->name))
		{
			*value = walk->address;
			break;
		}
		walk = walk->next;
	}
	if(walk != NULL)
		return 1;
	
	struct define * definewalk = define;
	while(definewalk!= NULL){
		if(!strcmp(definewalk->name, symbol))
		{
			switch(definewalk->type){
				case 1:
					*value = definewalk->integer;
					break;
				case 3:
					*value = (int)definewalk->character;
					break;
			}
				return 1;	
		}
		definewalk = definewalk->next;
	}
	return 0;

}

bool isimport(char *buff){
	if(!strcmp(get_mnemonic(buff), "%include"))
			return 1;
	return 0;
}

void callcorrectfunction(){

	int i;
	char *name = get_label(inst_index->text);
	unsigned int esp = 0, eax = 0;
	uc_reg_read(uc, UC_X86_REG_ESP, &esp);
	uc_reg_read(uc, UC_X86_REG_EAX, &eax);
	unsigned int tmp = 0;
	char sformat[3] = "%s";
	char cformat[3] = "%c";
	char iformat[3] = "%i";
	char buffer[512];
	if(!strcmp(name, "print_string"))//output the output to screen or print with function
	{
		char string[128];
		uc_mem_read(uc, eax, string, 128);
		mvwprintw(console.content, 2, 0, "Output> %s", string);
	}
	else if(!strcmp(name, "print_char")){
		char character = (char)eax;
		mvwprintw(console.content, 2, 0, "Output> %c", character); 
	}
	else if(!strcmp(name, "print_int")){
		int integer = eax;
		__asm__(
				"mov %0, %%rdi;"
				"mov %1, %%rsi;"
				"mov %2, %%edx;"
				"call sprintf;"
				:
				:"r" (buffer), "r" (iformat), "r" (integer)
				:"%rdi", "%rsi", "%rdx"
		       );
		mvwprintw(console.content, 2, 0, "Output> %s", buffer);
	}
	else if(!strcmp(name, "read_int")){
		int value;
		mvwprintw(console.content, 2, 0, "Input > ");
		mvwscanw(console.content, 2, 8, "%d", &value);
		uc_reg_write(uc, UC_X86_REG_EAX, &value);
	}
	else if(!strcmp(name, "read_char")){
		char c;
		mvwprintw(console.content, 2, 0, "Input > ");
		mvwscanw(console.content, 2, 8, cformat, &c);
		uc_reg_write(uc, UC_X86_REG_EAX, &c);
	}
	else if(!strcmp(name, "print_nl")){
		mvwprintw(console.content, 2, 0, "Output> \n");//not sure if this is really needed;
	}
	else if(!strcmp(name, "strlen")){
		char string[128] = {'\0'};
		uc_mem_read(uc, esp, &eax, 4);
		uc_mem_read(uc, eax, string, 127);
		eax = strlen(string);
		uc_reg_write(uc, UC_X86_REG_EAX, &eax);
	}
	else if(!strcmp(name, "atoi")){
		char string[11] = {'\0'};
		uc_mem_read(uc, esp, &eax, 4);
		uc_mem_read(uc, eax, string, 10);
		eax = atoi(string);
		uc_reg_write(uc, UC_X86_REG_EAX, &eax);
	}
	else if(!strcmp(name, "strcmp")){
		char string[128] = {'\0'}, string2[128] = {'\0'};
		uc_mem_read(uc, esp, &eax, 4);
		uc_mem_read(uc, eax, string, 127);
		uc_mem_read(uc, esp+4, &eax, 4);
		uc_mem_read(uc, eax, string2, 127);
		eax = strcmp(string, string2);
		uc_reg_write(uc, UC_X86_REG_EAX, &eax);
	}
	else if(!strcmp(name, "puts")){
		char string[128] = {'\0'};
		uc_mem_read(uc, esp, &eax, 4);
		uc_mem_read(uc, eax, string, 127);
		mvwprintw(console.content, 2, 0, "Output> %s", string);
	}
	else if(!strcmp(name, "gets")){
		char string[128] = {'\0'};
		uc_mem_read(uc, esp, &eax, 4);
		mvwprintw(console.content, 2, 0, "Input > ");
		mvwscanw(console.content, 2, 8, "%127s", string);
		uc_mem_write(uc, eax, string, strlen(string));
	}
	else if(!strcmp(name, "getchar")){
		eax = 0;
		mvwprintw(console.content, 2, 0, "Input > ");
		mvwscanw(console.content, 2, 8, "%c", &eax);
		uc_reg_write(uc, UC_X86_REG_EAX, &eax);
	}
	else if(!strcmp(name, "putchar")){
		uc_mem_read(uc, esp, &eax, 1);	
		mvwprintw(console.content, 2, 0, "Output> %c", eax);
	}
	else if(!strcmp(name, "printf")){
		long long counter = 0;
		char string[128];
		uc_mem_read(uc, esp, &tmp, 4);
		uc_mem_read(uc, tmp, string, 128);//string is starting string for the function
		struct arguments *arg = malloc(sizeof(struct arguments));
		arg->prev = NULL;
		arg->next = NULL;
		struct arguments *walk = NULL;
		mvwprintw(console.content, 2, 0, "Output> %s", buffer);
		esp+=4;
		struct arguments *walk2 = NULL;
		for(int i = 0; i < strlen(string); i++){
			if(string[i] == '%'){//look for special characters in string
				if(walk == NULL){
					walk = arg;
				}
				else if(counter > 2){
					walk2 = malloc(sizeof(struct arguments));
					walk2->next = walk;
					walk = walk->prev;
					walk2->prev = walk;
					walk->next = walk2;
					walk2->next->prev = walk2;
					walk = walk2;
				}
				else{
					walk->next = malloc(sizeof(struct arguments));
					walk->next->prev = walk;
					walk = walk->next;
					walk->next = NULL;
				}
				walk->type = 0;
				switch(string[i+1]){//grab the correct variable data type according to special characters
					case 's':
						walk->type = 1;
						uc_mem_read(uc, esp, &tmp, 4);
						uc_mem_read(uc, tmp, walk->string, 64);
						break;

					case 'c':
						walk->type = 2;
						uc_mem_read(uc, esp, &walk->character, 1);	
						break;

					case 'x':
					case 'd':
						walk->type = 3;
						uc_mem_read(uc, esp, &walk->integer, 4);
						break;

					default:
						printf("\%%c not yet supported\n", string[i]);
						return;
						//do something maybe
				}
				esp+=4;
				counter++;
			}
		}
		walk = arg;
		if(counter % 2 && counter > 2){
			__asm__(
					"sub $8, %%rsp":::"%rsp"
			       );
			counter++;
		}
			for(int i = 1;counter > 0 && walk != NULL; i++, walk = walk->next)//if special characters move correct values into registers
			{
				switch(i){
					case 1://r8
						switch(walk->type){
							case 1:
								__asm__(
										"mov %0, %%r8"
										:
										:"r" (walk->string)
										:"%r8"
								       );
								break;
							case 2:
								__asm__(
										"mov %0, %%r8b"
										:
										:"r" (walk->character)
										:"%r8"
								       );
								break;
							case 3:
								__asm__(
										"mov %0, %%r8d"
										:
										:"r" (walk->integer)
										:"%r8"
								       );
								break;
							default:
								break;
						}
						break;
					case 2://r9
						switch(walk->type){
							case 1:
								__asm__(
										"mov %0, %%r9"
										:
										:"r" (walk->string)
										:"%r9"
								       );
								break;
							case 2:
								__asm__(
										"mov %0, %%r9b"
										:
										:"r" (walk->character)
										:"%r9"
								       );
								break;
							case 3:
								__asm__(
										"mov %0, %%r9d"
										:
										:"r" (walk->integer)
										:"%r9"
								       );
								break;
							default:
								break;
						}

						break;
					default://push extras
						switch(walk->type){
							case 1:
								__asm__(
										"push %0"
										:
										:"r" (walk->string)
										:	
								       );
								break;
							case 2:
								__asm__(
										"mov $0, %%rax;"
										"mov %0, %%al;"
										"push %%rax"
										:
										:"r" (walk->character)
										:"%rax"
								       );
								break;
							case 3:
								__asm__(
										"mov $0, %%rax;"
										"mov %0, %%eax;"
										"push %%rax"
										:
										:"r" (walk->integer)
										:"%rax"
								       );
								break;
							default:
								break;
						}
						break;

				}
			}
			__asm__(//printing to the screen
				"movq %0, %%rdi;"
				"movq $2, %%rsi;"
				"movq $8, %%rdx;"
				"movq %1, %%rcx;"
				"mov $0, %%rax;"
				"call mvwprintw;"
				:
				:"r" (console.content), "r" (string)
				: "%rdi", "%rsi", "%rdx", "%rcx", "%r8", "%r9", "%rax", "%rsp"
		       );
		counter -= 2;
		if(counter > 0){//clearing the stack
			counter*=8;
			__asm__("sub %0, %%rsp" ::"r"(counter):"%rsp");
		}
	}
	else if(!strcmp(name, "scanf")){//same layout as printf above
		long long counter = 0;
		char string[128];
		uc_mem_read(uc, esp, &tmp, 4);
		uc_mem_read(uc, tmp, string, 128);
		struct arguments *arg = malloc(sizeof(struct arguments));
		arg->next = NULL;
		arg->prev = NULL;
		struct arguments *walk = NULL;
		struct arguments *walk2 = NULL;
		mvwprintw(console.content, 2, 0, "Input > ");
		for(int i = 0; i < strlen(string); i++){
			if(string[i] == '%'){
				if(walk == NULL){
					walk = arg;
				}
				else if(counter > 2){
					walk2 = malloc(sizeof(struct arguments));
					walk2->next = walk;
					walk = walk->prev;
					walk2->prev = walk;
					walk->next = walk2;
					walk2->next->prev = walk2;
					walk = walk2;
				}
				else{
					walk->next = malloc(sizeof(struct arguments));
					walk->next->prev = walk;
					walk = walk->next;
					walk->next = NULL;
				}
				walk->type = 0;
				walk->integer = 0;
				esp+=4;
				uc_mem_read(uc, esp, &walk->address, 4);
				counter++;
				switch(string[i+1]){
					case 's':
						walk->type = 1;
						break;
					case 'c':
						walk->type = 2;
						break;
					case 'x':
					case 'd':
						walk->type = 3;
						break;
					default:
						printf("\%%c not yet supported \n", string[i]);
						return;
				}
			}
		}

		walk = arg;
		if(counter%2 && counter > 2)
		{
			__asm__(
					"sub $8, %%rsp":::"%rsp"
			       );
			counter++;
		}
		for(int i = 1; counter > 0 && walk != NULL; i++, walk = walk->next){
			switch(i){
				case 1: //r8
					switch(walk->type){
						case 1:
                                                        __asm__(
                                                                        "mov %0, %%r8"
                                                                        :
                                                                        :"r" (walk->string)
                                                                        :"%r8"
                                                               );
                                                        break;
                                                case 2:
							__asm__(
                                                                        "mov %0, %%r8"
                                                                        :
                                                                        :"r" (&walk->character)
                                                                        :"%r8"
                                                               );
                                                        break;
                                               case 3:
                                                        __asm__(
									"mov %0, %%r8"
                                                                        :
                                                                        :"r" (&walk->integer)
                                                                        :"%r8"
                                                               );
                                                        break;
                                               default:
                                                        break;

					}
					break;
				case 2: //r9
					switch(walk->type){
						case 1:
                                                        __asm__(
                                                                        "mov %0, %%r9"
                                                                        :
                                                                        :"r" (walk->string)
                                                                        :"%r9"            
                                                               );
                                                        break;
                                                case 2:
							__asm__(
                                                                        "mov %0, %%r9"
                                                                        :
                                                                        :"r" (&walk->character)
                                                                        :"%r9"
                                                               );
                                                        break;
                                               case 3:
                                                        __asm__(
                                                                        "mov %0, %%r9"
                                                                        :
                                                                        :"r" (&walk->integer)
                                                                        :"%r9"
                                                               );
                                                        break;
                                               default:
                                                        break;
					}
					break;
				default://switch to be pushes
					switch(walk->type){
						case 1:
                                                        __asm__(
                                                                        "push %0"
                                                                        :
                                                                        :"r" (walk->string)
                                                                        :
                                                               );
                                                        break;
                                                case 2:
							__asm__(
									"push %0"
                                                                        :
                                                                        :"r" (&walk->character)
                                                                        :
                                                               );
                                                        break;
                                               case 3:
                                                        __asm__(
									"push %0"
                                                                        :
                                                                        :"r" (&walk->integer)
                                                                        :
                                                               );
                                                        break;
                                               default:
                                                        break;
					}
			
			}
		}
		__asm__(
				"movq %0, %%rdi;"
				"movq $2, %%rsi;"
				"movq $8, %%rdx;"
				"movq %1, %%rcx;"
				"mov $0, %%rax;"
				"call mvwscanw;"
				:
				:"r" (console.content), "r" (string)
				: "%rdi", "%rsi", "%rdx", "%rcx", "%r8", "%r9", "%rax", "%rsp"			
		       );
		counter -= 2;
		if(counter>0)
		{
			counter*=8;
			__asm__("sub %0, %%rsp" ::"r"(counter):"%rsp");
		}

		walk = arg;
		for(;walk!=NULL; walk = walk->next){//prints grabbed values to memory
			switch(walk->type){
				case 1:
					uc_mem_write(uc, walk->address, walk->string, strlen(walk->string));
					break;
				case 2:
					uc_mem_write(uc, walk->address, &walk->character, 1);
					break;
				case 3:
					uc_mem_write(uc, walk->address, &walk->integer, 4);
					break;
				default:
					break;
			}
		}
	}
	return;
}

bool external_func(char *name){//checks if call to a function is an external call current implemented functions are below
	
	if(!strcmp(name, "print_string"))
	{
	}
	else if(!strcmp(name, "print_char"))
	{
	}
	else if(!strcmp(name, "print_int")){
	}
	else if(!strcmp(name, "print_nl"))
	{
	}
	else if(!strcmp(name, "read_int"))
	{
	}
	else if(!strcmp(name, "read_char"))
	{
	}
	else if(!strcmp(name, "printf")){
	}
	else if(!strcmp(name, "scanf")){
	}
	else if(!strcmp(name, "strcmp")){
	}
	else if(!strcmp(name, "strlen")){
	}
	else if(!strcmp(name, "atoi")){
	}
	else if(!strcmp(name, "puts")){
	}
	else if(!strcmp(name, "gets")){
	}
	else if(!strcmp(name, "putchar")){
	}
	else if(!strcmp(name, "getchar")){
	}
	else
		return 0;
	return 1;
}

bool checkdisplay(char *buff){
	
	if(!strcasecmp(get_mnemonic(buff), "display")){
		return 1;
	}
	return 0;
}

void breakpoint(char* buff){
	char *bp = buff;
	unsigned int tmp;
	buff+= strlen(get_mnemonic(buff));
	buff = trim(buff);
	if(!checkbreakformat(buff)){
		render();
		mvwprintw(console.content, 0, 9, "Sorry %s does not match the correct format, 0xXXXXXXXX\n", buff);	
		mvwprintw(console.content, 1, 0, "%s ", PROMPT);
	}
	else{
		if(buff[1]!='x')//we want 0x...
		{
			strcpy(bp, buff);
			strcpy(buff, "0x");
			strcat(buff, bp);
		}
		else if(buff[0] == '\\')//given \x... not 0x...
			buff[0] = '0';
		sscanf(buff,"%i", &tmp);
		inst_index = get_inst_index(tmp); // pointer to breaking command
		render();
		if(inst_index == NULL)
		{
			mvwprintw(console.content, 0, 9, "Sorry could not find %s please try again\n", buff);
			mvwprintw(console.content, 1, 0, "%s ", PROMPT);
		}
		else{
		
			if(inst_index->breakpoint)
			{
				strcpy(bp, "Breakpoint removed from ");
				strcat(bp, buff);
				inst_index->breakpoint = 0;
			}
			else
			{
				strcpy(bp, "Breakpoint set at ");
				strcat(bp, buff);
				inst_index->breakpoint = 1;
			}
			//inst_index = get_inst_index(regs.eip); //changes whether shows the breakpoint or not right away
			render();
			mvwprintw(console.content, 0, 9, "%s\n", bp);
			mvwprintw(console.content, 1, 0, "%s ", PROMPT);
		}
	}
};
void init_instructions(FILE *fp, int entrypoint) {

	define = NULL;
	char buff[1024], comment[64];
	char instruction[64];
	unsigned char *opcodes;
	size_t size, count;
	int i;
	instruction_t *tmp;
	int addr, offset;//, index;

	if(!fp) {
		inst = NULL;
		return;
	}

	tmp = inst;
	addr = entrypoint;
	label_count = 0;
	data_count = 0;
	bss_count = 0;
	text_count = 0;
	offset = 0;
	int tester = 1;
	
	while(1){
		if(tester)
			if(fgets(buff, 1024, fp))
			{//nothing
			}
			else
			       break;
		else{
			tester = 1;
		}
		strncpy(comment, buff, 63); // allows comments
		comment[63] = '\0'; //terminate the string if buff is longer than 64 characters.

		for(i=0; i<strlen(buff); i++) {
			if(buff[i] == ';' || buff[i] == '\n') {
				buff[i] = '\0';		
				break;
			}
		}

		if(islabel(buff)) {
			strcpy(labels[label_count].text, buff);
			for(i=0; i<strlen(labels[label_count].text); i++) {
				if(labels[label_count].text[i] == ':') {
					labels[label_count].text[i] = '\0';
					break;
				}		}
			labels[label_count].offset = offset;
			labels[label_count].index = ind;
			label_count++;
			continue;
		}

		if(isbranch(buff)) {
			sprintf(instruction, "%s +0", get_mnemonic(buff));
			ks_asm(ks, instruction, 0, &opcodes, &size, &count);
		}
		else if(isimport(comment)){
			continue;
		}
		else if(i = issegment(buff)){
			if(i == 1){
				tester = datasegment(&fp, buff);
				continue;
			}
			else if(i == 2){
				tester = bsssegment(&fp, buff);
				continue;
			}
			else if(i == 3){
				tester = textsegment(&fp, buff);
			}
		}
		else if(isdefine(buff)){
			getdefine(buff);
			continue;
		}
		else {//buff should be a command at this point now compile
			if(ks_asm(ks, buff, 0, &opcodes, &size, &count) != KS_ERR_OK) {
				int errno = ks_errno(ks);
				if(errno == 161){//push variable error example: push tmp 
				       	
					ks_close(ks);
					ks_err error = ks_open(KS_ARCH_X86, KS_MODE_64, &ks);
					ks_option(ks, KS_OPT_SYNTAX, KS_OPT_SYNTAX_NASM);
        				ks_option(ks, KS_OPT_SYM_RESOLVER, (size_t)sym_resolver);
					if(error != KS_ERR_OK)
					{
						endwin();
						printf("ERROR: failed on trying to open ks as 64bit to fix\n");
						exit(0);
					}
					else if(ks_asm(ks, buff, 0, &opcodes, &size, &count) != KS_ERR_OK){
						endwin();
						printf("ERROR: Failed to assemble intstruction '%s'\nError Code: %u\n", buff, ks_errno(ks));
						exit(0);
					}
					else{
						ks_close(ks);
						error = ks_open(KS_ARCH_X86, KS_MODE_32, &ks);
						if(error != KS_ERR_OK)
						{
							endwin();
							printf("ERROR: failed on trying to open ks as 32bit after fix\n");
							exit(0);
						}
						ks_option(ks, KS_OPT_SYNTAX, KS_OPT_SYNTAX_NASM);
        					ks_option(ks, KS_OPT_SYM_RESOLVER, (size_t)sym_resolver);
					}
				}
				else if(errno == 512){//mov value into variable error example: mov [tmp], dword 5 becomes mov dword [tmp], dword 5
					char* buff2 = malloc(strlen(buff));
					strcpy(buff2, buff);
					char *token = strtok(buff, ", \t");
					char *pointer = malloc(sizeof(6));
					while(token != NULL)
					{
						if(!strcasecmp(token, "DWORD") || !strcasecmp(token, "BYTE") || !strcasecmp(token, "WORD"))
							break;
						token = strtok(NULL, ", \t");
					}

					if(token == NULL)
					{
						strcpy(pointer, "DWORD");
					}
					else{
						strcpy(pointer, token);
					}
					
					for(int i = 0; i < strlen(buff2)+1; i++){
						buff[i] = '\0';
					}
					int first = 0;
					for(first = 0; buff2[first] == '\t' || buff2[first] == ' '; first++)
					{
						buff[first] = buff2[first];
					}
					for(first; buff2[first] != '\t' && buff2[first] != ' '; first++)
					{
						buff[first] = buff2[first];
					}
					buff[first] = buff2[first];
					strcat(buff, pointer);
					strcat(buff, buff2 + first);
					if(ks_asm(ks, buff, 0, &opcodes, &size, &count) != KS_ERR_OK) {
						endwin();
						printf("ERROR: Failed to assemble intstruction '%s'\n%u\n", buff, ks_errno(ks));
						exit(0);
					}	
				}
				else{
					endwin();
					printf("ERROR: Failed to assemble intstruction '%s'\n%u\n", buff, ks_errno(ks));
					exit(0);
					}
			}
		}
		if(size == 0){//either a comment, whitespace, or compiler broke/tried to assemble incorrect format
			if(strchr(comment, ';') == NULL && strlen(get_mnemonic(comment)) != 0){
				//something bad just happened	
				endwin();
				printf("I'm going to be honest 1 of two things happened either something broke or your %s does not work with this compiler so try moving some stuff to different registers first then try again.\n", buff);
				exit(0);
			}
		}
		else
			offset += size;
		
		if(inst == NULL) {
			inst = malloc(sizeof(instruction_t));
			inst->prev = NULL;
			inst->next = NULL;
			inst->address = size == 0 ? 0xffffffff : addr;
			inst->index = ind++;
			inst->breakpoint = 0;
			memcpy(inst->opcodes, opcodes, size);
			inst->opcode_len = size;
			strncpy(inst->text, comment, 64);
			inst->ext = 0;
		} else {
			if(!tmp)
				tmp = inst;
			tmp->next = malloc(sizeof(instruction_t));
			tmp->next->prev = tmp;
			tmp = tmp->next;
			tmp->next = NULL;
			tmp->address = size == 0 ? 0xffffffff : addr;
			tmp->index = ind++;
			tmp->breakpoint = 0;
			memcpy(tmp->opcodes, opcodes, size);
			tmp->opcode_len = size;
			strncpy(tmp->text, comment, 64);
			tmp->ext = 0;
		}

		addr += size;
		free(opcodes);
	}
	fclose(fp);
	tmp = inst;
	offset = 0;
	int offset2;
	while(tmp != NULL) {//fix for calls not being able to use symbol link table
		if(isbranch(tmp->text)) {
			for(i=0; i<label_count; i++) {
				if(strlen(trim(labels[i].text)) == strlen(get_label(tmp->text))
				&& strncmp(trim(labels[i].text), get_label(tmp->text), strlen(trim(labels[i].text))) == 0)
					break;
			}
			offset2 = offset;
			if(i == label_count){
				if(!external_func(get_label(tmp->text)))
					offset2 = 10000;
				else{
					offset2 = -5;
					tmp->ext = 1;
				}

			}
			sprintf(instruction, "%s %c%d", get_mnemonic(tmp->text), (offset2 > labels[i].offset) ? '-' : '+',(offset2 > labels[i].offset) ? offset2 - labels[i].offset: labels[i].offset - offset2);
			ks_asm(ks, instruction, 0, &opcodes, &size, &count);
			memcpy(tmp->opcodes, opcodes, size);
		}

		offset += tmp->opcode_len;
		tmp = tmp->next;
	}
}
		
void init_memory() {

	instruction_t *tmp;
	uc_mem_map(uc, regs.eip, PAGE_SZ, UC_PROT_ALL);//maybe change to use dynamically allocated space so not too much memory is mapped at once
	
	for(tmp=inst; tmp; tmp=tmp->next) {
		uc_mem_write(uc, tmp->address, tmp->opcodes, tmp->opcode_len);
	}
	uc_mem_map(uc, regs.esp - PAGE_SZ, PAGE_SZ, UC_PROT_ALL);

}
void display(char *buff){
	char *prompt = "Press Enter to Exit";
	int i = 0;
	
	if(strlen(buff) == 0)
		printsegments(0);
		//display everything
	else if(!strcasecmp(buff, "data"))
	{
		printsegments(1);
		
	}
	else if(!strcasecmp(buff, "bss"))
	{
		printsegments(2);
	}
	else if(!strcasecmp(buff, "text"))
	{
		printsegments(3);
	}
	else if(!strcasecmp(buff, "define")){
		printsegments(4);
	}
	else
		mvwprintw(console.content, i++, 9, "ERROR Unkown Display: %s not valid", buff);
	
	draw_window(&code);
	mvwprintw(console.content, i, 9, "Press Enter to Exit");

	wgetnstr(console.content, buff, 0);
}

void scrolls(int val){//scrolls screen, also func name scroll was taken
	if(inst_index == NULL)
		inst_index = get_inst_index(regs.eip);
	instruction_t *tmp = inst_index;
	if(val == 0)
		inst_index = get_inst_index(regs.eip);
	else{
		for(; val!=0; (val < 0) ? val++ : val--)
		{
			while(1){
				if(val < 0){
					if(tmp->prev != NULL)
						tmp = tmp->prev;
					else
						break;
				}
				else{
					if(tmp->next != NULL)
						tmp = tmp->next;
					else
						break;
				}

				if(tmp->opcode_len)
					break;
			}
			if((val < 0 ? tmp->prev == NULL : tmp->next == NULL))
				break;
		}
	
		inst_index = get_inst_index(tmp->address);
	}	

	render();
}

void usage(char *arg0) {

	printf("Usage: %s [OPTIONS] <file.s>\n", arg0);
	printf("A simple 32-bit x86 emulator\n");
	printf("\n");
	printf("  %-10s %s\n", "-h", "Print this help menu");
	printf("\n");
	printf("(c)opyleft Andrew Kramer, 2017, <andrew@jmpesp.org>\n");
}

void printsegments(int x){//TODO add scrolling later
	int i = 0;
	Segments *walker;
	wattron(code.content, COLOR_PAIR(4));
	
	if(x < 2){//data
		mvwprintw(code.content, i, 0, "  %s", "segment .data");
		i++;

		walker = dataseg;

		
		while(walker != NULL)
		{
			if(walker->type == 1)
				mvwprintw(code.content, i, 0, "   %x   %s\t%s\t%d",walker->address, walker->name, "dd", walker->value);
			else	
				mvwprintw(code.content, i, 0, "   %x   %s\t%s\t%s",walker->address, walker->name, "db", walker->original);
			i++;
			walker = walker->next;
			
		}
	}
	if(x == 0 || x == 2 ){//bss
		mvwprintw(code.content, i, 0, "  %s", "segment .bss");
		i++;
		walker = bssseg;
			
		while(walker != NULL){
			mvwprintw(code.content, i, 0, "   %x%7s\t%s\t%d",walker->address, walker->name, (walker->type == 1 ? "resd" : "resb"), walker->size);
			i++;
			walker = walker->next;
		}
	}
	if(x == 0 || x == 3){//text
		
		mvwprintw(code.content, i, 0, "  %s", "segment .text");
		i++;
	
		for(int t = 0; t < text_count; t++, i++)
			mvwprintw(code.content, i, 0, "\t%s", text[t].string);
	}
	if(x == 4 || x == 0){//define
		
		mvwprintw(code.content, i, 0, "  %s", "\%define ");
		i++;

		struct define *walker = define;
		while(walker != NULL){
			switch(walker->type){
				case 1: mvwprintw(code.content, i, 0, "\t%s   %d", walker->name, walker->integer);
					break;
				case 2: mvwprintw(code.content, i, 0, "\t%s   %s", walker->name, walker->string);
					break;
				case 3: mvwprintw(code.content, i, 0, "\t%s   %c", walker->name, walker->character);
					break;
			}
			walker = walker->next;
		}

	}
	wattroff(code.content, COLOR_PAIR(4));
}

void render() {

	int i, j;
	int offset;
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

	if(regs.eax != oldregs.eax)
		wattron(registers.content, COLOR_PAIR(3));
	mvwprintw(registers.content, 0, 0, "EAX: %08x\n", regs.eax);
	if(regs.eax != oldregs.eax)
		wattroff(registers.content, COLOR_PAIR(3));

	if(regs.ebx != oldregs.ebx)
		wattron(registers.content, COLOR_PAIR(3));
	mvwprintw(registers.content, 1, 0, "EBX: %08x\n", regs.ebx);
	if(regs.ebx != oldregs.ebx)
		wattroff(registers.content, COLOR_PAIR(3));

	if(regs.ecx != oldregs.ecx)
		wattron(registers.content, COLOR_PAIR(3));
	mvwprintw(registers.content, 2, 0, "ECX: %08x\n", regs.ecx);
	if(regs.ecx != oldregs.ecx)
		wattroff(registers.content, COLOR_PAIR(3));

	if(regs.edx != oldregs.edx)
		wattron(registers.content, COLOR_PAIR(3));
	mvwprintw(registers.content, 3, 0, "EDX: %08x\n", regs.edx);
	if(regs.edx != oldregs.edx)
		wattroff(registers.content, COLOR_PAIR(3));
	
	if(regs.esi != oldregs.esi)
		wattron(registers.content, COLOR_PAIR(3));
	mvwprintw(registers.content, 4, 0, "ESI: %08x\n", regs.esi);
	if(regs.esi != oldregs.esi)
		wattroff(registers.content, COLOR_PAIR(3));
	
	if(regs.edi != oldregs.edi)
		wattron(registers.content, COLOR_PAIR(3));
	mvwprintw(registers.content, 5, 0, "EDI: %08x\n", regs.edi);
	if(regs.edi != oldregs.edi)
		wattroff(registers.content, COLOR_PAIR(3));
	
	if(regs.ebp != oldregs.ebp)
		wattron(registers.content, COLOR_PAIR(3));
	mvwprintw(registers.content, 6, 0, "EBP: %08x\n", regs.ebp);
	if(regs.ebp != oldregs.ebp)
		wattroff(registers.content, COLOR_PAIR(3));
	
	if(regs.esp != oldregs.esp)
		wattron(registers.content, COLOR_PAIR(3));
	mvwprintw(registers.content, 7, 0, "ESP: %08x\n", regs.esp);
	if(regs.esp != oldregs.esp)
		wattroff(registers.content, COLOR_PAIR(3));
	
	if(regs.eip != oldregs.eip)
		wattron(registers.content, COLOR_PAIR(3));
	mvwprintw(registers.content, 8, 0, "EIP: %08x\n", regs.eip);
	if(regs.eip != oldregs.eip)
		wattroff(registers.content, COLOR_PAIR(3));
	
	draw_window(&registers);
	for(i=stack.height-1,j=(regs.esp < (ESP_START-(stack.height-2)*4)) ? (ESP_START-(ESP_START-(stack.height -2)*4-regs.esp)) : ESP_START; i>=0; i--,j-=4) {

		if(j==ESP_START) {
			memset(mem, '\0', 4);
		} else {
			uc_mem_read(uc, j, mem, 4);
		}

		if(j == regs.esp && regs.esp == regs.ebp) {
			strcpy(ptrstr, "BS>");
		} else if(j == regs.esp) {
			strcpy(ptrstr, " S>");
		} else if(j == regs.ebp) {
			strcpy(ptrstr, " B>");
		} else {
			ptrstr[0] = '\x00';
		}


		if(j >= regs.esp)
			wattron(stack.content, COLOR_PAIR(2));
		mvwprintw(stack.content, i, 0, "%-4s%08x %02hhx%02hhx%02hhx%02hhx",
			ptrstr, j, mem[0], mem[1], mem[2], mem[3]);
		if(j >= regs.esp)
			wattroff(stack.content, COLOR_PAIR(2));
	}
	draw_window(&stack);
	offset = 0;
	tmp = inst;
	int fix = 0;
	unsigned int fix2 = 0; 
	int index = 0;
	//if(count_instructions(inst) + label_count < ) {
		if(inst_index == NULL || inst_index == 0)
		{
			fix = 0;
		}
		else{
			fix = inst_index->index;
			fix2 = inst_index->address;
		}
		for(i=0; i<fix-code.height/2; i++) {
			index++;
			tmp = tmp->next;
		}
	//}

		i = 0;	
	if(inst_index == NULL || inst_index == 0){
		printsegments(0);
		i += 3 + text_count + bss_count + data_count;
	}
	int l = -1, m = 0, t = 0;
	instruction_t* tmp2 = inst;
	for(; tmp && i<code.height; i++,tmp=tmp->next) {//prints for the code console
			
				
		while(labels[m].index < index && m < label_count)
			m++;
			if(labels[m].index == index) {
				wattron(code.content, COLOR_PAIR(4));
				mvwprintw(code.content, i, 0, "% *s%s:", 36, " ", labels[m].text);
				wattroff(code.content, COLOR_PAIR(4));
				i++;
				m++;
			}
		
		memset(opcodes, '\0', 32);
		for(j=0; j<tmp->opcode_len; j++) {
			sprintf(opcode, "%02hhx ", tmp->opcodes[j]);
			strcat(opcodes, opcode);
		}
		if(tmp->opcode_len){

			if(tmp->address == regs.eip)
				wattron(code.content, COLOR_PAIR(2));
			else if(tmp->breakpoint)
				wattron(code.content, COLOR_PAIR(5));
			mvwprintw(code.content, i, 0,
				"%c%c  %08x %-20s %s\n",
				(tmp->address==regs.eip ? '>' : ' '), (tmp->address== fix2 ? '-' : ' '),
				tmp->address == 0xffffffff ? 0 : tmp->address, opcodes, tmp->text);
			if(tmp->address == regs.eip)
				wattroff(code.content, COLOR_PAIR(2));
			else if(tmp->breakpoint)
				wattroff(code.content, COLOR_PAIR(5));
		}
		else{
			wattron(code.content, COLOR_PAIR(3));
			mvwprintw(code.content, i, 0, "%8s", tmp->text);
			wattroff(code.content, COLOR_PAIR(3));
		}
		index++;
		
	}
	draw_window(&code);

	mvwprintw(console.content, 0, 0, "%s ", PROMPT);
	draw_window(&console);

}

void printhelp(){//TODO add scrolling later
	
	char buff[1] = "\0";
	draw_window(&code);
	init_window(&code, 0, REGISTER_WIDTH +code.width/6, parent_y - CONSOLE_HEIGHT, parent_x - REGISTER_WIDTH - STACK_WIDTH-code.width/3, "CODE");
	int i = code.width/2 - 30;
	wattron(code.content, COLOR_PAIR(1));
	mvwprintw(code.content, 0, i, 
	"Welcome To The Assembly Emulator (assemu)\n\n"

	"To the left you will see the available registers present along with the values they hold\n throughout the program's runtime\n"
	"To the right you will see the current representation of the stack, as the program runs\n values will be pushed and popped from the stack\n"
	"Where you are reading currently is the code house, the place where you can see what command\n is being run as well as other bits of information\n"
	"Below where you typed help at is the console, all input and output will go through there and\n a list of commands follows:\n"

	"\trun, continue, or go  -  starts the program and goes until a breakpoint, end of file, error,\n external function call, or error\n\n"
	"\tnext, step, or ''  -  goes to the next instruction unless a number is given after then will execute\n that many instructions\n\n"
	"\tskip  -  skips over the current instruction and goes to the next, instuction still executes\n\n"
	"\tbreakpoint, break, or bp  -  sets a breakpoint at the address location given after the command,\n example: breakpoint 0x4000023 (all values are read as hex)\n\n"
	"\tsroll x  -  scrolls though the instrucion set x many instructions negative goes up and positive\n goes down, with 0 going back to the original instrucation\n\n"
	"\tdisplay s  - used to display the segments as well as any defined variables, leaving blank shows\n everything, but saying only one segment will only return that segment. example display data\n\n"
	"\tresize  -  realigns the size of the screen to the window size, use if screen has changed\n\n"
	"\thelp  -  displays this help screen \n\n"
	"\tquit or exit  -  quits the program\n\n"

	"Since emulating external funciton calls is hard, all external function calls are hard codded in,\n so if you would like additional functions please ask\n"
	"The available functions currently are: printf, scanf, strlen, atoi, strcmp, read_char, read_int,\n print_nl, print_int, print_char, print_string, putchar, getchar, puts, and gets\n\n"

	"Finally asemu looks better at full screen but can still operate at smaller sizes\n"
	);
	wattroff(code.content, COLOR_PAIR(1));
	wrefresh(code.content);

	mvwprintw(console.content, 0, 0, "Press ENTER to exit");
	wgetnstr(console.content, buff, 0);
	
	init_window(&code, 0, REGISTER_WIDTH, parent_y - CONSOLE_HEIGHT, parent_x - REGISTER_WIDTH - STACK_WIDTH, "CODE");
}

void resize(){

	getmaxyx(stdscr, parent_y, parent_x);

	init_window(&registers, 0, 0, parent_y - CONSOLE_HEIGHT, REGISTER_WIDTH, "REGISTERS");
	init_window(&stack, 0, parent_x - STACK_WIDTH, parent_y - CONSOLE_HEIGHT, STACK_WIDTH, "STACK");
	init_window(&code, 0, REGISTER_WIDTH, parent_y - CONSOLE_HEIGHT, parent_x - REGISTER_WIDTH - STACK_WIDTH, "CODE");
	init_window(&console, parent_y - CONSOLE_HEIGHT, 0, CONSOLE_HEIGHT, parent_x, "CONSOLE");

}

int main(int argc, char *argv[]) {

	int opt;
	uc_err err;
	unsigned char interupt;
	unsigned int autopilot;
	set_tabsize(4);
	ind = 0;	
	//signal(SIGSEGV, crash_handler);
	bool compiler = 1;

	while((opt = getopt(argc, argv, "ho")) != -1) {
		switch(opt) {
			case 'h':	// help
				usage(argv[0]);
				return 0;
			case 'o':	// compiler
				compiler--;
				break;
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
	FILE *fp = fopen(argv[optind], "r");
	if(fp == NULL) {
		printf("ERROR: failed to open file\n");
		endwin();
		return 0;
	}

	if(compiler){
		char *compstr = malloc(35+strlen(argv[optind]));
		strcpy(compstr, "nasm -f elf -F dwarf ");
	        strcat(compstr, argv[optind]);
		strcat(compstr, " 2>/dev/null");
			
	        if(system(compstr)){
			printf("\n\033[1;31mERROR \033[0m: file \033[32m%s\033[0m could not compile\n", argv[optind]);
			printf("run \"\033[36mnasm -f elf -F dwarf %s\033[0m\" for the error\n", argv[optind]);
			printf("or run asemu with -c flag to ignore compilation (not recommended)\n\n");
			return 0;
		}
	}

	if(ks_open(KS_ARCH_X86, KS_MODE_32, &ks) != KS_ERR_OK) {
		printf("ERROR: Failed to initialize Keystone engine\n");
		return 0;
	}
	
	ks_option(ks, KS_OPT_SYNTAX, KS_OPT_SYNTAX_NASM);
	ks_option(ks, KS_OPT_SYM_RESOLVER, (size_t)sym_resolver);

	if(uc_open(UC_ARCH_X86, UC_MODE_32, &uc) != UC_ERR_OK) {
		printf("ERROR: Failed to initialize Unicorn engine\n");
		return 0;
	}

	initscr();
	
	resize();

	start_color();
	init_pair(1, COLOR_GREEN, COLOR_BLACK);
	init_pair(2, COLOR_BLACK, COLOR_GREEN);
	init_pair(3, COLOR_RED, COLOR_BLACK);
	init_pair(4, COLOR_BLUE, COLOR_BLACK);
	init_pair(5, COLOR_YELLOW, COLOR_BLUE);
	
	init_regs();
	
	data_size = 0;

	
	inst = NULL;
	init_instructions(fp, regs.eip);
	inst_index = NULL;
	
	if(inst == NULL) {
		printf("ERROR: failed to failed to parse instructions\n");
		endwin();
		return 0;
	}
	
	init_memory();
	
	autopilot = regs.eip;
	int counter = 0;	
	char buff[1024] = {'\0'};
	for(;;) {
		memset(buff, 0, 32);
		render();
		
		if(counter--==0){
			autopilot = 1;
		}
		if(autopilot == 1 || autopilot == regs.eip || inst_index->breakpoint) {
			counter = 0;
			while(1){
				autopilot = regs.eip;
				wgetnstr(console.content, buff, 1024);
		
				if(checkbreakpoint(buff))
				{
					breakpoint(buff);
				}
				else if(checkscroll(buff)){
					scrolls(atoi(get_label(buff)));
				}
				else if(checknext(buff)) {
					if(strlen(get_label(buff)) > 0)
					{
						counter = atoi(get_label(buff));
						autopilot = 0;
					}
					else
						autopilot = 1;
					buff[0] = '\0';
					break;
				}
				else if(checkdisplay(buff)){
					display(get_label(buff));
					render();
				}
				else if(!strncasecmp(buff, "resize", 6))
				{
					resize();
					inst_index = get_inst_index(regs.eip);
					render();
				}
				else if(checkrun(buff)){
					counter = 999;
					autopilot = 0;
					buff[0] = '\0';
					break;
				}
				else if(!strcasecmp(get_mnemonic(buff), "exit") || !strcasecmp(get_mnemonic(buff), "quit"))
				{
					endwin();
					return 0;
				}
				else if(!strcasecmp(get_mnemonic(buff), "skip")){
					inst_index = get_inst_index(regs.eip);
					autopilot = regs.eip + inst_index->opcode_len;
					counter = 999;
					break;
				}
				else if(!strcasecmp(get_mnemonic(buff), "help")){
					resize();
					render();
					printhelp();
					render();

				}	
				else{
					render();

				}
				buff[0] = '\0';
			}
		}
	
		oldregs = regs;
		inst_index = get_inst_index(regs.eip);
		if(interupt = at_interupt()) {
		
			if(!handle_interupt(interupt)) {
				render();
				wgetnstr(console.content, buff, 1024);
				break;
			}
			autopilot = 1;
		} else if(err = uc_emu_start(uc, regs.eip, 0xffffffff, 0, 1)) {
				render();
				error(uc_strerror(err));
				wgetnstr(console.content, buff, 1024);
				break;
			}
		if(inst_index->ext)
			uc_reg_write(uc, UC_X86_REG_ESP, &regs.esp);
		render();
		if(inst_index->ext)
		{
			callcorrectfunction(inst_index);
			autopilot = 1;
		}

		inst_index = get_inst_index(regs.eip);
		
		if(inst_index == NULL) {
			render();
			error("Instruction pointer fell outside valid code");
			wgetnstr(console.content, buff, 1024);
			break;
		}
		
	}
	endwin();
	
	return 0;
}

