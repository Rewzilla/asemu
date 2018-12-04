
CC		:= gcc
CXX		:= g++
CFLAGS	:= -g
LIBS	:= -lncurses -lkeystone -lcapstone -lunicorn -lpthread

all:
	$(CC) $(CFLAGS) -o asemu asemu.c $(LIBS) 
	mv asemu /usr/local/bin/asemu

uninstall:
	rm /usr/local/bin/asemu

clean:
	rm -rf *.o
	rm -rf asemu
