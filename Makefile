
CC		:= gcc
CXX		:= g++
CFLAGS	:= -g
LIBS	:= -lncurses -lkeystone -lcapstone -lunicorn -lpthread

all:
	$(CC) $(CFLAGS) $(LIBS) -o asemu asemu.c

clean:
	rm -rf *.o
	rm -rf asemu