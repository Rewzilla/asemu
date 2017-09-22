
CC		:= gcc
CXX		:= g++
CFLAGS	:= -g
LIBS	:= -lncurses -lkeystone -lcapstone -lunicorn -lpthread

all:
	$(CC) $(CFLAGS) -o asemu asemu.c $(LIBS)

clean:
	rm -rf *.o
	rm -rf asemu
