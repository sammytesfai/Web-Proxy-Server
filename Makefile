asgn		= proj
SRC			= ./src/Syscalls.c ./src/misc.c
OBJ			= ./bin/Syscalls.o ./bin/misc.o
HEADER		= ./src/Syscalls.h ./src/misc.h
COMPILE		= gcc -c -g -std=c11 -Wall
LINK		= gcc -o
REMOVE		= rm -f
MEMCHECK	= valgrind --leak-check=full

all			:  			myproxy

myproxy		:			bin/myproxy.o $(OBJ) ./bin/proxy_manager.o
						$(LINK) ./bin/myproxy -lpthread -lssl -lcrypto ./bin/myproxy.o $(OBJ) ./bin/proxy_manager.o

bin/myproxy.o	:		./src/myproxy.c $(HEADER) ./src/proxy_manager.h
						$(COMPILE) -D_GNU_SOURCE ./src/myproxy.c
						mv *.o bin

bin/proxy_manager.o:	./src/proxy_manager.c $(HEADER)
						$(COMPILE) -D_GNU_SOURCE ./src/proxy_manager.c
						mv *.o bin

$(OBJ)	:				$(SRC) $(HEADER)
						$(COMPILE) -D_GNU_SOURCE $(SRC)
						mv *.o bin

clean	:
						$(REMOVE) ./bin/myproxy ./bin/*.o ./bin/out* lab$(asgn)-stesfai.tar.gz index.html* out*

tar		: 			
						@tar czvf $(asgn)-stesfai.tar.gz .
