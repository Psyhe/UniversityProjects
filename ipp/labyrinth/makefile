.PHONY: all clean
all: labyrinth

labyrinth: labyrinth.o bfs.o input.o errors.o

labyrinth.o: labyrinth.c errors.h input.h bfs.h
	gcc -Wall -Wextra -Wno-implicit-fallthrough -std=c17 -O2 -c labyrinth.c

bfs.o: bfs.c bfs.h input.h errors.h
	gcc -Wall -Wextra -Wno-implicit-fallthrough -std=c17 -O2 -c bfs.c

input.o: input.c input.h errors.h
	gcc -Wall -Wextra -Wno-implicit-fallthrough -std=c17 -O2 -c input.c

errors.o: errors.c errors.h
	gcc -Wall -Wextra -Wno-implicit-fallthrough -std=c17 -O2 -c errors.c


clean:
	rm labyrinth.o
	rm labyrinth
	rm input.o
	rm errors.o
	rm bfs.o
