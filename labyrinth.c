// Labyrinth
// author: Maria Wysoglad
//
// This projects finds a way in k-dimensional labyrinth and 
// returns its length. 
// Labyrinth is coded by 4 lines: 1st contains its dimensions,
// 2nd coordinates of the start, 3rd coordinates of the finish
// and 4th contains a number that codes location of walls in 
// labyrinth (it may be hexadecimal number or code R - special
// five numbers that code another code).
// If input is incorrect, project is supposed to return "ERROR n",
// where n codes the line where the error occured, or 0 if there is
// memory error.
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#include "errors.h"
#include "input.h"
#include "bfs.h"

// <visited_and_walls> stores the data about walls in bitset form - each square
// has its unique value n, and if n-th bit in a table is set as 1,
// there is a wall at the square coded by this number. <visited_and_walls>
// is called this way, because later in <labyrinth> we are going to set
// a wall on each visited square in order to be able to do BFS
// (walls and visited squares are going to be marked by 1). 
uint16_t *visited_and_walls = NULL;
// <dimensions> stores the data about labyrinth size.
// <start> and <finish> stores the coordinates of starting and ending
// points.
size_t  *dimensions = NULL;
size_t *start = NULL;
size_t *finish = NULL;

// At the end of the program, function clears all stored data about
// the labyrinth.
void clear_all(void) {
    free(dimensions);
    free(visited_and_walls);
    free(start);
    free(finish);
}

int main() {
    atexit(clear_all);

    size_t dimensions_size;
    size_t start_size;
    size_t finish_size;
    size_t visited_and_walls_size = 0;

    // Function gets the data abouth the labyrinth.
    input(&dimensions, &start, &finish, &visited_and_walls, &dimensions_size,
    &start_size, &finish_size, &visited_and_walls_size);

    // Function counts the distance based on the stored data.
    labyrinth(dimensions, start, finish, visited_and_walls, &dimensions_size, 
    visited_and_walls_size);

    return 0;
}