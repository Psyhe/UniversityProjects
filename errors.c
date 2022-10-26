#include <stdio.h>
#include <limits.h>
#include <stdint.h>
#include <ctype.h>
#include <stdlib.h>

#include "errors.h"

#define LINE_1 1
#define LINE_2 2
#define LINE_3 3
#define LINE_4 4
#define LINE_5 5
#define MEMORY_ERROR 0

// In case error occured, program stops and returns error on standard error.
void error(int n) {
    fprintf(stderr,"ERROR %d\n", n);
    exit(1);
}

// Function checks if there is a wall on starting or ending square.
void check_wall_destination(uint16_t *visited_and_walls, size_t place,
                            int line) {
    if ((visited_and_walls[place / 16] & (1 << (place % 16) )) != 0) {
        error(line);
    }
}

// If there are different amount of coordinates in dimensions,
// start and finish, labyrinth cannot be built.
void if_error_size(size_t dimensions_size, size_t start_size,
                   size_t finish_size) {
    if (dimensions_size != start_size) {
        error(LINE_2);
    }
    else if (dimensions_size != finish_size) {
        error(LINE_3);
    }
}


// If coordinates of start or finish exceed dimensions, 
// labyrinth cannot be built.
void if_error_comparison(size_t *dimensions, size_t *start, size_t *finish, 
                         size_t dimensions_size) {
    for (size_t i = 0; i < dimensions_size; i++) {
        if (dimensions[i] <  start[i]) {
            error(LINE_2);
        }
        else if (dimensions[i] < finish[i]) {
            error(LINE_3);
        }
    }
}

// Function checks if new number will be able to be stored in memory.
void check_error_addition(size_t number, int character, int line) {
    if ((number >= (SIZE_MAX / 10)) && ((size_t)character > (SIZE_MAX % 10))) {
        error(line);
    }
}

// Function checks if new product will be able to be stored in memory.
void check_err_multiplication(size_t n_i, size_t n_j) {
    if (n_i > SIZE_MAX / n_j) {
        error(LINE_1);
    }
}

int wrong_character(int character) {
    if (!isspace(character) && !isdigit(character)) {
        return 1;
    }
    else {
        return 0;
    }
}

void if_wrong_number(int character, int line) {
    if (wrong_character(character)) {
        error(line);
    }
}

// After we read  a number in fourth line, we need to check
// if there are errors of input or a fifth line.
void ending(int character) {
    while ((character != '\n') && (character != EOF)) {
        if (!isspace(character)) {
            error(LINE_4);
        }
        character = getchar();
    }

    // The fifth line must be empty or does not exist.
    character = getchar();
    if (character != EOF) {
        error(LINE_5);
    }
}