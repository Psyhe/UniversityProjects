#include <stdio.h>
#include <stdbool.h>
#include <limits.h>
#include <stdint.h>
#include <ctype.h>
#include <stdlib.h>

#include "errors.h"
#include "input.h"

// <MODULO_32> is used to create walls in R.
#define MODULO2_32 4294967296
#define NOTHING 2

static size_t read_number(int *character, int line) {
    size_t number = 0;

    while (((*character) >= '0') && ((*character) <= '9')) {
        check_error_addition(number, (*character) - '0', line);
        number = (10 * number) + ((*character) - '0');
        (*character) = getchar();
    }

    return number;
}

// Function counts size of the labyrinth (n1n2...nk).
static size_t product(size_t *table, size_t size) {
    size_t product_new = 1;

    for (size_t i = 0; i < size; i++) {
        if (SIZE_MAX / table[i] < product_new) {
            error(MEMORY_ERROR);
            break;
        }
        product_new = table[i] * product_new;
    }

    return product_new;
}

// Function reads a line and stores the numbers in a table, 
// that is sent into the data storage, according to the line 
// which is read. Function also returns the size of stored
// data.
static size_t read_line(size_t **data, int line) {
    size_t *table = NULL;
    size_t n = 1;
    size_t counter = 1;
    size_t number;
    int character = getchar();

    while (character != '\n') {
        if ((character == EOF) || wrong_character(character)) {
            free(table);
            error(line);
        }

        if (counter >= n) {
            n = 2 * n;
            table = realloc(table, n * sizeof(size_t));
            if (table == NULL) {
                error(MEMORY_ERROR);
            }
        }

        if ((character >= '0') && (character <= '9')) {
            number = read_number(&character, line);
            // If a coordinate equals 0, dimension does not exist
            // and it is impossible to convert coordinates into
            // a number.
            if (number == 0) {
                free(table);
                error(line);
            }

            counter++;
            table[counter - 2] = number;
        }
        else {
            character = getchar();
        }
    }

    table = realloc(table, counter*sizeof(size_t));
    *data = table;

    return counter - 1;
}


// Function sets the walls in table <visited_and_walls>, based on R-code.
static void where_walls_for_R(uint16_t **visited_and_walls_pointer,
                              size_t visited_and_walls_size,
                              size_t *walls, size_t walls_size) {
    uint16_t *visited_and_walls = calloc((visited_and_walls_size/16+1),
                                         sizeof(uint16_t));

    for (size_t i = 1; i < walls_size; i++) {
        size_t x = walls[i];

        while ((x <= SIZE_MAX - MODULO2_32) && (x < visited_and_walls_size)) {
            visited_and_walls[x / 16] |= 1 << (x % 16);
            x = x + MODULO2_32;
        }
    }

    *visited_and_walls_pointer=visited_and_walls;
}

// Function changes code R into the code of walls.
// In table raw_data we have 5 numbers:
// a = raw_data[0], b = raw_data_1, m = raw_data[2],
// r = raw_data[3], s0 = raw_data[4].
// Numbers that code walls are w_i, which are defined by
// s_i, which are defined by expression s_i = (a * s_(i-1)+b) mod m,
// which in our code is defined as:
// (raw_data[0] * walls[i-1] + raw_data[1]) % raw_data[2].
static void count_numbers_R(uint16_t ** visited_and_walls, size_t *raw_data,
                            size_t visited_and_walls_size) {
    size_t *walls = malloc((raw_data[3] + 1)*sizeof(size_t));
    if (walls == NULL) {
        error(MEMORY_ERROR);
    }
    walls[0] = raw_data[4];

    // If (m==0), code does not work.
    if (raw_data[2] == 0) {
        free(walls);
        error(LINE_4);
    }

    for (size_t i = 1; i <= raw_data[3]; i++) {
        walls[i] = (raw_data[0] * walls[i-1] + raw_data[1]) % raw_data[2];
    }

    // Changes s_i into w_i.
    for (size_t i = 0; i <= raw_data[3]; i++) {
        walls[i] = walls[i] % visited_and_walls_size;
    }

    where_walls_for_R(visited_and_walls, visited_and_walls_size, walls,
                      raw_data[3]+1);
    free(walls);
}

// Function is an agent of reading a number in R - it checks
// errors and skips spaces until there is a digit. It means
// that number can be read.
static size_t read_R(int *character) {
    *character = getchar();
    if ((*character == EOF) || (*character == '\n')) {
        error(LINE_4);
    }

    while (!((*character <= '9') && (*character >= '0'))) {
        if_wrong_number(*character, LINE_4);
        *character = getchar();
    }

    return read_number(character, LINE_4);
}

// Fourth line contains 5 numbers, which code set of numbers.
// This function stores those 5 numbers in a table and later
// <count_numbers_R> changes code into another code.
static void fourthline_R(uint16_t **visited_and_walls,
                         size_t visited_and_walls_size) {
    size_t raw_data[5];
    int character;

    for (int i = 0; i < 5; i++) {
        raw_data[i] = read_R(&character);

        if (raw_data[i] > UINT32_MAX) {
            error(LINE_4);
        }

        // If line ends before fifth number, error occured.
        if (!(i == 4) && ((character == EOF) || (character == '\n'))) {
            error(LINE_4);
        }
    }

    count_numbers_R(visited_and_walls, raw_data, visited_and_walls_size);
    ending(character);
}


// Function sets the walls in table <visited_and_walls>. It also 
// returns an information if error occured.
static int where_walls_for_16(uint16_t **visited_and_walls_pointer,
                              size_t visited_and_walls_size,
                              int *walls, size_t walls_size) {
    uint16_t *visited_and_walls = calloc((visited_and_walls_size/16+1),
                                         sizeof(uint16_t));
    size_t i = 0;
    size_t j = walls_size;
    // <i4> stores number of a current bit in a given hexadecimal digit.
    size_t i4 = 0;

    // Function writes walls while there are
    // digits in a coding number.
    while ((i < visited_and_walls_size) && (j >= 1)) {
        // Each digit in hexadecimal system codes 4 bits,
        // so a digit has to be changed after each 4 bits in
        // <visited_and_walls>.
        while ((i4 < 4) && (i < visited_and_walls_size)) {
            if (walls[j - 1] % 2 == 0) {
                visited_and_walls[i / 16] &= ~(1 << (i % 16));
            }
            else {
                visited_and_walls[i / 16] |= 1 << (i % 16);
            }
            walls[j - 1] = walls[j - 1] / 2;
            i++;
            i4++;
        }
        i4 = 0;
        j--;
    }

    *visited_and_walls_pointer = visited_and_walls;

    // If hexadecimal number exceeds a data stored in visited_and_walls, 
    // it cannot code a bit accurately and there is error.
    if (walls[0] > 0) {
        return LINE_4;
    }
    return 0;
}

// Function converts a hexadecimal digit in ASCII
// into its value in decimal system (int).
static int conversion_16(int character) {
    if ((character >= '0') && (character <= '9')) {
        return character - '0';
    }
    else if ((character >= 'a') && (character <= 'f')) {
        return character - 'a' + 10;
    }
    else if ((character >= 'A') && (character <= 'F')) {
        return character - 'A' + 10;
    }
    else {
        error(LINE_4);
        return 0;
    }
}

// Function reads a hexadecimal number - it changes 
// a string into a table of digits (walls) stored in type int.
// Each digit is between 0 to 15, where 0 is 0 and F(or f) is 15.
static void fourthline_16(uint16_t **visited_and_walls,
                          size_t visited_and_walls_size) {
    int *walls = NULL;
    int character = getchar();
    if (!(((character>='0') && (character<='9')) 
        || ((character>='a') && (character <= 'f')) 
        || ((character>='A') && (character <= 'F')))) {
        error(LINE_4);
    }
    size_t n = 1;
    size_t counter = 0;

    walls = realloc(walls, n * sizeof(size_t));
    if (walls == NULL) {
        error(MEMORY_ERROR);
    }

    while (((character>='0') && (character<='9')) 
           || ((character>='a') && (character <= 'f')) 
           || ((character>='A') && (character <= 'F'))) {
        counter++;
        walls[counter - 1] = conversion_16(character);
        character = getchar();

        if (counter >= n) {
            n = 2 * n;
            walls = realloc(walls, n*sizeof(size_t));
            if (walls == NULL) {
                error(MEMORY_ERROR);
            }
        }
    }

    walls = realloc(walls, (counter)*sizeof(size_t));
    // If error occurs, memory needs to be freed before exit, <if_error>
    // stores information about special exit.
    int if_error = where_walls_for_16(visited_and_walls, 
                                      visited_and_walls_size, walls, counter);
    free(walls);

    if (if_error != 0) {
        error(if_error);
    }

    ending(character);  
}

// Function reads the fourth line, which is coded differently -
// it may contain hexadecimal number or special coded numbers R.
static void fourth_line(uint16_t **visited_and_walls,
                        size_t visited_and_walls_size) {
    int character = getchar();
    int previous_character = NOTHING;

    while ((character!= '\n') && (isspace(character) || (character == '0'))) {
        previous_character = character;
        character = getchar();
    }

    // Combination '0x' means that number is hexadecimal.
    if ((character == 'x') && (previous_character == '0')) {
        fourthline_16(visited_and_walls, visited_and_walls_size);
    }
    // 'R' means that number is coded by special system.
    else if (character == 'R') {
        fourthline_R(visited_and_walls, visited_and_walls_size);
    }
    else {
        error(LINE_4);
    }
}

// Function collects the data about the labyrinth. It coordinates
// all the functions in input.c file.
void input(size_t **dimensions, size_t **start, size_t **finish,
           uint16_t **visited_and_walls, size_t *dimensions_size,
           size_t *start_size, size_t *finish_size,
           size_t *visited_and_walls_size) {
    *dimensions_size = read_line(dimensions, 1);
    *start_size = read_line(start, 2);
    *finish_size = read_line(finish, 3);
    // <visited_and_walls_size> is equal to n1n2..nk, where n_i is the size
    // of labyrinth in i-th dimension.
    *visited_and_walls_size = product(*dimensions, *dimensions_size);
    
    fourth_line(visited_and_walls, *visited_and_walls_size);

    if_error_size(*dimensions_size, *start_size, *finish_size);
    if_error_comparison(*dimensions, *start, *finish, *dimensions_size);
}