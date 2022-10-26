#ifndef ERRORS_H
#define ERRORS_H

#define LINE_1 1
#define LINE_2 2
#define LINE_3 3
#define LINE_4 4
#define LINE_5 5
#define MEMORY_ERROR 0

extern void error(int n);

extern void check_wall_destination(uint16_t *visited_and_walls,
                                   size_t place, int line);

extern void if_error_size(size_t dimensions_size, size_t start_size,
                          size_t finish_size);

extern void if_error_comparison(size_t *dimensions, size_t *start,
                                size_t *finish, size_t dimensions_size);

extern void check_error_addition(size_t number, int character, int line);

extern void check_err_multiplication(size_t n_i, size_t n_j);

extern int wrong_character(int character);

extern void if_wrong_number(int character, int line);

extern void ending(int character);

#endif
