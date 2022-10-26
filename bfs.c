#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>

#include "errors.h"
#include "bfs.h"

#define DECOY 1
#define NOT_DECOY 0

// All functions till <remove_queue> code various queue features.
struct list  {
    size_t value;
    int if_decoy;
    struct list *next;
};
typedef struct list List;

typedef struct queue {
    List *front;
    List *rear;
} Queue;

static bool empty_queue(Queue q) {
    if (q.front == NULL) {
        return 1;
    }
    else {
        return 0;
    }
}

static int if_decoy_queue(Queue q) {
    if (!empty_queue(q)) {
        return q.front->if_decoy;
    }
    else {
        return 0;
    }
}

// <x> codes the valueue, <y> codes if it is a decoy.
static void push_queue(Queue *q, size_t x, int y) {
    List *temp = malloc(sizeof(List));
    if (temp == NULL) {
        error(MEMORY_ERROR);
    }

    temp->value = x;
    temp->if_decoy = y;
    if (q->front == NULL) {
        q->front = temp;
        q->rear = q->front;
    }
    else {
        (q->rear)->next = temp;
        q->rear = (q->rear)->next;
    }
}

static size_t pop_queue(Queue *q) {
    if (!empty_queue(*q)) {
        List *temp = q->front;
        size_t x = (q->front)->value;

        if (q->front == q->rear) {
            q->front = NULL;
            q->rear = NULL;
        }
        else {
            q->front = (q->front)->next;
        }

        free(temp);
        return x;
    }
    else {
        return 0;
    }
}

static void remove_queue(Queue *q) {
    while (!empty_queue(*q)) {
        pop_queue(q);
    }

    (*q).front = NULL;
    (*q).rear = NULL;
}

// Function pushes into queue neighbours of a given square, if they are
// actually their neighbours (e. g. we cannot push a neighbour
// if a given square is on the edge).
static void push_neighbours(Queue *q, size_t current, size_t dimensions_size,
                            size_t *dimensions, size_t visited_and_walls_size) {
    // In a given dimension a square have 2 neighbours, I called them
    // <neighbour_low> and <neighbour_high>.
    size_t neighbour_high;
    size_t neighbour_low;
    size_t stage = 1;
    size_t stage_prev =1;
    // A <neighbour_low> is actually a neighbour only
    // if integer part of <current>/<stage> is equal to integer part
    // of <neighbour_low>/<stage> (<current> and <neighbour_low> are
    // unique numbers of squares coded by their coordinates). Analogiously with 
    // <neighbour_high>.
    for (size_t i = 0; i < dimensions_size; i++) {
        stage = stage * dimensions[i];

        if ((current >= stage_prev) && 
            (((current - stage_prev) / stage) == (current / stage))) {
            neighbour_low = current - stage_prev;
            push_queue(q, neighbour_low, NOT_DECOY);
        }
        if ((current <= (visited_and_walls_size - stage_prev)) &&
            (((current + stage_prev) / stage) == (current / stage))) {
            neighbour_high = current + stage_prev;
            push_queue(q, neighbour_high, NOT_DECOY);
        }
        stage_prev = stage;
    }

}

// We can push neighbours only if current square does not have a wall
// or was already visited.
static void searching(Queue *q, size_t current, size_t *dimensions_size,       
                      uint16_t *visited_and_walls, size_t *dimensions,
                      size_t visited_and_walls_size) {
    if ((visited_and_walls[current / 16] & (1 << (current % 16))) == 0) {
        visited_and_walls[current / 16] |= 1 << (current % 16);
        push_neighbours(q, current, *dimensions_size, dimensions,
                        visited_and_walls_size);
    }
}

// This function looks for the distance between start and finish by using 
// BFS algorithm.
// <way> stores the information if there is a way between start and finish.
static size_t BFS(uint16_t *visited_and_walls, size_t start, size_t finish,
                  size_t *dimensions, size_t *dimensions_size, bool *way,
                  size_t visited_and_walls_size) {
    size_t current = start;
    size_t distance = 0;
    int check;
    int decoy = 0;

    Queue queue_bfs;
    queue_bfs.front = NULL;
    queue_bfs.rear = NULL;
    // Decoys inditace the beginning and ending of a level.
    push_queue(&queue_bfs, DECOY, DECOY);

    while (((current != finish) && (decoy != 2)) && !(empty_queue(queue_bfs))) {
        if (decoy == 0) {
            searching(&queue_bfs, current, dimensions_size, visited_and_walls, 
                      dimensions, visited_and_walls_size);
        }

        check = if_decoy_queue(queue_bfs);

        if (check == 1) {
            // When we find a decoy, it means that we've checked the entire
            // level, so the distance is definietly greater than our current
            // distance, so we add (distance++), and we push a new decoy to
            // leave information for the future.
            push_queue(&queue_bfs, DECOY, DECOY);
            current = pop_queue(&queue_bfs);
            distance++;
            decoy++;
        }
        else {
            current = pop_queue(&queue_bfs);
            *way = true;
            decoy = 0;
        }
    }

    // If there are 2 decoys next to each other, it means that we've 
    // visited the whole accessible labyrinth and there is no
    // way to finish.
    if (decoy == 2) {
        *way = false;
    }
    remove_queue(&queue_bfs);
    
    return distance;
}

// Function changes coordinates into one number that codes
// the location of a square in one-dimensional table.
// It uses the formula:
// number = (z1-1) + (z2-1)*n1 + ... + (zk-1)n1n2...n(k-1),
// where z_i is a coordinate and n_i is size of i_th dimension.
static size_t marked_square(size_t *table, size_t table_size,
                            size_t *dimensions) {
    size_t square = 0;
    size_t stage = 1;

    for (size_t i = 0; i < table_size; i++) {
        if (table[i] != 0) {
            square = square + (table[i] - 1) * stage;
            stage = stage * dimensions[i];
        }
    }
    return square;
}

// Function writes the answer.
static void out(bool way, size_t distance) {
    if (way) {
        printf("%zu\n", distance);
    }
    else {
        printf("NO WAY\n");
    }
}

// Function uses the stored data and coordinates all functions needed
// to find a way in labyrinth.
void labyrinth(size_t *dimensions, size_t *start, size_t *finish,
               uint16_t *visited_and_walls, size_t *dimensions_size,
               size_t visited_and_walls_size) {
    bool way = 1;
    size_t distance = 0;
    // At the beginning, we need to know if there is a wall on starting
    // or ending square, in this case error occurs.
    size_t start_number = marked_square(start, *dimensions_size, dimensions);
    size_t finish_number = marked_square(finish, *dimensions_size, dimensions);
    check_wall_destination(visited_and_walls, start_number, LINE_2);
    check_wall_destination(visited_and_walls, finish_number, LINE_3);

    distance = BFS(visited_and_walls, start_number, finish_number, dimensions, 
    dimensions_size, &way, visited_and_walls_size);

    out(way, distance);
}