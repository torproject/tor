#include <stdio.h>

void print_array(size_t size, uint8_t array[size], char *name) {
  printf("Array %s:\n", name);
  printf("[");
  for (size_t i = 0; i < size; i++) {
    printf("%u,", array[i]);
  }
  printf("]\n");
  return;
}
