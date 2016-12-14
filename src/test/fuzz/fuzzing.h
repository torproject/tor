#ifndef FUZZING_H
#define FUZZING_H

int fuzz_init(void);
int fuzz_main(const uint8_t *data, size_t sz);

#endif /* FUZZING_H */
