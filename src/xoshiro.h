#ifndef _XOSHIRO_H
#define _XOSHIRO_H

#include <stdint.h>


uint64_t next (void);
void seed_generator (uint64_t *seeds);
void jump (void);
void long_jump (void);

#endif // _XOSHIRO_H