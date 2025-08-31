#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>

static inline int bit_length(const BIT_STRING_t& bs);
static bool realloc_and_zero(uint8_t** buf, int new_size);


int validate_or_fix_gnb_id_length(BIT_STRING_t* gnb_id_bs,
                                  int min_bits,
                                  int max_bits,
                                  int target_if_pad);
                                  
void stampaln(const char* msg, ...);