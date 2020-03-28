#include "util.h"

#define RADIX_BITS 10

size_t slip39_word_count_for_bytes(size_t bytes) {
  return (bytes * 8 + RADIX_BITS - 1) / RADIX_BITS;
}

size_t slip39_byte_count_for_words(size_t words) {
  return (words * RADIX_BITS) / 8;
}
