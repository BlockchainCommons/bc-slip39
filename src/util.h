//
//  util.h
//
//  Copyright © 2020 by Blockchain Commons, LLC
//  Licensed under the "BSD-2-Clause Plus Patent License"
//

#ifndef UTIL_H
#define UTIL_H

#include <stddef.h>

size_t slip39_word_count_for_bytes(size_t bytes);
size_t slip39_byte_count_for_words(size_t words);

#endif /* UTIL_H */
