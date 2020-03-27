//
//  util.h
//
//  Copyright © 2020 by Blockchain Commons, LLC
//  Licensed under the "BSD-2-Clause Plus Patent License"
//

#ifndef UTIL_H
#define UTIL_H

#define RADIX_BITS 10

#define bytes_to_words(n)  ( ( (n) * 8 + RADIX_BITS-1) / RADIX_BITS)
#define words_to_bytes(n)  ( ( (n) * RADIX_BITS ) / 8)

#endif /* UTIL_H */
