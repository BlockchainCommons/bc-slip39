//
//  encoding.c
//
//  Copyright © 2020 by Blockchain Commons, LLC
//  Licensed under the "BSD-2-Clause Plus Patent License"
//

#include "slip39-errors.h"
#include "wordlist-english.h"
#include "util.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

//////////////////////////////////////////////////
// slip39 words
//
int16_t slip39_word_for_string(const char *word) {
    int16_t hi=WORDLIST_SIZE;
    int16_t lo=-1;

    while(hi>lo+1) {
        int16_t mid = (hi + lo) / 2;
        int16_t cmp = strcmp(word, wordlist[mid]);
        if(cmp > 0) {
            lo = mid;
        } else if(cmp < 0){
            hi = mid;
        } else {
            return mid;
        }
    }
    return -1;
}

const char *slip39_string_for_word(int16_t word) {
    if(word < 1024) {
        return wordlist[word];
    }

    return "";
}

char* slip39_strings_for_words(
  const uint16_t* words,
  size_t words_len
) {
  if(words_len == 0) {
    char* result = malloc(1);
    result[0] = '\0';
    return result;
  }

  size_t result_len = words_len; // space characters + nul
  const char* strings[words_len];
  for(int i = 0; i < words_len; i++) {
    strings[i] = slip39_string_for_word(words[i]);
    result_len += strlen(strings[i]);
  }
  char* result_string = malloc(result_len);
  result_string[0] = '\0';

  for(int i = 0; i < words_len; i++) {
    strcat(result_string, strings[i]);
    if(i != words_len - 1) {
      strcat(result_string, " ");
    }
  }

  return result_string;
}

uint32_t slip39_words_for_strings(
    const char *words_string,
    uint16_t *words,
    uint32_t words_length
) {
    char buf[16];
    uint8_t i=0;
    uint32_t j=0;


    const char *p = words_string;

    while(*p) {
        for(i=0; *p>='a' && *p<='z'; i++, p++) {
            if(i<15) {
                buf[i] = *p;
            } else {
                buf[15] = 0;
            }
        }
        if(i<15) {
            buf[i] = 0;
        }

        if(j<words_length) {
            int16_t w = slip39_word_for_string(buf);
            if(w<0) {
                printf("%s is not valid.\n", buf);
                return -1;
            } else {
                words[j] = w;
            }
        }
        j++;

        while(*p && (*p<'a' || *p>'z')) {
            p++;
        }
    }

    return j;
}

// convert a buffer of bytes into 10-bit mnemonic words
// returns the number of words written or -1 if there was an error
int32_t slip39_words_for_data(
    const uint8_t *buffer, // byte buffer to encode into 10-bit words
    uint32_t size,   // buffer size
    uint16_t *words, // destination for words
    uint32_t max     // maximum number of words to write
) {
    // The bottom bit of the last byte should always line up with
    // the bottom bit of the last word.

    // calculate the padding bits to add to the first byte to get
    // the last byte and the last word bottom bits to align
    //
    // bytes  5       4       3       2       1       0
    //        |...,...|...,...|...,...|...,...|...,...+
    //        X         X         X         X         *
    // words  4         3         2         1         0
    //
    // Looks like the number of zero bit padding to add
    // is 2x the remainder when your divide the number of
    // bytes by 5.

    uint32_t byte = 0;
    uint32_t word = 0;

    uint8_t bits = (size % 5) * 2; // padded so that bottom bits align

    uint16_t i = 0;

    if(max < slip39_word_count_for_bytes(size)) {
        printf("Not enough space to encode into 10-bit words \n");
        return -1;
    }

    while(byte < size && word < max) {
        while(bits < 10) {
            i =  i << 8;
            bits += 8;
            if(byte < size) {
                i = i | buffer[byte++];
            }
        }

        words[word++] = (i >> (bits-10));
        i = i & ((1<<(bits-10))-1);
        bits -= 10;
    }

    return word;
}

// returns the number of bytes written, or -1 if there was an error
int32_t slip39_data_for_words(
    const uint16_t *words, // words to decode
    uint32_t wordsize,       // number of words to decode
    uint8_t *buffer,          // space for result
    size_t size            // total space available
) {


    // The bottom bit of the last byte will always show up in
    // the bottom bit of the last word.

    // calculate the padding bits to add to the first byte to get
    // the last byte and the last word bottom bits to align
    //
    // bytes  5       4       3       2       1       0
    //        |...,...|...,...|...,...|...,...|...,...+
    //        X         X         X         X         *
    // words  4         3         2         1         0
    //


    uint32_t word = 0;
    int16_t bits = -2*(wordsize%4);

    // A negative number indicates a number of padding bits. Those bits
    // must be zero.
    if(bits <0 && (words[0] & (1023 << (10+bits)))) {
        return ERROR_INVALID_PADDING;
    }

    // If the number of words is an odd multiple of 5, and the top
    // byte is all zeros, we should probably discard it to get a
    // resulting buffer that is an even number of bytes

    uint8_t discard_top_zeros = (wordsize%4 == 0) && (wordsize & 4);
    uint32_t byte = 0;
    uint16_t i = 0;

    if(size < slip39_byte_count_for_words(wordsize)) {
        return ERROR_INSUFFICIENT_SPACE;
    }

    while(word < wordsize && byte < size) {
        i = (i << 10) | words[word++];
        bits += 10;

        if(discard_top_zeros && (i & 1020)==0) {
            discard_top_zeros = 0;
            bits -= 8;
        }

        while(bits >= 8 && byte < size) {
            buffer[byte++] = (i >> (bits -8));
            i = i & ((1<<(bits-8))-1);
            bits -= 8;
        }
    }

    return byte;
}
