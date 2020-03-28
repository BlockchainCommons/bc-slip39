//
//  encoding.h
//
//  Copyright © 2020 by Blockchain Commons, LLC
//  Licensed under the "BSD-2-Clause Plus Patent License"
//

#ifndef ENCODING_H
#define ENCODING_H

// returns the 10-bit integer that a string represents, or -1
// if the string is not a code word.
int16_t slip39_word_for_string(const char *word);

const char *slip39_string_for_word(int16_t word);

/**
 * Converts an array of 10-bit integers to a string of whitespace
 * delimited mnemonic words. Returns a C string that must be
 * freed by the caller.
 *
 * returns: A string. Must be freed by the caller.
 *
 * words: An array of 10-bit words.
 * words_len: The length of the array.
*/
char* slip39_strings_for_words(
  const uint16_t* words,
  size_t words_len
);

/**
 * converts a string of whitespace delimited mnemonic words
 * to an array of 10-bit integers. Returns the number of integers
 * written to the buffer.
 *
 * returns: number of ints written to the words buffer
 *
 * inputs: word_string: space delimited group of mnemonic words
 * words: space to return results
 * words_length: maximum size of the words buffer
 */

uint32_t slip39_words_for_strings(
    const char *words_string,
    uint16_t *words,
    uint32_t words_length
);

/**
 * convert a buffer of bytes into 10-bit mnemonic words
 *
 * returns: the number of words written or -1 if there was an error
 *
 * inputs: buffer: byte buffer to encode into 10-bit words
 *         size: size of the buffer
 *         words: destination for the words
 *         max: maximum number of words to write
 */

int32_t slip39_words_for_data(
    const uint8_t *buffer, // byte buffer to encode into 10-bit words
    uint32_t size,   // buffer size
    uint16_t *words, // destination for words
    uint32_t max     // maximum number of words to write
);

/**
 * convert a buffer of words into bytes
 *
 * returns: the number of bytes written or a negative number if there was an error
 *
 * inputs: words: array of words to decode
 *         wordsise: number of elements in the words array
 *         buffer: memory location to write results to
 *         size: maximum number of bytes in the buffer.
 */
int32_t slip39_data_for_words(
    const uint16_t *words, // words to decode
    uint32_t wordsize,       // number of words to decode
    uint8_t *buffer,          // space for result
    size_t size            // total space available
);

#endif /* ENCODING_H */
