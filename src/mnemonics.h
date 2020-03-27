//
//  mnemonics.h
//
//  Copyright © 2020 by Blockchain Commons, LLC
//  Licensed under the "BSD-2-Clause Plus Patent License"
//

#ifndef MNEMONICS_H
#define MNEMONICS_H

#include <stdlib.h>
#include "util.h"
#include "shard.h"
#include "group.h"

#define METADATA_LENGTH_WORDS 7
#define MIN_MNEMONIC_LENGTH_WORDS (METADATA_LENGTH_WORDS + bytes_to_words(MIN_STRENGTH_BYTES) )
#define MIN_STRENGTH_BYTES 16

/**
 * encrypt the share value of a shard
 *
 * inputs: shard: the shard to encrypt. The shard value is modified in place.
 *         passphrase: a NULL terminated ascii string to use to encrypt the shard
 */
void encrypt_shard(
    slip39_shard *shard,
    const char *passphrase
);

/**
 * decrypt the share value of a shard
 *
 * inputs: shard: the shard to decrypt. The shard value is modified in place.
 *         passphrase: a NULL terminated ascii string to use to decrypt the shard
 */
void decrypt_shard(
    slip39_shard *shard,
    const char *passphrase
);

/**
 * generate a set of shards that can be used to reconstuct a secret
 * using the given group policy, but encode them as mnemonic codes
 *
 * returns: the number of shards generated if successful,
 *          or a negative number indicating an error code when unsuccessful
 *
 * inputs: group_threshold: the number of groups that need to be satisfied in order
 *                          to reconstruct the secret
 *         groups: an array of group descriptors
 *         groups_length: the length of the groups array
 *         master_secret: pointer to the secret to split up
 *         master_secret_length: length of the master secret in bytes.
 *                               must be >= 16, <= 32, and even.
 *         passphrase: string to use to encrypt the master secret
 *         iteration_exponent: exponent to use when calculating the number of rounds of encryption
 *                             to go through when encrypting the master secret.
 *         mnemonic_length: pointer to an integer that will be filled with the number of
 *                          mnemonic words in each shard
 *         mnemonics: array of shard structures to store the resulting mnemonics.
 *                    the ith shard will be represented by
 *                     mnemonics[i*mnemonic_length]..mnemonics[(i+1)*mnemonic_length -1]
 *         buffer_size: maximum number of mnemonics code to write to the mnemonics array
 */
int generate_mnemonics(
    uint8_t group_threshold,
    const group_descriptor *groups,
    uint8_t groups_length,
    const uint8_t *master_secret,
    uint32_t master_secret_length,
    const char *passphrase,
    uint8_t iteration_exponent,
    uint32_t *mnemonic_length,
    uint16_t *mnemonics,
    uint32_t buffer_size,
    void (*random_generator)(uint8_t *, size_t)
);


/**
 * combine a set of mnemonic encoded shards to reconstuct a secret
 *
 * returns: the length of the reconstructed secret if successful
 *          or a negative number indicating an error code when unsuccessful
 *
 * inputs: mnemonics: an array of pointers to arrays of mnemonic codes
 *         mnemonics_words: length of each array of mnemonic codes\
 *         mnemonics_shards: length of the mnemonics array
 *         passphrase: passphrase to use encrypt the resulting secret
 *         passwords: array of strings to use to decrypt shard data
 *                    passing NULL disables password decrypt for all shards
 *                    passing NULL for the ith password will disable decrypt for the ith shard
 *                    passing a pointer to a string for the ith shard will cause the ith shard
 *                    to be decrypted with the string before recombination
 *         buffer: location to store the result
 *         buffer_length: maximum space available in buffer
 */
int combine_mnemonics(
    const uint16_t **mnemonics, // array of pointers to 10-bit words
    uint32_t mnemonics_words,   // number of words in each shard
    uint32_t mnemonics_shards,  // total number of shards
    const char *passphrase,     // passphrase to unlock master secret
    const char **passwords,     // passwords protecting shards
    uint8_t *buffer,            // working space, and place to return secret
    uint32_t buffer_length      // total amount of working space
);

#endif /* MNEMONICS_H */
