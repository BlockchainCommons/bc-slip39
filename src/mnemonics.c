//
//  mnemonics.c
//
//  Copyright © 2020 by Blockchain Commons, LLC
//  Licensed under the "BSD-2-Clause Plus Patent License"
//

#include "mnemonics.h"
#include "encoding.h"
#include "rs1024.h"
#include "encrypt.h"
#include "slip39-errors.h"

#ifdef ARDUINO
#include "bc-shamir.h"
#else
#include <bc-shamir/bc-shamir.h>
#endif

#include <stdio.h>
#include <string.h>

//////////////////////////////////////////////////
// encode mnemonic
int encode_mnemonic(
    const slip39_shard *shard,
    uint16_t *destination,
    uint32_t destination_length) {

    // pack the id, exp, group and member data into 4 10-bit words:
    // [id:1  5][exp:5][g_index:4][g_thresh*:4][g_count*:4][m_idx:4][m_thrsh*:4]s
    // [w0:10][  w1:10][w2:10                      ][w3:10                     ]

    // change offset and clip group and member coordinate data
    uint16_t gt = (shard->group_threshold -1) & 15;
    uint16_t gc = (shard->group_count -1) & 15;
    uint16_t mi = (shard->member_index) & 15;
    uint16_t mt = (shard->member_threshold -1) & 15;

    destination[0] = (shard->identifier >> 5) & 1023;
    destination[1] = ((shard->identifier << 5) | shard->iteration_exponent) & 1023;
    destination[2] = ((shard->group_index << 6) | (gt << 2) | (gc >> 2)) & 1023;
    destination[3] = ((gc << 8) | (mi << 4) | (mt)) & 1023;

    uint32_t words = slip39_words_for_data(shard->value, shard->value_length, destination+4, destination_length - METADATA_LENGTH_WORDS);
    rs1024_create_checksum(destination, words + METADATA_LENGTH_WORDS);

    return words+METADATA_LENGTH_WORDS;
 }

//////////////////////////////////////////////////
// decode mnemonic
int decode_mnemonic(
    const uint16_t *mnemonic,
    uint32_t mnemonic_length,
    slip39_shard *shard
) {
    if(mnemonic_length < MIN_MNEMONIC_LENGTH_WORDS) {
        return ERROR_NOT_ENOUGH_MNEMONIC_WORDS;
    }

    if( !rs1024_verify_checksum(mnemonic, mnemonic_length) ) {
        return ERROR_INVALID_MNEMONIC_CHECKSUM;
    }

    uint8_t group_threshold = ((mnemonic[2] >> 2) & 15) +1;
    uint8_t group_count = (((mnemonic[2]&3) << 2) | ((mnemonic[3]>>8)&3)) +1;

    if(group_threshold > group_count) {
        return ERROR_INVALID_GROUP_THRESHOLD;
    }

    shard->identifier = mnemonic[0] << 5 | mnemonic[1] >> 5;
    shard->iteration_exponent = mnemonic[1] & 31;
    shard->group_index = mnemonic[2] >> 6;
    shard->group_threshold = group_threshold;
    shard->group_count = group_count;
    shard->member_index = (mnemonic[3]>>4) & 15;
    shard->member_threshold = (mnemonic[3]&15) + 1;
    int32_t result = slip39_data_for_words(mnemonic+4, mnemonic_length - 7, shard->value, 32);
    if(result < 0) {
        return result;
    }
    shard->value_length = result;
    if(shard->value_length < MIN_STRENGTH_BYTES) {
        return ERROR_SECRET_TOO_SHORT;
    }
    if(shard->value_length % 2) {
        return ERROR_INVALID_SECRET_LENGTH;
    }
    return shard->value_length;
}


void print_hex(
    const uint8_t *buffer,
    uint32_t length
) {
    printf("0x");
    for(uint32_t i=0;i<length;++i) {
        if(i > 0 && i%32== 0) {
            printf("\n  ");
        }
        printf("%02x", buffer[i]);
    }
    printf("\n");
}


void print_mnemonic(
    const uint16_t *mnemonic,
    unsigned int mnemonic_length
) {
    slip39_shard shard;
    shard.value_length = 32;

    unsigned int secret_length = decode_mnemonic(mnemonic, mnemonic_length, &shard);
    shard.value_length = secret_length;

    for(unsigned int i=0;i< mnemonic_length; ++i) {
        printf("%s ", slip39_string_for_word(mnemonic[i]));
    }

    printf("\n");
    printf("identifier: %d  exponent: %d\n", shard.identifier, shard.iteration_exponent);
    printf("group index: %d  threshold: %d  count: %d\n",
        shard.group_index, shard.group_threshold, shard.group_count);
    printf("member index: %d  threshold: %d\n",
        shard.member_index, shard.member_threshold);
    print_hex(shard.value, shard.value_length);
}

int count_shards(uint8_t group_threshold, const group_descriptor *groups, uint8_t groups_length);

int count_shards(
    uint8_t group_threshold,
    const group_descriptor *groups,
    uint8_t groups_length
) {
    uint16_t total_shards = 0;

    if(group_threshold > groups_length) {
        return ERROR_INVALID_GROUP_THRESHOLD;
    }

    for(uint8_t i=0; i<groups_length; ++i) {
        total_shards += groups[i].count;
        if( groups[i].threshold > groups[i].count ) {
            return ERROR_INVALID_MEMBER_THRESHOLD;
        }
        if( groups[i].threshold == 1 && groups[i].count > 1) {
            return ERROR_INVALID_SINGLETON_MEMBER;
        }
    }

    return total_shards;
}

//////////////////////////////////////////////////
// generate shards
//
int generate_shards(
    uint8_t group_threshold,
    const group_descriptor *groups,
    uint8_t groups_length,
    const uint8_t *master_secret,
    uint32_t master_secret_length,
    const char *passphrase,
    uint8_t iteration_exponent,
    slip39_shard *shards,
    uint16_t shards_size,
    void* ctx,
    void (*random_generator)(uint8_t *, size_t, void*)
) {

    if(master_secret_length < MIN_STRENGTH_BYTES) {
        return ERROR_SECRET_TOO_SHORT;
    }

    if(master_secret_length % 2 == 1) {
        return ERROR_INVALID_SECRET_LENGTH;
    }

    // Figure out how many shards we are dealing with
    int total_shards = count_shards(group_threshold, groups, groups_length);
    if(total_shards < 0) {
        return total_shards;
    }

    // assign a random identifier
    uint16_t identifier = 0;
    random_generator((uint8_t *)(&identifier), 2, ctx);
    identifier = identifier & ((1<<15)-1);

    if(shards_size < total_shards) {
        return ERROR_INSUFFICIENT_SPACE;
    }

    if(master_secret_length % 2 == 1) {
        return ERROR_INVALID_SECRET_LENGTH;
    }

    for(const uint8_t *p = (const uint8_t *) passphrase; *p; p++) {
        if( (*p < 32) || (126 < *p) ) {
            return ERROR_INVALID_PASSPHRASE;
        }
    }

    if(group_threshold > groups_length) {
        return ERROR_INVALID_GROUP_THRESHOLD;
    }

    uint8_t encrypted_master_secret[master_secret_length];

    slip39_encrypt(master_secret,master_secret_length,passphrase,iteration_exponent,identifier, encrypted_master_secret);

    uint8_t group_shares[master_secret_length * groups_length];

    split_secret(group_threshold, groups_length, encrypted_master_secret, master_secret_length, group_shares, ctx, random_generator);

    uint8_t *group_share = group_shares;

    unsigned int shard_count = 0;
    slip39_shard *shard = &shards[shard_count];

    for(uint8_t i=0; i<groups_length; ++i, group_share += master_secret_length) {
        uint8_t member_shares[master_secret_length *groups[i].count];
        split_secret(groups[i].threshold, groups[i].count, group_share, master_secret_length, member_shares, ctx, random_generator);

        uint8_t *value = member_shares;
        for(uint8_t j=0; j< groups[i].count; ++j, value += master_secret_length) {
            shard = &shards[shard_count];

            shard->identifier = identifier;
            shard->iteration_exponent = iteration_exponent;
            shard->group_threshold = group_threshold;
            shard->group_count = groups_length;
            shard->value_length = master_secret_length;
            shard->group_index = i;
            shard->member_threshold = groups[i].threshold;
            shard->member_index = j;
            memset(shard->value, 0, 32);
            memcpy(shard->value, value, master_secret_length);

            if(groups[i].passwords && groups[i].passwords[j]) {
                encrypt_shard(shard, groups[i].passwords[j]);
            }

            shard_count++;
        }

        // clean up
        memset(member_shares, 0, sizeof(member_shares));
    }

    // clean up stack
    memset(encrypted_master_secret, 0, sizeof(encrypted_master_secret));
    memset(group_shares, 0, sizeof(group_shares));

    // return the number of shards generated
    return shard_count;
}

//////////////////////////////////////////////////
// generate mnemonics
//
int slip39_generate(
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
    void* ctx,
    void (*random_generator)(uint8_t *, size_t, void*)
) {
    if(master_secret_length < MIN_STRENGTH_BYTES) {
        return ERROR_SECRET_TOO_SHORT;
    }

    // Figure out how many shards we are dealing with
    int total_shards = count_shards(group_threshold, groups, groups_length);
    if(total_shards < 0) {
        return total_shards;
    }

    // figure out how much space we need to store all of the mnemonics
    // and make sure that we were provided with sufficient resources
    uint32_t shard_length = METADATA_LENGTH_WORDS + slip39_word_count_for_bytes(master_secret_length);
    if(buffer_size < shard_length * total_shards) {
        return ERROR_INSUFFICIENT_SPACE;
    }

    int error = 0;

    // allocate space for shard representations
    slip39_shard shards[total_shards];

    // generate shards
    total_shards = generate_shards(group_threshold, groups, groups_length, master_secret, master_secret_length,
        passphrase, iteration_exponent, shards, total_shards, ctx, random_generator);

    if(total_shards < 0) {
        error = total_shards;
    }

    uint16_t *mnemonic = mnemonics;
    unsigned int remaining_buffer = buffer_size;
    unsigned int word_count = 0;

    for(uint16_t i =0; !error && i<total_shards ; ++i) {
        int words = encode_mnemonic(&shards[i], mnemonic, remaining_buffer);
        if(words < 0) {
            error = words;
            break;
        }
        word_count = words;
        remaining_buffer -= word_count;
        mnemonic += word_count;
    }

    memset(shards,0,sizeof(shards));
    if(error) {
        memset(mnemonics, 0, buffer_size);
        return 0;
    }

    *mnemonic_length = word_count;
    return total_shards;
}

int combine_shards_internal(
    slip39_shard *shards,       // array of shard structures
    uint16_t shards_count,      // number of shards in array
    const char *passphrase,     // passphrase to unlock master secret
    const char **passwords,     // passwords for the shards
    uint8_t *buffer,            // working space, and place to return secret
    uint32_t buffer_length      // total amount of working space
);


int combine_shards(
    const slip39_shard *shards, // array of shard structures
    uint16_t shards_count,      // number of shards in array
    const char *passphrase,     // passphrase to unlock master secret
    const char **passwords,     // passwords for the shards
    uint8_t *buffer,            // working space, and place to return secret
    uint32_t buffer_length      // total amount of working space
) {
    if(shards_count == 0) {
        return ERROR_EMPTY_MNEMONIC_SET;
    }

    slip39_shard working_shards[shards_count];
    memcpy(working_shards, shards, sizeof(working_shards));

    int result = combine_shards_internal(working_shards, shards_count, passphrase, passwords, buffer, buffer_length);

    memset(working_shards,0, sizeof(working_shards));

    return result;
}

/**
 * This version of combine shards potentially modifies the shard structures
 * in place, so it is for internal use only, however it provides the implementation
 * for both combine_shards and slip39_combine.
 */
int combine_shards_internal(
    slip39_shard *shards,       // array of shard structures
    uint16_t shards_count,      // number of shards in array
    const char *passphrase,     // passphrase to unlock master secret
    const char **passwords,     // passwords for the shards
    uint8_t *buffer,            // working space, and place to return secret
    uint32_t buffer_length      // total amount of working space
) {
    int error = 0;
    uint16_t identifier = 0;
    uint8_t iteration_exponent = 0;
    uint8_t group_threshold = 0;
    uint8_t group_count = 0;

    if(shards_count == 0) {
        return ERROR_EMPTY_MNEMONIC_SET;
    }

    uint8_t next_group = 0;
    slip39_group groups[16];
    uint8_t secret_length = 0;

    for(unsigned int i=0; !error && i<shards_count; ++i) {
        slip39_shard *shard = &shards[i];
        if(passwords && passwords[i]) {
            decrypt_shard(shard, passwords[i]);
        }

        if( i == 0) {
            // on the first one, establish expected values for common metadata
            identifier = shard->identifier;
            iteration_exponent = shard->iteration_exponent;
            group_count = shard->group_count;
            group_threshold = shard->group_threshold;
            secret_length = shard->value_length;
        } else {
            // on subsequent shards, check that common metadata matches
            if( shard->identifier != identifier ||
                shard->iteration_exponent != iteration_exponent ||
                shard->group_threshold != group_threshold ||
                shard->group_count != group_count ||
                shard->value_length != secret_length
            ) {
                return ERROR_INVALID_SHARD_SET;
            }
        }

        // sort shards into member groups
        uint8_t group_found = 0;
        for(uint8_t j=0; j<next_group; ++j) {
            if(shard->group_index == groups[j].group_index) {
                group_found = 1;
                if(shard->member_threshold != groups[j].member_threshold) {
                    return ERROR_INVALID_MEMBER_THRESHOLD;
                }
                for(uint8_t k=0; k<groups[j].count; ++k) {
                    if(shard->member_index == groups[j].member_index[k]) {
                        return ERROR_DUPLICATE_MEMBER_INDEX;
                    }
                }
                groups[j].member_index[groups[j].count] = shard->member_index;
                groups[j].value[groups[j].count] = shard->value;
                groups[j].count++;
            }
        }

        if(!group_found) {
            groups[next_group].group_index = shard->group_index;
            groups[next_group].member_threshold = shard->member_threshold;
            groups[next_group].count = 1;
            groups[next_group].member_index[0] = shard->member_index;
            groups[next_group].value[0] = shard->value;
            next_group++;
        }
    }

    if(buffer_length < secret_length) {
        error = ERROR_INSUFFICIENT_SPACE;
    } else if(next_group < group_threshold) {
        error = ERROR_NOT_ENOUGH_GROUPS;
    }

    // here, all of the shards are unpacked into member groups. Now we go through each
    // group and recover the group secret, and then use the result to recover the
    // master secret
    uint8_t gx[16];
    const uint8_t *gy[16];

    // allocate enough space for the group shards and the encrypted master secret
    uint8_t group_shares[secret_length * (group_threshold + 1)];
    uint8_t *group_share = group_shares;

    for(uint8_t i=0; !error && i<next_group; ++i) {
        gx[i] = groups[i].group_index;
        if(groups[i].count < groups[i].member_threshold) {
            error = ERROR_NOT_ENOUGH_MEMBER_SHARDS;
            break;
        }

        int recovery = recover_secret(
            groups[i].member_threshold, groups[i].member_index,
            groups[i].value, secret_length, group_share);

        if(recovery < 0) {
            error = recovery;
            break;
        }
        gy[i] = group_share;

        group_share += recovery;
    }

    int recovery = 0;
    if(!error) {
        recovery = recover_secret(group_threshold, gx, gy, secret_length, group_share);
    }

    if(recovery < 0) {
        error = recovery;
    }

    // decrypt copy the result to the beinning of the buffer supplied
    if(!error) {
        slip39_decrypt(group_share, secret_length, passphrase, iteration_exponent, identifier, buffer);
    }

    // clean up stack
    memset(group_shares,0,sizeof(group_shares));
    memset(gx,0,sizeof(gx));
    memset(gy,0,sizeof(gy));
    memset(groups,0,sizeof(groups));

    if(error) {
        return error;
    }

    return secret_length;
}


/////////////////////////////////////////////////
// slip39_combine
int slip39_combine(
    const uint16_t **mnemonics, // array of pointers to 10-bit words
    uint32_t mnemonics_words,   // number of words in each shard
    uint32_t mnemonics_shards,  // total number of shards
    const char *passphrase,     // passphrase to unlock master secret
    const char **passwords,     // passwords for the shards
    uint8_t *buffer,            // working space, and place to return secret
    uint32_t buffer_length      // total amount of working space
) {
    int result = 0;

    if(mnemonics_shards == 0) {
        return ERROR_EMPTY_MNEMONIC_SET;
    }

    slip39_shard shards[mnemonics_shards];

    for(unsigned int i=0; !result && i<mnemonics_shards; ++i) {
        shards[i].value_length = 32;

        int32_t bytes = decode_mnemonic(mnemonics[i], mnemonics_words, &shards[i]);

        if(bytes < 0) {
            result = bytes;
        }
    }

    if(!result) {
        result = combine_shards_internal(shards, mnemonics_shards, passphrase, passwords, buffer, buffer_length);
    }

    memset(shards,0,sizeof(shards));

    return result;
}


////
// encrypt/decrypt shards
//
void encrypt_shard(
    slip39_shard *shard,
    const char *passphrase
) {
    uint8_t temp[shard->value_length];
    slip39_encrypt(shard->value, shard->value_length, passphrase, shard->iteration_exponent, shard->identifier, temp);
    memcpy(shard->value, temp, shard->value_length);
}

void decrypt_shard(
    slip39_shard *shard,
    const char *passphrase
) {
    uint8_t temp[shard->value_length];
    slip39_decrypt(shard->value, shard->value_length, passphrase, shard->iteration_exponent, shard->identifier, temp);
    memcpy(shard->value, temp, shard->value_length);
}
