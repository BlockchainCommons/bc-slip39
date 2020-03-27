//
//  buffer.c
//
//  Copyright © 2020 by Blockchain Commons, LLC
//  Licensed under the "BSD-2-Clause Plus Patent License"
//

#include "bc-shamir.h"
#include "slip39-errors.h"
#include "shamir-errors.h"
#include "shard.h"

#include <string.h>

int decode_binary_shard(
    slip39_shard *shard,
    const uint8_t *buffer,
    uint32_t buffer_length
) {
    if(buffer_length < 12 || buffer[0] != 0x48 || buffer[1] != 0xbd || buffer[2] != 0xfd) {
        return ERROR_INVALID_SHARD_BUFFER;
    }

    shard->identifier = (buffer[3] << 8) | buffer[4];
    shard->iteration_exponent = buffer[5];
    shard->group_index = buffer[6];
    shard->group_threshold = buffer[7];
    shard->group_count = buffer[8];
    shard->member_index = buffer[9];
    shard->member_threshold = buffer[10];
    shard->value_length= buffer[11];

    if(shard->value_length < 16) {
        return ERROR_SECRET_TOO_SHORT;
    }

    if(shard->value_length > 32) {
        return ERROR_SECRET_TOO_LONG;
    }

    if(buffer_length < (uint32_t) shard->value_length + 12) {
        return ERROR_INVALID_SHARD_BUFFER;
    }

    memset(shard->value, 0, 32);
    memcpy(shard->value, buffer+12, shard->value_length);

    return shard->value_length + 12;
}

int encode_binary_shard(
    uint8_t *buffer,
    uint32_t buffer_length,
    const slip39_shard *shard
) {
    if(buffer_length < (uint32_t) shard->value_length + 12) {
        return ERROR_INVALID_SHARD_BUFFER;
    }

    buffer[0] = 0x48;
    buffer[1] = 0xbd;
    buffer[2] = 0xfd;
    buffer[3] = (uint8_t) (shard->identifier >> 8);
    buffer[4] = (uint8_t) (shard->identifier & 0xff);
    buffer[5] = shard->iteration_exponent;
    buffer[6] = shard->group_index;
    buffer[7] = shard->group_threshold;
    buffer[8] = shard->group_count;
    buffer[9] = shard->member_index;
    buffer[10] = shard->member_threshold;
    buffer[11] = shard->value_length;

    memcpy(buffer+12, shard->value, shard->value_length);

    return shard->value_length + 12;
}
