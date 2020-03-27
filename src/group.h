//
//  group.h
//
//  Copyright © 2020 by Blockchain Commons, LLC
//  Licensed under the "BSD-2-Clause Plus Patent License"
//

#ifndef GROUP_H
#define GROUP_H

#include <stdlib.h>

typedef struct group_struct {
    uint8_t group_index;
    uint8_t member_threshold;
    uint8_t count;
    uint8_t member_index[16];
    const uint8_t *value[16];
} slip39_group;

typedef struct group_descriptor_struct {
    uint8_t threshold;
    uint8_t count;
    const char **passwords;
} group_descriptor;

#endif /* GROUP_H */
