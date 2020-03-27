//
//  slip39-errors.c
//
//  Copyright © 2020 by Blockchain Commons, LLC
//  Licensed under the "BSD-2-Clause Plus Patent License"
//

#ifndef SLIP39_ERRORS_H
#define SLIP39_ERRORS_H

#define ERROR_NOT_ENOUGH_MNEMONIC_WORDS        (-1)
#define ERROR_INVALID_MNEMONIC_CHECKSUM        (-2)
#define ERROR_SECRET_TOO_SHORT                 (-3)
#define ERROR_INVALID_GROUP_THRESHOLD          (-4)
#define ERROR_INVALID_SINGLETON_MEMBER         (-5)
#define ERROR_INSUFFICIENT_SPACE               (-6)
#define ERROR_INVALID_SECRET_LENGTH            (-7)
#define ERROR_INVALID_PASSPHRASE               (-8)
#define ERROR_INVALID_SHARD_SET                (-9)
#define ERROR_EMPTY_MNEMONIC_SET              (-10)
#define ERROR_DUPLICATE_MEMBER_INDEX          (-11)
#define ERROR_NOT_ENOUGH_MEMBER_SHARDS        (-12)
#define ERROR_INVALID_MEMBER_THRESHOLD        (-13)
#define ERROR_INVALID_PADDING                 (-14)
#define ERROR_NOT_ENOUGH_GROUPS               (-15)
#define ERROR_INVALID_SHARD_BUFFER            (-16)

#endif /* SLIP39_ERRORS_H */
