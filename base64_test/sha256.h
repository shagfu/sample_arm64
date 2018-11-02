//
//  sha256.h
//  base64_test
//
//  Created by fcj on 2018/11/2.
//  Copyright © 2018年 fcj. All rights reserved.
//

#ifndef sha256_h
#define sha256_h

#include <stdio.h>
#include <unicorn/unicorn.h>
#define SHA256_BLOCK_SIZE 32
typedef unsigned char BYTE;             // 8-bit byte
typedef unsigned int  WORD;             // 32-bit word, change to "long" for 16-bit machines
typedef struct {
    BYTE data[64];
    WORD datalen;
    unsigned long long bitlen;
    WORD state[8];
} SHA256_CTX;

void testsha256(void);
void sha256_init(SHA256_CTX *ctx);
void sha256_update(SHA256_CTX *ctx, const BYTE data[], size_t len);
void sha256_final(SHA256_CTX *ctx, BYTE hash[]);
void sha256_transform(SHA256_CTX *ctx, const BYTE data[]);
#endif /* sha256_h */
