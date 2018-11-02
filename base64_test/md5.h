//
//  md5.h
//  base64_test
//
//  Created by fcj on 2018/11/2.
//  Copyright © 2018年 fcj. All rights reserved.
//

#ifndef md5_h
#define md5_h

#include <stdio.h>
#include "uc_unit.h"
#pragma pack(push)
typedef struct
{
    unsigned int count[2];//8
    //记录当前状态，其数据位数
    
    unsigned int state[4];//16
    //4个数，一共32位 记录用于保存对512bits信息加密的中间结果或者最终结果
    
    unsigned char buffer[64];
    //一共64字节，512位
}MD5_CTX;
#pragma pack(pop)
// code to be emulated
void MD5Init(MD5_CTX *context);
void base64_decode(void);
void MD5Transform(unsigned int state[4],unsigned char block[64]);
void MD5Encode(unsigned char *output,unsigned int *input,unsigned int len);
void MD5Decode(unsigned int *output,unsigned char *input,unsigned int len);
#endif /* md5_h */
