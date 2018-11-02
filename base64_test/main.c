//
//  main.c
//  base64_test
//
//  Created by fcj on 2018/10/24.
//  Copyright © 2018年 fcj. All rights reserved.
//

#include <stdio.h>
#include <unicorn/unicorn.h>
#include "sha256.h"
#include "base64.h"
#include "md5.h"

int main(int argc, const char * argv[]) {
    // insert code here...
    //md5_test();
    base64_encode();
    //MD5Transform();
    printf("Hello, World!\n");
    return 0;
}

