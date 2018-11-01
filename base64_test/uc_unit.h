//
//  uc_unit.hpp
//  base64_test
//
//  Created by fcj on 2018/10/29.
//  Copyright © 2018年 fcj. All rights reserved.
//

#ifndef uc_unit_hpp
#define uc_unit_hpp

#include <stdio.h>
#include <stdio.h>
#include <unicorn/unicorn.h>
typedef uint64_t float64;
#define ELF_HEADER_SIZE  0x40

#define STACK_ADDR  0x8000000
#define STACK_ADDR1  0x9000000

#define STACK_SIZE  1024*1024
#define ADDRESS_CODE 0x00000

#define MEM_ADDR    STACK_ADDR+STACK_SIZE

#define MEM_ADDR1    STACK_ADDR1+STACK_SIZE

#define F(x,y,z) ((x & y) | (~x & z))
#define G(x,y,z) ((x & z) | (y & ~z))
#define H(x,y,z) (x^y^z)
#define I(x,y,z) (y ^ (x | ~z))


/**************************************
 *向右环移n个单位
 * ************************************/
#define ROTATE_LEFT(x,n) ((x << n) | (x >> (32-n)))
#define FF(a,b,c,d,x,s,ac) { a += F(b,c,d) + x + ac;  a = ROTATE_LEFT(a,s); a += b; }
#define GG(a,b,c,d,x,s,ac) { a += G(b,c,d) + x + ac;  a = ROTATE_LEFT(a,s); a += b; }
#define HH(a,b,c,d,x,s,ac) { a += H(b,c,d) + x + ac;  a = ROTATE_LEFT(a,s); a += b; }
#define II(a,b,c,d,x,s,ac) { a += I(b,c,d) + x + ac;  a = ROTATE_LEFT(a,s); a += b; }
char* read_file(char* path, uint32_t* len);
int64_t get_mem_addres(int nsize);
void bl_strlen_function(uc_engine *uc,uint64_t pc_address);
void bl_malloc_function(uc_engine *uc,uint64_t pc_address);
void bl_strstr_function(uc_engine *uc,uint64_t pc_address);
void bl_strchr_function(uc_engine *uc,uint64_t pc_address);
void bl_memcpu_function(uc_engine *uc,uint64_t pc_address);
void adrp_relo_function(uc_engine *uc,uint64_t pc_address,int regid,char* str,int len);
void hook_code(uc_engine *uc, uint64_t pc_address, uint32_t size, void *user_data);

#endif /* uc_unit_hpp */
