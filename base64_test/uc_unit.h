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
#define ADDRESS_CODE 0x00000
#define ELF_HEADER_SIZE  0x40

#define STACK_ADDR  0x04000000
#define STACK_INC   0x01000000
#define STACK_SIZE  1024*1024
#define MEM_ADDR    STACK_ADDR+STACK_SIZE


#pragma pack(push)
typedef struct function_info_t
{
    int64_t func_memaddr;
    int64_t code_addr;
    int64_t code_len;
    int64_t code_begin;
    int64_t code_end;
    void *  code_hook;
    int   arg_number;
    int64_t  args[10];
    int32_t  args_size[10];
}function_info;
#pragma pack(pop)
char* read_file(char* path, uint32_t* len);
int64_t get_mem_addres(int nsize);
void bl_strlen_function(uc_engine *uc,uint64_t pc_address);
void bl_memset_function(uc_engine *uc,uint64_t pc_address);
void bl_malloc_function(uc_engine *uc,uint64_t pc_address);
void bl_strstr_function(uc_engine *uc,uint64_t pc_address);
void bl_strchr_function(uc_engine *uc,uint64_t pc_address);
void bl_memcpu_function(uc_engine *uc,uint64_t pc_address);
void adrp_relo_function(uc_engine *uc,uint64_t pc_address,int regid,char* str,int len);
void hook_code(uc_engine *uc, uint64_t pc_address, uint32_t size, void *user_data);
uc_engine * call_function(function_info * funcinfo);
#endif /* uc_unit_hpp */
