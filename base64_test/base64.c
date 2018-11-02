//
//  base64.c
//  base64_test
//
//  Created by fcj on 2018/11/2.
//  Copyright © 2018年 fcj. All rights reserved.
//

#include "base64.h"
void base64_decode()
{
    uc_engine *uc;
    uc_hook  trace2;
    uc_err err;
    printf("Emulate ARM64 code\n");
    
    // Initialize emulator in ARM mode
    err = uc_open(UC_ARCH_ARM64, UC_MODE_ARM, &uc);
    if (err) {
        printf("Failed on uc_open() with error returned: %u (%s)\n",
               err, uc_strerror(err));
        return;
    }
    
    // map 2MB memory for this emulation
    err=uc_mem_map(uc, ADDRESS_CODE, 10 * 1024 * 1024, UC_PROT_ALL);
    if(err){
        printf("Failed on uc_mem_map() with error returned: %u (%s)\n",
               err, uc_strerror(err));
    }
    
    err=uc_mem_map(uc, STACK_ADDR, STACK_SIZE, UC_PROT_ALL);
    if(err){
        printf("Failed on uc_mem_map() with error returned: %u (%s)\n",
               err, uc_strerror(err));
    }
    uint64_t sp_address=(STACK_ADDR + STACK_SIZE/2);
    err=uc_reg_write(uc,  UC_ARM64_REG_SP, &sp_address);//分配栈内存
    uint32_t len = 0;
    char* code = read_file("/Volumes/extData/vm/llvm_dylib/TD_VM_CC/build/Debug/obj_su/local/arm64-v8a/base64", &len);
    // write machine code to be emulated to memory
    //uc_mem_write(uc, ADDRESS+0x92B8, tmpcode, 0x1000);
    err=uc_mem_write(uc, ADDRESS_CODE, code, len);
    
    if (err) {
        printf("Failed on uc_mem_write() with error returned: %u (%s)\n",
               err, uc_strerror(err));
        return;
    }
    
    //设置一个指令执行回调用，该回调函数会在指令执行前被调用
    uc_hook_add(uc, &trace2, UC_HOOK_CODE, hook_code, NULL, ADDRESS_CODE+0x9F4, ADDRESS_CODE+0xAF4);
    
    err=uc_mem_map(uc, MEM_ADDR, STACK_SIZE*4, UC_PROT_ALL);
    if(err){
        printf("Failed on uc_mem_map() with error returned: %u (%s)\n",
               err, uc_strerror(err));
    }
    
    char *str="dG9uZ2R1bmRhZmRzZGExMjMx";
    int64_t address=get_mem_addres(strlen(str));
    uc_mem_write(uc, address, str, strlen(str));
    uc_reg_write(uc, UC_ARM64_REG_X0, &address);
    err = uc_emu_start(uc, ADDRESS_CODE+0x9F4, ADDRESS_CODE+0xAF4, 0, 0);
    if (err) {
        printf("Failed on uc_emu_start() with error returned: %u (%s)\n",
               err, uc_strerror(err));
        return;
    }
    char  buff[0x1024 ]={0};
    int64_t x0;
    uc_reg_read(uc, UC_ARM64_REG_X0, &x0);
    uc_mem_read(uc, x0, buff, 0x1024);
    printf("----base64 encode buff  ==%s\n",buff);
}
void base64_encode()
{
    char *str="tongdundafdsda1231";
    uc_engine *uc;
    uc_hook  trace2;
    uc_err err;
    printf("Emulate ARM64 code\n");
    
    // Initialize emulator in ARM mode
    err = uc_open(UC_ARCH_ARM64, UC_MODE_ARM, &uc);
    if (err) {
        printf("Failed on uc_open() with error returned: %u (%s)\n",
               err, uc_strerror(err));
        return;
    }
    
    // map 2MB memory for this emulation
    err=uc_mem_map(uc, ADDRESS_CODE, 10 * 1024 * 1024, UC_PROT_ALL);
    if(err){
        printf("Failed on uc_mem_map() with error returned: %u (%s)\n",
               err, uc_strerror(err));
    }
    
    err=uc_mem_map(uc, STACK_ADDR, STACK_SIZE, UC_PROT_ALL);
    if(err){
        printf("Failed on uc_mem_map() with error returned: %u (%s)\n",
               err, uc_strerror(err));
    }
    uint64_t sp_address=(STACK_ADDR + STACK_SIZE/2);
    err=uc_reg_write(uc,  UC_ARM64_REG_SP, &sp_address);//分配栈内存
    uint32_t len = 0;
    char* code = read_file("/Volumes/extData/vm/llvm_dylib/TD_VM_CC/build/Debug/obj_su/local/arm64-v8a/base64", &len);
    // write machine code to be emulated to memory
    //uc_mem_write(uc, ADDRESS+0x92B8, tmpcode, 0x1000);
    err=uc_mem_write(uc, ADDRESS_CODE, code, len);
    
    if (err) {
        printf("Failed on uc_mem_write() with error returned: %u (%s)\n",
               err, uc_strerror(err));
        return;
    }
    
    //设置一个指令执行回调用，该回调函数会在指令执行前被调用
    uc_hook_add(uc, &trace2, UC_HOOK_CODE, hook_code, NULL, ADDRESS_CODE, ADDRESS_CODE+0x1634);
    
    
    err=uc_mem_map(uc, MEM_ADDR, STACK_SIZE*4, UC_PROT_ALL);
    if(err){
        printf("Failed on uc_mem_map() with error returned: %u (%s)\n",
               err, uc_strerror(err));
    }
    int64_t address=get_mem_addres(strlen(str));
    uc_mem_write(uc, address, str, strlen(str));
    uc_reg_write(uc, UC_ARM64_REG_X0, &address);
    err = uc_emu_start(uc, ADDRESS_CODE+0x8F8, ADDRESS_CODE+0x9F0, 0, 0);
    if (err) {
        printf("Failed on uc_emu_start() with error returned: %u (%s)\n",
               err, uc_strerror(err));
        return;
    }
    char  buff[0x1024 ]={0};
    int64_t x0;
    uc_reg_read(uc, UC_ARM64_REG_X0, &x0);
    uc_mem_read(uc, x0, buff, 0x1024);
    printf("----base64 encode buff  ==%s\n",buff);
}
