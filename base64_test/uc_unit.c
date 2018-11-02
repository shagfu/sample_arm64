//
//  uc_unit.cpp
//  base64_test
//
//  Created by fcj on 2018/10/29.
//  Copyright © 2018年 fcj. All rights reserved.
//
#include <stdio.h>
#include "uc_unit.h"
int mem_off=0;
int m_statck=2;
void adrp_relo_function(uc_engine *uc,uint64_t pc_address,int regid,char* str,int len)
{
    int64_t mem_address=get_mem_addres(len);
    uc_mem_write(uc, mem_address, str, len);
    uc_reg_write(uc, regid,&mem_address);
    int64_t pc=pc_address+8;
    uc_reg_write(uc, UC_ARM64_REG_PC, &pc);
}
void bl_strlen_function(uc_engine *uc,uint64_t pc_address)
{
    int64_t x0;
    char tmpbuff[0x1000]={0};
    uc_reg_read(uc, UC_ARM64_REG_X0, &x0);
    uc_mem_read(uc, x0, tmpbuff, 0x1000);
    printf("----strlen   str == %s\n",tmpbuff);
    unsigned int len =strlen(tmpbuff);
    uc_reg_write(uc, UC_ARM64_REG_X0, &len);
    int64_t pc=pc_address+4;
    uc_reg_write(uc, UC_ARM64_REG_PC, &pc);
}
void bl_malloc_function(uc_engine *uc,uint64_t pc_address)
{
    int64_t x0=0;
    uc_reg_read(uc, UC_ARM64_REG_X0, &x0);//读取需要分配的大小
    printf("---malloc size == %llx \n",x0);
    int64_t mem_address= get_mem_addres(x0);
    char buff[0x100]={0};
    uc_mem_write(uc, mem_address, buff, 0x100);//将buff写到uc的mem里面
    uc_reg_write(uc, UC_ARM64_REG_X0,&mem_address);//给x0赋值分配的内存
    uint64_t pc = pc_address;
    pc += 4;
    uc_reg_write(uc, UC_ARM64_REG_PC, &pc);
}
void bl_memcpu_function(uc_engine *uc,uint64_t pc_address)
{
    int64_t x0,x1,x2;
    uc_reg_read(uc, UC_ARM64_REG_X0, &x0);//dest
    uc_reg_read(uc, UC_ARM64_REG_X1, &x1);//src
    uc_reg_read(uc, UC_ARM64_REG_X2, &x2);//len
    //uc_reg_write(uc, UC_ARM64_REG_X0, &x1);
    
    char tmp1[0x100]={0};
    char tmp2[0x100]={0};
    uc_mem_read(uc, x0, tmp1, 0x100);
    uc_mem_read(uc, x1, tmp2, 0x100);
    uc_mem_write(uc, x0, tmp2, x2);
    uint64_t pc = pc_address;
    pc += 4;
    uc_reg_write(uc, UC_ARM64_REG_PC, &pc);
    
}
void bl_strstr_function(uc_engine *uc,uint64_t pc_address)
{
    int64_t x0;
    int64_t x1;
    char x0_buff[0x1000]={0};
    char x1_buff[0x1000]={0};
    uc_reg_read(uc, UC_ARM64_REG_X0, &x0);
    uc_reg_read(uc, UC_ARM64_REG_X1, &x1);
    uc_mem_read(uc, x0,x0_buff , 0x1000);
    uc_mem_read(uc, x1,x1_buff , 0x1000);
    char * strres=strstr(x0_buff,x1_buff);
    if(strres)
    {
        int64_t mem_address= get_mem_addres(strlen(strres));
        uc_mem_write(uc, mem_address, strres, strlen(strres));
        uc_reg_write(uc, UC_ARM64_REG_X0, &mem_address);
    }else{
        int64_t mem_address=0;
        uc_reg_write(uc, UC_ARM64_REG_X0, &mem_address);
    }
    int64_t pc=pc_address+4;
    uc_reg_write(uc, UC_ARM64_REG_PC, &pc);
}
void bl_memset_function(uc_engine *uc,uint64_t pc_address)
{
    int64_t x0,x1,x2;
    uc_reg_read(uc, UC_ARM64_REG_X0, &x0);//dest
    uc_reg_read(uc, UC_ARM64_REG_X1, &x1);//src
    uc_reg_read(uc, UC_ARM64_REG_X2, &x2);//len
    //uc_reg_write(uc, UC_ARM64_REG_X0, &x1);
    
    char tmp1[0x100]={0};
    char tmp2[0x100]={0};
    uc_mem_read(uc, x0, tmp1, 0x100);
    //uc_mem_read(uc, x1, tmp2, 0x100);
    uc_mem_write(uc, x0, tmp2, x2);
    uint64_t pc = pc_address;
    pc += 4;
    uc_reg_write(uc, UC_ARM64_REG_PC, &pc);
}
void bl_strchr_function(uc_engine *uc,uint64_t pc_address)
{
    int64_t x0;
    int w1;
    char buff[0x100]={0};
    uc_reg_read(uc, UC_ARM64_REG_X0, &x0);
    uc_reg_read(uc, UC_ARM64_REG_W1, &w1);
    uc_mem_read(uc, x0,buff , 0x100);
    char * strres=strchr(buff,0x3D);
    if(strres)
    {
        int64_t mem_address= get_mem_addres(strlen(strres));
        uc_mem_write(uc, mem_address, strres, strlen(strres));
        uc_reg_write(uc, UC_ARM64_REG_X0, &mem_address);
    }else{
        int64_t mem_address=0;
        uc_reg_write(uc, UC_ARM64_REG_X0, &mem_address);
    }
    
    int64_t pc=pc_address+4;
    uc_reg_write(uc, UC_ARM64_REG_PC, &pc);
}
int64_t get_mem_addres(int nsize)
{
    nsize=nsize&0xFFFF;
    int64_t ret;
    ret=MEM_ADDR+mem_off;
    mem_off+=nsize;
    mem_off+=0x10;
    return ret;
}

uc_engine * call_function(function_info * funcinfo)
{
    uc_engine *uc_new;
    uc_hook  trace2;
    uc_err err;
    int64_t address_code=ADDRESS_CODE+STACK_INC*(m_statck-1);
    // Initialize emulator in ARM mode
    err = uc_open(UC_ARCH_ARM64, UC_MODE_ARM, &uc_new);
    if (err) {
        printf("Failed on uc_open() with error returned: %u (%s)\n",
               err, uc_strerror(err));
        return 0;
    }
    // 分配代码内存
    err=uc_mem_map(uc_new, address_code, 10 * 1024 * 1024, UC_PROT_ALL);
    if(err){
        printf("Failed on uc_mem_map() with error returned: %u (%s)\n",
               err, uc_strerror(err));
    }
    err=uc_mem_write(uc_new, address_code, (const void*)funcinfo->code_addr, funcinfo->code_len);

    //分配栈内存
     int64_t function_stack=STACK_ADDR+m_statck*STACK_INC;
    err=uc_mem_map(uc_new,function_stack , STACK_SIZE, UC_PROT_ALL);
    if(err){
        printf("Failed on uc_mem_map() with error returned: %u (%s)\n",
               err, uc_strerror(err));
    }
    uint64_t sp_address=function_stack+(STACK_SIZE/2);
    err=uc_reg_write(uc_new,  UC_ARM64_REG_SP, &sp_address);//分配栈内存
    if (err) {
        printf("Failed on uc_mem_write() with error returned: %u (%s)\n",
               err, uc_strerror(err));
        return 0;
    }
    
    //设置一个指令执行回调用，该回调函数会在指令执行前被调用
    uc_hook_add(uc_new, &trace2, UC_HOOK_CODE, funcinfo->code_hook, NULL, address_code+funcinfo->code_begin, address_code+funcinfo->code_end);
    //分配函数内存地址
    int64_t function_mem_addr=function_stack+STACK_SIZE;
    err=uc_mem_map(uc_new,function_mem_addr,STACK_SIZE*8, UC_PROT_ALL);
    if(err){
        printf("Failed on uc_mem_map() with error returned: %u (%s)\n",
               err, uc_strerror(err));
    }
    //传参数
    int64_t address=0;
    for (int i=0; i<funcinfo->arg_number; i++) {
        address=function_mem_addr+0x100*i;
        int64_t *arg=(int64_t*)(funcinfo->args[i]);
        if(funcinfo->args_size[i]==0x40000)
        {
             err=uc_reg_write(uc_new, UC_ARM64_REG_X0+i, arg);
        }else
        {
            
            err=uc_mem_write(uc_new, address,(const void*)arg,funcinfo->args_size[i]);//写内存
             err=uc_reg_write(uc_new, UC_ARM64_REG_X0+i, &address);
        }
 
        
    }
    funcinfo->func_memaddr=function_mem_addr;
    err = uc_emu_start(uc_new, address_code+funcinfo->code_begin, address_code+funcinfo->code_end, 0, 0);
    if (err) {
        printf("************* !!!!!!!!!!! function mem_addr == %llx\n",function_mem_addr);
        printf("Failed on uc_emu_start() with error returned: %u (%s)\n",
               err, uc_strerror(err));
        return 0;
    }
    m_statck++;
    return uc_new;
}
char* read_file(char* path, uint32_t* len)
{
    FILE* fp = fopen(path, "rb");
    if (fp == NULL)
        return 0;
    fseek(fp, 0, SEEK_END);
    *len = (uint32_t)ftell(fp);
    fseek(fp, 0, SEEK_SET);
    char* code = (char*)malloc(*len);
    memset((void*)code, 0, (unsigned long)*len);
    fread(code, 1, *len, fp);
    fclose(fp);
    return code;
}
void hook_code(uc_engine *uc, uint64_t pc_address, uint32_t size, void *user_data)
{
    uc_err err;
    printf(">>> Tracing hook_code at 0x%"PRIx64 ", instruction size = 0x%x\n", pc_address, size);
    switch (pc_address) {
            
        case 0x90C://strlen
        case 0xA08:
        {
            bl_strlen_function(uc,pc_address);
            break;
        }
        case 0xA10:
        {
            char *strda="==";
            adrp_relo_function(uc,pc_address,strda,UC_ARM64_REG_X1,strlen(strda));
            break;
        }
        case 0xA1C://strstr
        {
            bl_strstr_function(uc, pc_address);
            break;
        }
        case 0xA28:
        case 0xA50:
        {
            int64_t x20=0;
            uc_reg_read(uc, UC_ARM64_REG_X20,&x20);
            x20=x20&0xFF;
            uc_reg_write(uc,UC_ARM64_REG_X20,&x20);
            break;
        }
        case 0xA48://strchr
        {
            bl_strchr_function(uc, pc_address);
            break;
        }
        case 0x938://malloc
        case 0xA70:
        {
            bl_malloc_function(uc, pc_address);
            break;
        }
        case 0x940:
        case 0xA74:
        {
            //size 大小错误  修正
            int64_t x0=0;
            int64_t x21=0;
            err=uc_reg_read(uc, UC_ARM64_REG_X0, &x0);//读取需要分配的大小
            err=uc_reg_read(uc, UC_ARM64_REG_X21, &x21);//读取需要分配的大小
            x21=x21&0xFF;
            uc_reg_write(uc, UC_ARM64_REG_X21, &x21);
            printf("---test size == x0 == %llx   x21===%llx \n",x0,x21);
            break;
        }
        default:
            break;
    }
}
