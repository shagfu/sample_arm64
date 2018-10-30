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
void adrp_relo_function(uc_engine *uc,uint64_t pc_address,char* str)
{
    int len =strlen(str);
    int64_t mem_address=get_mem_addres(len);
    uc_mem_write(uc, mem_address, str, len);
    uc_reg_write(uc, UC_ARM64_REG_X1,&mem_address);
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
char* read_file(char* path, uint32_t* len)
{
    FILE* fp = fopen(path, "rb");
    if (fp == NULL)
        return 0;
    fseek(fp, 0, SEEK_END);
    *len = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    char* code = (char*)malloc(*len);
    memset(code, 0, *len);
    fread(code, 1, *len, fp);
    fclose(fp);
    return code;
}
