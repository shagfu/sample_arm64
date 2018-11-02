//
//  md5.c
//  base64_test
//
//  Created by fcj on 2018/11/2.
//  Copyright © 2018年 fcj. All rights reserved.
//

#include "md5.h"
char* code_md5=0;
uint32_t   code_len=0;
//第一位1 其后若干个0,用于MD5Final函数时的补足
unsigned char PADDING[]={0x80,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
static void hook_code_md5_transform(uc_engine *uc, uint64_t pc_address, uint32_t size, void *user_data);
static void hook_code_md5(uc_engine *uc, uint64_t pc_address, uint32_t size, void *user_data)
{
    printf(">>> Tracing hook_code at 0x%"PRIx64 ", instruction size = 0x%x\n", pc_address, size);
    switch (pc_address)
    {
        case 0x880:
        {
            int64_t flag=0;
            int64_t w10,w19;
            
            uc_reg_read(uc, UC_ARM64_REG_NZCV, &flag);
            uc_reg_read(uc, UC_ARM64_REG_W10, &w10);
            uc_reg_read(uc, UC_ARM64_REG_W19, &w19);
            w10=(~(w19<<3))+1;
            //uc_reg_write(uc, UC_ARM64_REG_W10, &w10);
            printf("flag == %llx\n",flag);
            break;
        }
        case 0x884:
        {
            int64_t flag=0;
            int64_t w10=0;
            uc_reg_read(uc, UC_ARM64_REG_NZCV, &flag);
            uc_reg_read(uc, UC_ARM64_REG_W10, &w10);
            printf("flag == %llx\n",flag);
            break;
        }
        case 0x82C:
        {
            uint64_t pc1=0;
            float64  aa=0xEFCDAB8967452301;
            uc_reg_write(uc, UC_ARM64_REG_D0, &aa);
            uc_reg_read(uc, UC_ARM64_REG_PC,&pc1 );
            
            int64_t pc=pc_address;
            pc+=8;
            uc_reg_write(uc, UC_ARM64_REG_PC, &pc);
            break;
        }
        case 0x8BC://memcpy
        case 0x920:
        case 0x1410:
        case 0x146c:
        case 0x14bc:
        case 0x14E8:
        {
            bl_memcpu_function(uc,pc_address);
            break;
        }
        case 0x1420://transform
        case 0x143c:
        case 0x14C8:
        {
            
            int64_t x0,x1,x20;
            uc_reg_read(uc,UC_ARM64_REG_X0,&x0);
            uc_reg_read(uc,UC_ARM64_REG_X1,&x1);
            uc_reg_read(uc,UC_ARM64_REG_X20,&x20);
            MD5_CTX md51={0};
            uc_mem_read(uc, x20, &md51, sizeof(MD5_CTX));
            unsigned int state[4];
            unsigned char block[64];
            uc_mem_read(uc, x0, state, 16);
            uc_mem_read(uc, x1, block, 64);
            function_info MD5Transform_info={0,(int64_t)code_md5,code_len,0x924,0x1348,\
                hook_code_md5_transform,2,{&state,&block},{16,64}};
            uc_engine *uc_new =call_function(&MD5Transform_info);
            if(uc_new ==0){
                printf("************* !!!!!!!!!!! error\n");
            }
            int64_t address_p1=MD5Transform_info.func_memaddr;
            uc_mem_read(uc_new, address_p1, state, 16);
            int64_t address_p2=MD5Transform_info.func_memaddr+0x100;
            uc_mem_read(uc_new, address_p2, block, 64);
            uc_close(uc_new);
            uc_mem_write(uc, x0, state, 16);//把数据考回到x0中
            uc_mem_write(uc, x1, block , 64);
            int64_t pc=pc_address;
            pc+=4;
            uc_reg_write(uc, UC_ARM64_REG_PC, &pc);
            break;
        }
        case 0x145c: //padding
        {
            adrp_relo_function(uc,pc_address,UC_ARM64_REG_X8,PADDING,sizeof(PADDING));
            break;
        }
        default:
            break;
    }
}
void md5_test()
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
    uint64_t tmp_val;
    
    err = uc_reg_read(uc, UC_ARM_REG_C1_C0_2, &tmp_val);
    if (err) {
        printf("uc_open %d\n", err);
        return ;
    }
    
    tmp_val = tmp_val | (0xf << 20);
    err = uc_reg_write(uc, UC_ARM_REG_C1_C0_2, &tmp_val);
    if (err) {
        printf("uc_open %d\n", err);
        return ;
    }
    
    size_t enable_vfp = 0x40000000;
    err = uc_reg_write(uc, UC_ARM_REG_FPEXC, &enable_vfp);
    if (err) {
        printf("uc_open %d\n", err);
        return ;
        
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
    code_md5= read_file("/Volumes/extData/vm/llvm_dylib/TD_VM_CC/build/Debug/obj_su/local/arm64-v8a/md5_1", &code_len);
    err=uc_mem_write(uc, ADDRESS_CODE, code_md5, code_len);
    
    if (err) {
        printf("Failed on uc_mem_write() with error returned: %u (%s)\n",
               err, uc_strerror(err));
        return;
    }
    
    //设置一个指令执行回调用，该回调函数会在指令执行前被调用
    uc_hook_add(uc, &trace2, UC_HOOK_CODE, hook_code_md5, NULL, ADDRESS_CODE, ADDRESS_CODE+0x1634);
    
    MD5_CTX md5={0};  //定义一个MD5 text
    //md5_context_init(&md5);
    err=uc_mem_map(uc, MEM_ADDR, STACK_SIZE*4, UC_PROT_ALL);
    if(err){
        printf("Failed on uc_mem_map() with error returned: %u (%s)\n",
               err, uc_strerror(err));
    }
    MD5Init(&md5);//初始化
    unsigned char encrypt[] ="testdongun";//要加密内容
    size_t len_sr =strlen(encrypt);
    int64_t address_md5=get_mem_addres(sizeof(MD5_CTX));
    uc_mem_write(uc, address_md5, &md5, sizeof(MD5_CTX));
    uc_reg_write(uc, UC_ARM64_REG_X0, &address_md5);//第一个参数
    int64_t address=get_mem_addres(len_sr);
    uc_mem_write(uc, address, encrypt, len_sr);
    uc_reg_write(uc, UC_ARM64_REG_X1, &address);//第二个参数 md5字符串
    uc_reg_write(uc, UC_ARM64_REG_X2, &len_sr);//第三个参数  md5字符串长度
    err = uc_emu_start(uc, ADDRESS_CODE+0x850, ADDRESS_CODE+0x924, 0, 0);//MD5Update
    if (err) {
        printf("Failed on uc_emu_start() with error returned: %u (%s)\n",
               err, uc_strerror(err));
        return;
    }
    //MD5Final
    MD5_CTX md51={0};  //定义一个MD5 text
    uc_mem_read(uc, address_md5, &md51, sizeof(MD5_CTX));
    int64_t address_md52=get_mem_addres(sizeof(MD5_CTX));
    uc_mem_write(uc, address_md52,&md51, sizeof(MD5_CTX));
    uc_reg_write(uc, UC_ARM64_REG_X0, &address_md52);//x0  md5
    unsigned char decrypt[16]; //加密结果
    int64_t address_decrypt=get_mem_addres(16);
    uc_mem_write(uc, address_decrypt, &decrypt, 16);
    uc_reg_write(uc, UC_ARM64_REG_X1, &address_decrypt);//x1  out
    
    err = uc_emu_start(uc, ADDRESS_CODE+0x134C, ADDRESS_CODE+0x1590, 0, 0);
    // now print out some registers
    
    MD5_CTX md52={0};
    uc_mem_read(uc, address_decrypt, decrypt, 16);
    uc_mem_read(uc, address_md52, &md52, sizeof(MD5_CTX));
    int i=0;
    for(i=4;i<12;i++)
    {
        printf("%02x",decrypt[i]);  //02x前需要加上 %
    }
    
    printf("\n加密前:%s\n加密后32位:",encrypt);
    for(i=0;i<16;i++)
    {
        printf("%02x",decrypt[i]);  //02x前需要加上 %
    }
    uc_close(uc);
}
static void hook_code_md5_transform(uc_engine *uc, uint64_t pc_address, uint32_t size, void *user_data)
{
    uc_err err;
    printf(">>> Tracing hook_code at 0x%"PRIx64 ", instruction size = 0x%x\n", pc_address, size);
    switch (pc_address)
    {
        case 0x934:
        {
            unsigned int state[4];
            unsigned char block[64];
            int64_t x0=0;
            int64_t x1=0;
            uc_reg_read(uc, UC_ARM64_REG_X0, &x0);
            uc_reg_read(uc, UC_ARM64_REG_X1, &x1);
            uc_mem_read(uc, x0, state, 16);
            uc_mem_read(uc, x1, block, 64);
            break;
        }
        case 0x938:
        {
            unsigned int state[4];
            unsigned char block[64];
            int64_t x0=0;
            int64_t x1=0;
            uc_reg_read(uc, UC_ARM64_REG_X0, &x0);
            uc_reg_read(uc, UC_ARM64_REG_X1, &x1);
            uc_mem_read(uc, x0, state, 16);
            uc_mem_read(uc, x1, block, 64);
            int64_t address =0x0000000009100000;
            uc_reg_write(uc, UC_ARM64_REG_X0, &address);
            break;
        }
        default:
            break;
    }
}
void MD5Init(MD5_CTX *context)
{
    context->count[0] = 0;
    context->count[1] = 0;
    //分别赋固定值
    context->state[0] = 0x67452301;
    context->state[1] = 0xEFCDAB89;
    context->state[2] = 0x98BADCFE;
    context->state[3] = 0x10325476;
}
