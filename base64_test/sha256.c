//
//  sha256.c
//  base64_test
//
//  Created by fcj on 2018/11/2.
//  Copyright © 2018年 fcj. All rights reserved.
//

#include "sha256.h"
#include "uc_unit.h"

char *code_sha256=0;
uint32_t code_len_sha256=0;
void hook_code_sha256(uc_engine *uc, uint64_t pc_address, uint32_t size, void *user_data);
void testsha256(void)
{
    SHA256_CTX ctx;
    sha256_init(&ctx);
    char *str="tongdun";
    size_t len_str=strlen(str);
    code_sha256= read_file("/Volumes/extData/vm/llvm_dylib/TD_VM_CC/build/Debug/obj_su/local/arm64-v8a/sha256", &code_len_sha256);
    function_info sha256_update_info={0,(int64_t)code_sha256,code_len_sha256,0x958,0x9DC,\
        hook_code_sha256,3,{&ctx,&str,&len_str},{sizeof(SHA256_CTX),len_str,0x40000}};

    uc_engine *uc_new =call_function(&sha256_update_info);
    
    SHA256_CTX ctx1={0};
    int64_t x0=0;
    uc_reg_read(uc_new, UC_ARM64_REG_X0, &x0);
    uc_mem_read(uc_new, x0, &ctx1, sizeof(SHA256_CTX));
    uc_close(uc_new);
    char buf[SHA256_BLOCK_SIZE]={0};
    function_info sha256_final_info={0,(int64_t)code_sha256,code_len_sha256,0x9E0,0xC1C,\
        hook_code_sha256,2,{&ctx1,&buf},{sizeof(SHA256_CTX),SHA256_BLOCK_SIZE}};
    uc_engine *uc_new1 =call_function(&sha256_final_info);
    uc_reg_read(uc_new, UC_ARM64_REG_X0, &x0);
    uc_mem_read(uc_new, x0, &ctx1, sizeof(SHA256_CTX));
}

void hook_code_sha256(uc_engine *uc, uint64_t pc_address, uint32_t size, void *user_data)

{
    printf(">>> Tracing hook_code at 0x%"PRIx64 ", instruction size = 0x%x\n", pc_address, size);
    int64_t pc_address1=pc_address&0xFFFF;
    switch (pc_address1)
    {
        case 0x9a8://sha256_transform
        case 0xA5C:
        case 0xAC8:
        {
            
            int64_t x0,x1;
            SHA256_CTX ctx={0};
            char buff[0x100]={0};
            uc_reg_read(uc, UC_ARM64_REG_X0, &x0);
            uc_reg_read(uc, UC_ARM64_REG_X1, &x1);
            uc_mem_read(uc, x0, &ctx, sizeof(SHA256_CTX));
            uc_mem_read(uc, x1, buff, 64);
            
            function_info sha256_transform_info={0,(int64_t)code_sha256,code_len_sha256,0x788,0x918,\
                hook_code_sha256,2,{&ctx,&buff},{sizeof(SHA256_CTX),64}};
            uc_engine *uc_new1 =call_function(&sha256_transform_info);
            
            if(uc_new1 ==0){
                printf("************* !!!!!!!!!!! error\n");
            }
            int64_t address_p1=sha256_transform_info.func_memaddr;
            uc_mem_read(uc_new1, address_p1, &ctx, 16);
            int64_t address_p2=sha256_transform_info.func_memaddr+0x100;
            uc_mem_read(uc_new1, address_p2, buff, 64);
            uc_close(uc_new1);
            uc_mem_write(uc, x0, &ctx, sizeof(SHA256_CTX));//把数据考回到x0中
            uc_mem_write(uc, x1, buff , 64);
            int64_t pc=pc_address;
            pc+=4;
            uc_reg_write(uc, UC_ARM64_REG_PC, &pc);
            break;
        }
        case 0xA2C://memset
        {
            bl_memset_function(uc,pc_address);
            break;
        }
        case 0xBF0:
        {
            break;
        }
        case 0xC04:
        {
            break;
        }
        default:
            break;
    }
}
void sha256_init(SHA256_CTX *ctx)
{
    ctx->datalen = 0;
    ctx->bitlen = 0;
    ctx->state[0] = 0x6a09e667;
    ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372;
    ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f;
    ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab;
    ctx->state[7] = 0x5be0cd19;
}
