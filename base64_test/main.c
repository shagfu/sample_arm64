//
//  main.c
//  base64_test
//
//  Created by fcj on 2018/10/24.
//  Copyright © 2018年 fcj. All rights reserved.
//

#include <stdio.h>
#include <unicorn/unicorn.h>
#include "uc_unit.h"

// code to be emulated
uc_engine *uc;
void base64_decode(void);
void MD5Transform(unsigned int state[4],unsigned char block[64]);
void MD5Encode(unsigned char *output,unsigned int *input,unsigned int len);
void MD5Decode(unsigned int *output,unsigned char *input,unsigned int len);
char * base64str="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
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
static void hook_code(uc_engine *uc, uint64_t pc_address, uint32_t size, void *user_data)
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
            adrp_relo_function(uc,pc_address,strda);
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
static void hook_code_md5(uc_engine *uc, uint64_t pc_address, uint32_t size, void *user_data)
{
    uc_err err;
    printf(">>> Tracing hook_code at 0x%"PRIx64 ", instruction size = 0x%x\n", pc_address, size);
    switch (pc_address)
    {
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
            int64_t x0,x1;
            uc_reg_read(uc,UC_ARM64_REG_X0,&x0);
            uc_reg_read(uc,UC_ARM64_REG_X1,&x1);
            unsigned int state[4];
            unsigned char block[64];
            uc_mem_read(uc, x0, state, 16);
            uc_mem_read(uc, x0, block, 64);
            MD5Transform(state, block);
            int64_t address=get_mem_addres(16);
            uc_mem_write(uc, address, state, 16);
            uc_reg_write(uc, UC_ARM64_REG_X0, &address);
            address=get_mem_addres(64);
            uc_mem_write(uc, address, block, 64);
            uc_reg_write(uc, UC_ARM64_REG_X1, &address);
            int64_t pc=pc_address;
            pc+=4;
            uc_reg_write(uc, UC_ARM64_REG_PC, &pc);
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
void md5_test()
{
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
    uint32_t len = 0;
    char* code = read_file("/Volumes/extData/vm/llvm_dylib/TD_VM_CC/build/Debug/obj_su/local/arm64-v8a/md5_1", &len);
    err=uc_mem_write(uc, ADDRESS_CODE, code, len);
    
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
    unsigned char encrypt[] ="admin";//要加密内容
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
    address=get_mem_addres(sizeof(MD5_CTX));
    uc_mem_write(uc, address,&md51, sizeof(MD5_CTX));
    uc_reg_write(uc, UC_ARM64_REG_X0, &address);//x0  md5
    unsigned char decrypt[16]; //加密结果
    address=get_mem_addres(16);
    uc_mem_write(uc, address, &decrypt, 16);
    uc_reg_write(uc, UC_ARM64_REG_X1, &address);//x1  out

    err = uc_emu_start(uc, ADDRESS_CODE+0x134C, ADDRESS_CODE+0x1590, 0, 0);
    // now print out some registers
    
    uc_mem_read(uc, address, decrypt, 16);
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
int main(int argc, const char * argv[]) {
    // insert code here...
    md5_test();
    printf("Hello, World!\n");
    return 0;
}
void base64_decode()
{
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
void MD5Transform(unsigned int state[4],unsigned char block[64])
{
    //a b c d继承上一个加密的结果，所以其具有继承性
    unsigned int a = state[0];
    unsigned int b = state[1];
    unsigned int c = state[2];
    unsigned int d = state[3];
    
    //这里只需用到16个，我把原来的unsiged int x[64]  改为了 x[16]
    unsigned int x[16];
    
    //把字符转化成数字，便于运算
    MD5Decode(x,block,64);
    
    
    //具体函数方式固定，不再赘述
    
    /*************第一轮******************/
    FF(a, b, c, d, x[ 0], 7, 0xd76aa478);
    FF(d, a, b, c, x[ 1], 12, 0xe8c7b756);
    FF(c, d, a, b, x[ 2], 17, 0x242070db);
    FF(b, c, d, a, x[ 3], 22, 0xc1bdceee);
    
    FF(a, b, c, d, x[ 4], 7, 0xf57c0faf);
    FF(d, a, b, c, x[ 5], 12, 0x4787c62a);
    FF(c, d, a, b, x[ 6], 17, 0xa8304613);
    FF(b, c, d, a, x[ 7], 22, 0xfd469501);
    
    FF(a, b, c, d, x[ 8], 7, 0x698098d8);
    FF(d, a, b, c, x[ 9], 12, 0x8b44f7af);
    FF(c, d, a, b, x[10], 17, 0xffff5bb1);
    FF(b, c, d, a, x[11], 22, 0x895cd7be);
    
    FF(a, b, c, d, x[12], 7, 0x6b901122);
    FF(d, a, b, c, x[13], 12, 0xfd987193);
    FF(c, d, a, b, x[14], 17, 0xa679438e);
    FF(b, c, d, a, x[15], 22, 0x49b40821);
    
    
    /*************第二轮*****************/
    GG(a, b, c, d, x[ 1], 5, 0xf61e2562);
    GG(d, a, b, c, x[ 6], 9, 0xc040b340);
    GG(c, d, a, b, x[11], 14, 0x265e5a51);
    GG(b, c, d, a, x[ 0], 20, 0xe9b6c7aa);
    
    GG(a, b, c, d, x[ 5], 5, 0xd62f105d);
    GG(d, a, b, c, x[10], 9,  0x2441453);
    GG(c, d, a, b, x[15], 14, 0xd8a1e681);
    GG(b, c, d, a, x[ 4], 20, 0xe7d3fbc8);
    
    GG(a, b, c, d, x[ 9], 5, 0x21e1cde6);
    GG(d, a, b, c, x[14], 9, 0xc33707d6);
    GG(c, d, a, b, x[ 3], 14, 0xf4d50d87);
    GG(b, c, d, a, x[ 8], 20, 0x455a14ed);
    
    GG(a, b, c, d, x[13], 5, 0xa9e3e905);
    GG(d, a, b, c, x[ 2], 9, 0xfcefa3f8);
    GG(c, d, a, b, x[ 7], 14, 0x676f02d9);
    GG(b, c, d, a, x[12], 20, 0x8d2a4c8a);
    
    
    /*************第三轮*****************/
    HH(a, b, c, d, x[ 5], 4, 0xfffa3942);
    HH(d, a, b, c, x[ 8], 11, 0x8771f681);
    HH(c, d, a, b, x[11], 16, 0x6d9d6122);
    HH(b, c, d, a, x[14], 23, 0xfde5380c);
    
    HH(a, b, c, d, x[ 1], 4, 0xa4beea44);
    HH(d, a, b, c, x[ 4], 11, 0x4bdecfa9);
    HH(c, d, a, b, x[ 7], 16, 0xf6bb4b60);
    HH(b, c, d, a, x[10], 23, 0xbebfbc70);
    
    HH(a, b, c, d, x[13], 4, 0x289b7ec6);
    HH(d, a, b, c, x[ 0], 11, 0xeaa127fa);
    HH(c, d, a, b, x[ 3], 16, 0xd4ef3085);
    HH(b, c, d, a, x[ 6], 23,  0x4881d05);
    
    HH(a, b, c, d, x[ 9], 4, 0xd9d4d039);
    HH(d, a, b, c, x[12], 11, 0xe6db99e5);
    HH(c, d, a, b, x[15], 16, 0x1fa27cf8);
    HH(b, c, d, a, x[ 2], 23, 0xc4ac5665);
    
    
    
    /*************第四轮******************/
    II(a, b, c, d, x[ 0], 6, 0xf4292244);
    II(d, a, b, c, x[ 7], 10, 0x432aff97);
    II(c, d, a, b, x[14], 15, 0xab9423a7);
    II(b, c, d, a, x[ 5], 21, 0xfc93a039);
    
    II(a, b, c, d, x[12], 6, 0x655b59c3);
    II(d, a, b, c, x[ 3], 10, 0x8f0ccc92);
    II(c, d, a, b, x[10], 15, 0xffeff47d);
    II(b, c, d, a, x[ 1], 21, 0x85845dd1);
    
    II(a, b, c, d, x[ 8], 6, 0x6fa87e4f);
    II(d, a, b, c, x[15], 10, 0xfe2ce6e0);
    II(c, d, a, b, x[ 6], 15, 0xa3014314);
    II(b, c, d, a, x[13], 21, 0x4e0811a1);
    
    II(a, b, c, d, x[ 4], 6, 0xf7537e82);
    II(d, a, b, c, x[11], 10, 0xbd3af235);
    II(c, d, a, b, x[ 2], 15, 0x2ad7d2bb);
    II(b, c, d, a, x[ 9], 21, 0xeb86d391);
    
    
    //更换原来的结果
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
}

void MD5Encode(unsigned char *output,unsigned int *input,unsigned int len)
{
    unsigned int i = 0,j = 0;
    while(j < len)
    {
        //这里& 0xFF为取后8位
        //i代表数字数组下标
        //j代表字符数组下标
        //把数字的8、8-16、16-24、24-32分别赋值给字符
        output[j] = input[i] & 0xFF;
        output[j+1] = (input[i] >> 8) & 0xFF;
        output[j+2] = (input[i] >> 16) & 0xFF;
        output[j+3] = (input[i] >> 24) & 0xFF;
        i++;
        j+=4;
    }
}
/**********************************************************
 * 函数功能：利用位操作，按4->1方式把字符合成数字
 *
 * 参数分析：
 * unsigned int  *output ：输出的数字的数组
 * unsigned char *input  ：输入字符的数组
 * unsigned int  len     : 输入字符的长度 （单位：位）
 * *********************************************************/

void MD5Decode(unsigned int *output,unsigned char *input,unsigned int len)
{
    unsigned int i = 0,j = 0;
    while(j < len)
    {
        //利用位操作，把四个单位为1字节的字符，合成一个单位为4字节的数字
        //因为FF GG HH II和非线性函数都只能对数字进行处理
        //第一个字符占前8位，第二个占8-16位，第三个占16-24位，第四个占
        //24-32位。
        //i代表数字数组下标
        //j代表字符数组下标
        output[i] = (input[j]) |
        (input[j+1] << 8) |
        (input[j+2] << 16) |
        (input[j+3] << 24);
        i++;
        j+=4;
    }
}
