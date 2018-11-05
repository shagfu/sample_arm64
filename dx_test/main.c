/* Unicorn Emulator Engine */
/* By Nguyen Anh Quynh, 2015 */

/* Sample code to demonstrate how to emulate ARM64 code */

#include <unicorn/unicorn.h>
#include <string.h>

#define STACK_ADDR  0x8000000
#define STACK_SIZE  1024*4
#define MEM_ADDR    STACK_ADDR+STACK_SIZE
// code to be emulated
#define ARM_CODE "\xab\x05\x00\xb8\xaf\x05\x40\x38" // str w11, [x13]; ldrb w15, [x13]

// memory address where emulation starts
#define ADDRESS 0x10000
#define code_begin  0x3992B8
int   m_mem_pos=0;
static void print_reg(uc_engine *uc, uint32_t address)
{
#ifdef DEBUG
    uint32_t pc = 0;
    uc_reg_read(uc, UC_ARM_REG_PC, &pc);
    if (pc == address)
    {
        printf("========================\n");        printf("Break on 0x%x\n", pc);
        uint32_t values = 0;
        uc_reg_read(uc, UC_ARM64_REG_X0, &values);        printf("X0 = 0x%x \n", values);
        uc_reg_read(uc, UC_ARM64_REG_X1, &values);        printf("X1 = 0x%x \n", values);
        uc_reg_read(uc, UC_ARM64_REG_X2, &values);        printf("X2 = 0x%x \n", values);
        uc_reg_read(uc, UC_ARM64_REG_X3, &values);        printf("X3 = 0x%x \n", values);
        uc_reg_read(uc, UC_ARM64_REG_X4, &values);        printf("X4 = 0x%x \n", values);
        uc_reg_read(uc, UC_ARM64_REG_X5, &values);        printf("X5 = 0x%x \n", values);
        uc_reg_read(uc, UC_ARM64_REG_X6, &values);        printf("X6 = 0x%x \n", values);
        uc_reg_read(uc, UC_ARM_REG_PC, &values);        printf("PC = 0x%x \n", values);
        uc_reg_read(uc, UC_ARM_REG_SP, &values);        printf("SP = 0x%x \n", values);
        printf("========================\n");
    }
#endif // DEBUG
}
static void hook_block(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    printf(">>> Tracing basic block at 0x%"PRIx64 ", block size = 0x%x\n", address, size);
}

static void hook_code(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    printf(">>> Tracing instruction at 0x%"PRIx64 ", instruction size = 0x%x\n", address, size);
}
static  char* read_file(char* path, uint32_t* len)
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
static void test_arm64_c950(void)
{
    uc_engine *uc;
    uc_err err;
    uc_hook trace1, trace2;
    
    
    
    printf("Emulate ARM64 code\n");
    
    // Initialize emulator in ARM mode
    err = uc_open(UC_ARCH_ARM64, UC_MODE_ARM, &uc);
    if (err) {
        printf("Failed on uc_open() with error returned: %u (%s)\n",
               err, uc_strerror(err));
        return;
    }
    
    // map 2MB memory for this emulation
    uc_mem_map(uc, ADDRESS, 100 * 1024 * 1024, UC_PROT_ALL);
    
    
    err=uc_mem_map(uc, STACK_ADDR, STACK_SIZE, UC_PROT_ALL);
    if(err){
        printf("Failed on uc_mem_map() with error returned: %u (%s)\n",
               err, uc_strerror(err));
    }
    uint64_t sp_address=(STACK_ADDR + STACK_SIZE/2);
    err=uc_reg_write(uc,  UC_ARM64_REG_SP, &sp_address);//分配栈内存
    
    
    err=uc_mem_map(uc, MEM_ADDR, STACK_SIZE*4, UC_PROT_ALL);
    if(err){
        printf("Failed on uc_mem_map() with error returned: %u (%s)\n",
               err, uc_strerror(err));
    }
    
    uint32_t len = 0;
    char* code = read_file("/Users/fcj/Desktop/product/dx/DXRiskWithIDFA", &len);
    // write machine code to be emulated to memory
    //uc_mem_write(uc, ADDRESS+0x92B8, tmpcode, 0x1000);
    err=uc_mem_write(uc, ADDRESS, code, len);
    uc_hook_add(uc, &trace2, UC_HOOK_CODE, hook_code, NULL, 0, 0);
    
    
    
    unsigned char encdata[] = {
        0x94, 0x19, 0x59, 0x10, 0x5D, 0x28, 0x5B, 0x2C, 0x94, 0x1F, 0x66, 0x1B, 0x94, 0x1A, 0x5B, 0x28,
        0x58, 0x11, 0xC7, 0x00
    };
    char buff[0x200]={0};
    err=uc_mem_write(uc, MEM_ADDR, buff, sizeof(buff));
    if(err){
        printf("Failed on uc_mem_write() with error returned: %u (%s)\n",
               err, uc_strerror(err));
    }
    int64_t address=MEM_ADDR;
    err=uc_reg_write(uc, UC_ARM64_REG_X0, &address);
    
    
    int w1=0x13;//enc 长度
    int w4=0x2; //key len 长度
    int w5=0xF1;
    
    
    char  x3_buff[]={0x36, 0x78,0x00};
    err=uc_reg_write(uc, UC_ARM64_REG_W1, &w1);
    err=uc_mem_write(uc, MEM_ADDR+0x2000, encdata, sizeof(encdata));
    if(err){
        printf("Failed on uc_mem_write() with error returned: %u (%s)\n",
               err, uc_strerror(err));
    }
    address=MEM_ADDR+0x2000;
    err=uc_reg_write(uc, UC_ARM64_REG_X2, &address);//写入X2
    err=uc_mem_write(uc, MEM_ADDR+0x3000, x3_buff, sizeof(x3_buff));
    if(err){
        printf("Failed on uc_mem_write() with error returned: %u (%s)\n",
               err, uc_strerror(err));
    }
    address=MEM_ADDR+0x3000;
    err=uc_reg_write(uc, UC_ARM64_REG_X3, &address);
    err=uc_reg_write(uc, UC_ARM64_REG_W4, &w4);
    err=uc_reg_write(uc, UC_ARM64_REG_W5, &w5);
    err = uc_emu_start(uc, ADDRESS+0x39c950, ADDRESS+0x39C984, 0, 0);
    uc_mem_read(uc, MEM_ADDR, buff, sizeof(buff));
    printf("decrypt str== %s\n",buff);
    if (err) {
        printf("Failed on uc_mem_write() with error returned: %u (%s)\n",
               err, uc_strerror(err));
    }
    
    //uc_reg_read(uc, UC_ARM64_REG_X15, &x15);
    //printf(">>> X15 = 0x%" PRIx64 "\n", x15);
    
    uc_close(uc);
}
static void test_arm64_9328(void)
{
    uc_engine *uc;
    uc_err err;
    uc_hook trace1, trace2;
    
    
    
    printf("Emulate ARM64 code\n");
    
    // Initialize emulator in ARM mode
    err = uc_open(UC_ARCH_ARM64, UC_MODE_ARM, &uc);
    if (err) {
        printf("Failed on uc_open() with error returned: %u (%s)\n",
               err, uc_strerror(err));
        return;
    }
    
    // map 2MB memory for this emulation
    uc_mem_map(uc, ADDRESS, 100 * 1024 * 1024, UC_PROT_ALL);
    
    
    err=uc_mem_map(uc, STACK_ADDR, STACK_SIZE, UC_PROT_ALL);
    if(err){
        printf("Failed on uc_mem_map() with error returned: %u (%s)\n",
               err, uc_strerror(err));
    }
    uint64_t sp_address=(STACK_ADDR + STACK_SIZE/2);
    err=uc_reg_write(uc,  UC_ARM64_REG_SP, &sp_address);//分配栈内存
    
    
    err=uc_mem_map(uc, MEM_ADDR, STACK_SIZE*4, UC_PROT_ALL);
    if(err){
        printf("Failed on uc_mem_map() with error returned: %u (%s)\n",
               err, uc_strerror(err));
    }
    
    uint32_t len = 0;
    char* code = read_file("/Users/fcj/Desktop/product/dx/DXRiskWithIDFA", &len);
    // write machine code to be emulated to memory
    //uc_mem_write(uc, ADDRESS+0x92B8, tmpcode, 0x1000);
    err=uc_mem_write(uc, ADDRESS, code, len);
    uc_hook_add(uc, &trace2, UC_HOOK_CODE, hook_code, NULL, 0, 0);
    
    unsigned char encdata[] = {
        0x76, 0x9A, 0xE9, 0x4F, 0x9A, 0x2B, 0x12, 0x2B, 0xED, 0x2B, 0x2F, 0xA7, 0x84,0x00
    };
    char buff[0x200]={0};
    err=uc_mem_write(uc, MEM_ADDR, buff, sizeof(buff));
    if(err){
        printf("Failed on uc_mem_write() with error returned: %u (%s)\n",
               err, uc_strerror(err));
    }
    int64_t address=MEM_ADDR;
    err=uc_reg_write(uc, UC_ARM64_REG_X0, &address);
    
    
    int w1=0xD;//enc 长度
    int w4=0x3; //key len 长度
    int w5=0x9F;
    
    
    char  x3_buff[]={0x5A, 0x6C,0x50,0x00};
    err=uc_reg_write(uc, UC_ARM64_REG_W1, &w1);
    err=uc_mem_write(uc, MEM_ADDR+0x2000, encdata, sizeof(encdata));
    if(err){
        printf("Failed on uc_mem_write() with error returned: %u (%s)\n",
               err, uc_strerror(err));
    }
    address=MEM_ADDR+0x2000;
    err=uc_reg_write(uc, UC_ARM64_REG_X2, &address);//写入X2
    err=uc_mem_write(uc, MEM_ADDR+0x3000, x3_buff, sizeof(x3_buff));
    if(err){
        printf("Failed on uc_mem_write() with error returned: %u (%s)\n",
               err, uc_strerror(err));
    }
    address=MEM_ADDR+0x3000;
    err=uc_reg_write(uc, UC_ARM64_REG_X3, &address);
    err=uc_reg_write(uc, UC_ARM64_REG_W4, &w4);
    err=uc_reg_write(uc, UC_ARM64_REG_W5, &w5);
    err = uc_emu_start(uc, ADDRESS+0x399328, ADDRESS+0x3994f4, 0, 0);
    uc_mem_read(uc, MEM_ADDR, buff, sizeof(buff));
    printf("decrypt str== %s\n",buff);
    if (err) {
        printf("Failed on uc_mem_write() with error returned: %u (%s)\n",
               err, uc_strerror(err));
    }
    
    //uc_reg_read(uc, UC_ARM64_REG_X15, &x15);
    //printf(">>> X15 = 0x%" PRIx64 "\n", x15);
    
    uc_close(uc);
}
static void test_arm64_92B8(void)
{
    uc_engine *uc;
    uc_err err;
    uc_hook trace1, trace2;
    

    
    printf("Emulate ARM64 code\n");
    
    // Initialize emulator in ARM mode
    err = uc_open(UC_ARCH_ARM64, UC_MODE_ARM, &uc);
    if (err) {
        printf("Failed on uc_open() with error returned: %u (%s)\n",
               err, uc_strerror(err));
        return;
    }
   
    // map 2MB memory for this emulation
    uc_mem_map(uc, ADDRESS, 100 * 1024 * 1024, UC_PROT_ALL);
    
    
    err=uc_mem_map(uc, STACK_ADDR, STACK_SIZE, UC_PROT_ALL);
    if(err){
        printf("Failed on uc_mem_map() with error returned: %u (%s)\n",
               err, uc_strerror(err));
    }
    uint64_t sp_address=(STACK_ADDR + STACK_SIZE/2);
    err=uc_reg_write(uc,  UC_ARM64_REG_SP, &sp_address);//分配栈内存
    
    
    err=uc_mem_map(uc, MEM_ADDR, STACK_SIZE*4, UC_PROT_ALL);
    if(err){
        printf("Failed on uc_mem_map() with error returned: %u (%s)\n",
               err, uc_strerror(err));
    }
    
    uint32_t len = 0;
    char* code = read_file("/Users/fcj/Desktop/product/dx/DXRiskWithIDFA", &len);
    // write machine code to be emulated to memory
    //uc_mem_write(uc, ADDRESS+0x92B8, tmpcode, 0x1000);
    err=uc_mem_write(uc, ADDRESS, code, len);
    uc_hook_add(uc, &trace2, UC_HOOK_CODE, hook_code, NULL, 0, 0);
    


    unsigned char encdata[] = {
        0xE5, 0xF9, 0xF8, 0x9C, 0x8C, 0x4F, 0x9E, 0xF9, 0xFB, 0x20, 0xF1, 0x88, 0x94, 0x48, 0x8A, 0x97,
        0xFA, 0xFD, 0xE7, 0xF6, 0xFB, 0x20, 0x93, 0x9F, 0x20, 0x8B, 0x8B, 0xE4, 0xFA, 0x88, 0x95, 0xFD,
        0x4F, 0x91, 0x8E, 0x4F, 0xE7, 0xF6, 0xBF, 0x3A, 0x68, 0x00
    };
    char buff[0x200]={0};
    err=uc_mem_write(uc, MEM_ADDR, buff, sizeof(buff));
    if(err){
        printf("Failed on uc_mem_write() with error returned: %u (%s)\n",
               err, uc_strerror(err));
    }
    int64_t address=MEM_ADDR;
    err=uc_reg_write(uc, UC_ARM64_REG_X0, &address);

    
    int w1=0x29;//enc 长度
    int w4=0x3; //key len 长度
    int w5=0xA7;


    char  x3_buff[]={0x59, 0x31, 0x36,0x00};
    err=uc_reg_write(uc, UC_ARM64_REG_W1, &w1);
    err=uc_mem_write(uc, MEM_ADDR+0x2000, encdata, sizeof(encdata));
    if(err){
        printf("Failed on uc_mem_write() with error returned: %u (%s)\n",
               err, uc_strerror(err));
    }
    address=MEM_ADDR+0x2000;
    err=uc_reg_write(uc, UC_ARM64_REG_X2, &address);//写入X2
    err=uc_mem_write(uc, MEM_ADDR+0x3000, x3_buff, sizeof(x3_buff));
    if(err){
        printf("Failed on uc_mem_write() with error returned: %u (%s)\n",
               err, uc_strerror(err));
    }
    address=MEM_ADDR+0x3000;
    err=uc_reg_write(uc, UC_ARM64_REG_X3, &address);
    err=uc_reg_write(uc, UC_ARM64_REG_W4, &w4);
    err=uc_reg_write(uc, UC_ARM64_REG_W5, &w5);
    err = uc_emu_start(uc, ADDRESS+code_begin, ADDRESS+code_begin+0x40, 0, 0);
    uc_mem_read(uc, MEM_ADDR, buff, sizeof(buff));
    printf("decrypt str== %s\n",buff);
    if (err) {
        printf("Failed on uc_mem_write() with error returned: %u (%s)\n",
               err, uc_strerror(err));
    }
    
    //uc_reg_read(uc, UC_ARM64_REG_X15, &x15);
    //printf(">>> X15 = 0x%" PRIx64 "\n", x15);
    
    uc_close(uc);
}
static void test_arm64_92F0(void)
{
    uc_engine *uc;
    uc_err err;
    uc_hook trace1, trace2;
    
    
    
    printf("Emulate ARM64 code\n");
    
    // Initialize emulator in ARM mode
    err = uc_open(UC_ARCH_ARM64, UC_MODE_ARM, &uc);
    if (err) {
        printf("Failed on uc_open() with error returned: %u (%s)\n",
               err, uc_strerror(err));
        return;
    }
    
    // map 2MB memory for this emulation
    uc_mem_map(uc, ADDRESS, 100 * 1024 * 1024, UC_PROT_ALL);
    
    
    err=uc_mem_map(uc, STACK_ADDR, STACK_SIZE, UC_PROT_ALL);
    if(err){
        printf("Failed on uc_mem_map() with error returned: %u (%s)\n",
               err, uc_strerror(err));
    }
    uint64_t sp_address=(STACK_ADDR + STACK_SIZE/2);
    err=uc_reg_write(uc,  UC_ARM64_REG_SP, &sp_address);//分配栈内存
    
    
    err=uc_mem_map(uc, MEM_ADDR, STACK_SIZE*4, UC_PROT_ALL);
    if(err){
        printf("Failed on uc_mem_map() with error returned: %u (%s)\n",
               err, uc_strerror(err));
    }
    
    uint32_t len = 0;
    char* code = read_file("/Users/fcj/Desktop/product/dx/DXRiskWithIDFA", &len);
    // write machine code to be emulated to memory
    //uc_mem_write(uc, ADDRESS+0x92B8, tmpcode, 0x1000);
    err=uc_mem_write(uc, ADDRESS, code, len);
    uc_hook_add(uc, &trace2, UC_HOOK_CODE, hook_code, NULL, 0, 0);
    
    
    
    unsigned char encdata[] = {
        0x97, 0xAA, 0xB9, 0x32, 0xB9, 0xB9, 0x17, 0xB2, 0x34, 0xB7, 0x33, 0xBC, 0xB4, 0x30, 0xB7, 0xB3,
        0x17, 0xB1, 0xBA, 0x34, 0x36, 0xB2, 0xB9, 0x17, 0x18, 0x32, 0x1B, 0x1C, 0x32, 0x98, 0x99, 0xB0,
        0x17, 0x98, 0x97, 0x39, 0xB2, 0xB5, 0x17, 0x32, 0xBC, 0x16, 0xB9, 0xB4, 0xB9, 0xB5, 0x17, 0xBC,
        0xB1, 0x37, 0xB2, 0xB2, 0x2F, 0x38, 0xB9, 0x37, 0xB5, 0x97, 0x29, 0xAA, 0xA2, 0x22, 0xA3, 0x37,
        0xB9, 0xB4, 0xA7, 0xA9, 0x17, 0x22, 0x2C, 0xA9, 0xB4, 0xB9, 0xB5, 0x97, 0xB4, 0xB7, 0xB9, 0x97,
        0xA6, 0x37, 0xB2, 0x32, 0xB6, 0x17, 0xA7, 0x32, 0xBA, 0xBB, 0x37, 0xB9, 0xB5, 0x17, 0xA9, 0xB2,
        0xB0, 0x31, 0xB4, 0x30, 0xB1, 0x34, 0xB6, 0x34, 0xBA, 0x3C, 0x97, 0x36, 0x80, 0x00
    };
    char buff[0x200]={0};
    err=uc_mem_write(uc, MEM_ADDR, buff, sizeof(buff));
    if(err){
        printf("Failed on uc_mem_write() with error returned: %u (%s)\n",
               err, uc_strerror(err));
    }
    int64_t address=MEM_ADDR;
    err=uc_reg_write(uc, UC_ARM64_REG_X0, &address);
    
    
    int w1=0x6D;//enc 长度
    int w4=0x0; //key len 长度
    int w5=0x1;
    
    
    char  x3_buff[]={0x59, 0x31, 0x36,0x00};
    err=uc_reg_write(uc, UC_ARM64_REG_W1, &w1);
    err=uc_mem_write(uc, MEM_ADDR+0x2000, encdata, sizeof(encdata));
    if(err){
        printf("Failed on uc_mem_write() with error returned: %u (%s)\n",
               err, uc_strerror(err));
    }
    address=MEM_ADDR+0x2000;
    err=uc_reg_write(uc, UC_ARM64_REG_X2, &address);//写入X2
    err=uc_mem_write(uc, MEM_ADDR+0x3000, x3_buff, sizeof(x3_buff));
    if(err){
        printf("Failed on uc_mem_write() with error returned: %u (%s)\n",
               err, uc_strerror(err));
    }
    address=MEM_ADDR+0x3000;
    err=uc_reg_write(uc, UC_ARM64_REG_X3, &address);
    err=uc_reg_write(uc, UC_ARM64_REG_W4, &w4);
    err=uc_reg_write(uc, UC_ARM64_REG_W5, &w5);
    err = uc_emu_start(uc, ADDRESS+0x3992F0, ADDRESS+0x399324, 0, 0);
    uc_mem_read(uc, MEM_ADDR, buff, sizeof(buff));
    printf("decrypt str== %s\n",buff);
    if (err) {
        printf("Failed on uc_mem_write() with error returned: %u (%s)\n",
               err, uc_strerror(err));
    }
    
    //uc_reg_read(uc, UC_ARM64_REG_X15, &x15);
    //printf(">>> X15 = 0x%" PRIx64 "\n", x15);
    
    uc_close(uc);
}

int main(int argc, char **argv, char **envp)
{
    // dynamically load shared library
#ifdef DYNLOAD
    if (!uc_dyn_load(NULL, 0)) {
        printf("Error dynamically loading shared library.\n");
        printf("Please check that unicorn.dll/unicorn.so is available as well as\n");
        printf("any other dependent dll/so files.\n");
        printf("The easiest way is to place them in the same directory as this app.\n");
        return 1;
    }
#endif
    
    test_arm64_92F0();
    
    // dynamically free shared library
#ifdef DYNLOAD
    uc_dyn_free();
#endif
    
    return 0;
}
