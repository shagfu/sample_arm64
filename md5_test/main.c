/* Unicorn Emulator Engine */
/* By Nguyen Anh Quynh, 2015 */

/* Sample code to demonstrate how to emulate ARM64 code */

#include <unicorn/unicorn.h>
#include <string.h>

#define ELF_HEADER_SIZE  0x40

#define STACK_ADDR  0x8000000
#define STACK_SIZE  1024*4

#define MEM_ADDR    STACK_ADDR+STACK_SIZE
// code to be emulated
uc_engine *uc;
int   m_mem_pos=0;
#define ARM_CODE "\xab\x05\x00\xb8\xaf\x05\x40\x38" // str w11, [x13]; ldrb w15, [x13]
#pragma pack(push)
typedef struct
{
    unsigned int count[2];//8
    //记录当前状态，其数据位数
    
    unsigned int state[4];//12
    //4个数，一共32位 记录用于保存对512bits信息加密的中间结果或者最终结果
    
    unsigned char buffer[64];
    //一共64字节，512位
}MD5_CTX;
#pragma pack(pop)
// memory address where emulation starts
#define ADDRESS_CODE 0x00000
#define code_begin  0x3992B8
void MD5Transform(unsigned int state[4],unsigned char block[64]);
static void print_reg(uc_engine *uc, uint32_t address)
{
#if     1
    uint32_t pc = 0;
    uc_reg_read(uc, UC_ARM_REG_PC, &pc);
    printf("========================\n");        printf("Break on 0x%x\n", address);
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
    if (pc == address)
    {

    }
#endif // DEBUG
}

unsigned char hexData[] = {
    0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10
};
void write_mem_uc(const void * address, uint32_t size)
{
    uc_err err;
    
    err=uc_mem_write(uc, MEM_ADDR+0x200*m_mem_pos, address, size);
    if(err){
        printf("Failed on uc_mem_write() with error returned: %u (%s)\n",
               err, uc_strerror(err));
    }
    m_mem_pos++;
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
unsigned char PADDING[]={0x80,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
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

#define UNICORN_HAS_ARM64 1
typedef uint64_t float64;
int64_t m_pc=0;
unsigned int state[4];
unsigned char block[64];
int64_t x0,x1;
static void hook_code(uc_engine *uc, uint64_t pc_address, uint32_t size, void *user_data)
{
    printf(">>> Tracing hook_code at 0x%"PRIx64 ", instruction size = 0x%x\n", pc_address, size);
    //print_reg(uc,address);
    switch (pc_address) {
        case 0x8BC:
        case 0x920://memcpy
        case 0x1410:
        case 0x146c:
        case 0x14BC:
        case 0x14E8:
        {
            
            char  buff[100]={0};
            int64_t x0,x1,x2;
            uc_reg_read(uc,UC_ARM64_REG_X0,&x0);
            uc_reg_read(uc,UC_ARM64_REG_X1,&x1);
            uc_reg_read(uc,UC_ARM64_REG_X2,&x2);
            uc_mem_read(uc, x1,buff , x2);
            uc_mem_write(uc, x0,buff , x2);
            
            //memcpy(x0, x1, x2);
            int64_t pc=pc_address;
            pc+=4;
            uc_reg_write(uc, UC_ARM64_REG_PC, &pc);
            break;
        }
        case 0x8CC:
        case 0x8E8://transfrom
        case 0x1420:
        case 0x143c:
        case 0x14c8:
        {
            
            m_pc=pc_address;
            int64_t pc=0x924;
            uc_reg_write(uc, UC_ARM64_REG_PC, &pc);
            //uc_err err = uc_emu_start(uc, ADDRESS_CODE+0x924, ADDRESS_CODE+0x1348, 0, 0);
            
            uc_reg_read(uc, UC_ARM64_REG_X0,&x0);
            uc_reg_read(uc, UC_ARM64_REG_X0,&x1);
            uc_mem_read(uc, x0, state, sizeof(state));
            uc_mem_read(uc, x0, block, sizeof(block));
            MD5Transform(state,block);
            break;
        }
        case 0x1348://end transfrom
        {
            int dd=10;
            m_pc+=4;
            uc_reg_write(uc, UC_ARM64_REG_PC, &m_pc);
            break;
        }
        case 0x82C://adrp
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
        case 0x830:
        {
            printf("dddd  0x830\n");
        }
        case 0x834:
        {
            /*
            uint32_t x;
            uc_reg_read(uc, UC_ARM64_REG_CPACR_EL1, &x);
            x |= 0x300000; // set FPEN bit
            uc_reg_write(uc, UC_ARM64_REG_CPACR_EL1, &x);
            */
            
            float64  aa;
            int64_t x8=0;
            int64_t x0=0;
            uc_reg_read(uc, UC_ARM64_REG_D0,&aa);
            uc_reg_read(uc, UC_ARM64_REG_X8,&x8);
            uc_reg_read(uc, UC_ARM64_REG_X0, &x0);
            
            int64_t pc=pc_address;
            //pc+=4;
            //uc_reg_write(uc, UC_ARM64_REG_PC, &pc);
            int dd=10;
        }
        default:
            break;
    }
}
void MD5Transform(unsigned int state[4],unsigned char block[64])
{
    uc_err err;
    uc_hook  trace2;
    int64_t address=MEM_ADDR+0x200*m_mem_pos;
    uc_mem_write(uc, address, state, 16);
    uc_reg_write(uc, UC_ARM64_REG_X0, &address);
    m_mem_pos++;
    address=MEM_ADDR+0x200*m_mem_pos;
    uc_mem_write(uc, address, block, 64);
    uc_reg_write(uc, UC_ARM64_REG_X1, &address);
    m_mem_pos++;
    //uc_hook_add(uc, &trace2, UC_HOOK_CODE, hook_code, NULL, ADDRESS_CODE+0x924, ADDRESS_CODE+0x1348);
    err = uc_emu_start(uc, ADDRESS_CODE+0x924, ADDRESS_CODE+0x1348, 0, 0);
    if (err) {
        printf("Failed on uc_emu_start() with error returned: %u (%s)\n",
               err, uc_strerror(err));
        return;
    }
    
}
static void test_arm64(void)
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

    MD5_CTX md5={0};  //定义一个MD5 text
    //md5_context_init(&md5);
    
    err=uc_mem_map(uc, MEM_ADDR, STACK_SIZE*4, UC_PROT_ALL);
    if(err){
        printf("Failed on uc_mem_map() with error returned: %u (%s)\n",
               err, uc_strerror(err));
    }
    if(1)
    {
        int64_t address=MEM_ADDR+0x200*m_mem_pos;
        uc_mem_write(uc, address, &md5, sizeof(MD5_CTX));
        uc_reg_write(uc, UC_ARM64_REG_X0, &address);
        err = uc_emu_start(uc, ADDRESS_CODE+0x828, ADDRESS_CODE+0x84C, 0, 0);
        MD5_CTX md51={0};  //定义一个MD5 text
        uc_mem_read(uc, address, &md51, sizeof(MD5_CTX));
        if (err) {
            printf("Failed on uc_emu_start() with error returned: %u (%s)\n",
                   err, uc_strerror(err));
            return;
        }
    }
    MD5Init(&md5);//初始化
    unsigned char encrypt[] ="admin";//要加密内容
    int len_sr =strlen(encrypt);
    int64_t address=MEM_ADDR+0x200*m_mem_pos;
    uc_mem_write(uc, address, &md5, sizeof(MD5_CTX));
    uc_reg_write(uc, UC_ARM64_REG_X0, &address);
    m_mem_pos++;
    address=MEM_ADDR+0x200*m_mem_pos;
    uc_mem_write(uc, address, &encrypt, len_sr);
    m_mem_pos++;
    uc_reg_write(uc, UC_ARM64_REG_X1, &address);
    uc_reg_write(uc, UC_ARM64_REG_X2, &len_sr);
    err = uc_emu_start(uc, ADDRESS_CODE+0x850, ADDRESS_CODE+0x924, 0, 0);
    if(1)
    {
        MD5_CTX md51={0};  //定义一个MD5 text
        uc_mem_read(uc, MEM_ADDR, &md51, sizeof(MD5_CTX));
    }
    if (err) {
        printf("Failed on uc_emu_start() with error returned: %u (%s)\n",
               err, uc_strerror(err));
        return;
    }
    m_mem_pos++;
    unsigned char decrypt[16]; //加密结果
    address=MEM_ADDR;
    uc_reg_write(uc, UC_ARM64_REG_X0, &address);//x0  md5
    address=MEM_ADDR+0x200*m_mem_pos;
    uc_mem_write(uc, address, &decrypt, 16);
    uc_reg_write(uc, UC_ARM64_REG_X1, &address);//x1  out
    m_mem_pos++;
    //set pc
    err = uc_emu_start(uc, ADDRESS_CODE+0x134C, ADDRESS_CODE+0x1590, 0, 0);
    // now print out some registers
    printf(">>> Emulation done. Below is the CPU context\n");
    printf(">>> As little endian, X15 should be 0x78:\n");
    
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
    
    test_arm64();
    
    // dynamically free shared library
#ifdef DYNLOAD
    uc_dyn_free();
#endif
    
    return 0;
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
void md5_context_init(MD5_CTX *md5)
{
    MD5Init(md5);//初始化
    unsigned char decrypt[16]; //加密结果
    unsigned char encrypt[] ="admin";//要加密内容
    memcpy(md5->buffer,encrypt,5);
    unsigned char bits[8];
    md5->state[0]=0x67452301;
    md5->state[1]=0xefcdab89;
    md5->state[2]=0x98badcfe;
    md5->state[3]=0x10325476;
    md5->count[0]=40;
    MD5Encode(bits,md5->count,8);
    md5->count[0]=512;
    memcpy(md5->buffer+56,PADDING,8);
    memcpy(md5->buffer+5,PADDING,51);
    memcpy(md5->buffer+56,bits,8);
}
void test()
{
    /*
     write_mem_uc(&md5, sizeof(MD5_CTX));
     
     uint64_t pos1=MEM_ADDR+8;//state
     uint64_t pos2=MEM_ADDR+20;//buff
     uc_reg_write(uc, UC_ARM64_REG_X0, &pos1);
     uc_reg_write(uc, UC_ARM64_REG_X1, &pos2);
     */
    //err = uc_emu_start(uc, ADDRESS+0x924, ADDRESS+0x924+0xA28, 0, 0);
}
