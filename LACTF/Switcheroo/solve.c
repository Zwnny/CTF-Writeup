#include <stdio.h>
#define INT_BITS 64
#include <stdbool.h>
#include <string.h>
/*Function to left rotate n by d bits*/
unsigned long long leftRotate(unsigned long long n, unsigned int d)
{
    /* In n<<d, last d bits are 0. To put first 3 bits of n
       at last, do bitwise or of n<<d with n >>(INT_BITS -
       d) */
    return (n << d) | (n >> (INT_BITS - d));
}
 
/*Function to right rotate n by d bits*/
unsigned long long rightRotate(unsigned long long n, unsigned int d)
{
    /* In n>>d, first d bits are 0. To put last 3 bits of at
            first, do bitwise or of n>>d with n <<(INT_BITS
       - d) */
    return (n >> d) | (n << (INT_BITS - d));
}


void main()
{
    unsigned long long a[] =
    {
     0x700010203040506,
     0x3e04f4fb783cfc7e,
     0x9d70813d04308703,
     0x4a51a1f8093da74d,
     0xc4950b2a88b02fc,
     0x2d21d9262f0fd4b,
     0x88e781beaabe46a9,
     0x77090f0e85bb1994,
     0x564eb824353f49fb,
     0x7f0b7a9deb629b47,
     0x13fb130146e18d1,
     0xe650e17e4dd465ed,
     0x81d36704803dabe7,
     0x2ce80a373718c7a,
     0x822c510930254873,
     0x570837475070684e,
     0x3bd734ec321014b5,
     0x975e1ee37edd98b3,
     0x158144feb60d4cfd,
     0x88407c6cac154291,
     0xfae192b920dfc1b,
     0xfc0c676e7c762680,
     0x4850b8d36d94ef27,
     0x86466720d884da2,
     0xac7e0453c14f48dc,
     0x7c2568ad2461dfd8,
     0x473b065dde911f08,
     0x1eed1fd742e65871,
     0x6c81edc3c1b82548,
     0x3169f71b61802ff,
     0xe4a7396792ae3fe0,
     0x90cf08ac6b10b7ca,
     0x4ca10931f081a0,
     0xf53df18f89683b,
     0x4242bcb1de8f49,
     0x7e5900ceac84ca,
     0x706f0fe8110ea4,
     0x2278b42062504e,
     0x2a05a95da52b9c,
     0x4dc5d0b9df0e49,
     0x6c3641e06cf0c4,
     0x7947a68e374a6e,
     0xd8d2632b336802,
     0x13856c42fb5022e,
     0x3b14db1a083918,
     0xf8673ab12fe1bb,
     0xa108b014ed1224,
     0xb2892e6aef3b04,
     0x22c3cd3180024d6,
     0x23911aad0fc5f34,
     0x20807c9714b4ee6,
     0x71a331c09302327,
     0x418062921a9d245,
     0x51f16342b0f9253,
     0x13b19bfda0ae97c,
     0x712172535192f1e,
     0x3322a0bc910d295,
     0xc070fffa196394,
     0x9ab072a84999dd,
     0x4e82e174a1aaac,
     0xaa5205419584b9,
     0x678a2b8c1ee3d5,
     0x45bcacc9d8e7d0,
     0x3a19c384b0d4f9,
     0x8b1960a582c51b,
     0x4ec4506c2a2acd,
     0x7473c8605786e1,
     0x11316536bbab37f,
     0xf0d247fdbdeef,
     0xadf608a9de1e76,
     0x9f540868cf82e3,
     0x14f5fc312b801d,
     0x106f14c43224fe,
     0xb85bad5d8b37c5,
     0xedce17848c990d,
     0xccdc13df11bcc4,
     0x20c2d6776a0559b,
     0x20a1b64ea7521f7,
     0x391d24d990be82,
     0x7500719dd73ca8,
     0xef2eadb2a82a37,
     0x8ef10a40961460,
     0x339a2cfe3f67a5,
     0xe071306365879d,
     0x6e6e3d2a75dcf0,
     0x12e7254c18273f0,
     0x4808adcd9b667f,
     0x110801230ea6395,
     0xfa98c7f1f1fc38,
     0x10d400fe6fe7bd9,
     0x479e150008b94d,
     0xf980cf38134895,
     0x2a0ffe7bcb5dac,
     0x750b4b0fce9b99,
     0xbd6efe79b37758,
     0x7200e2431153628,
     0x7caaf14032bc02,
     0x23d011f618395bb,
     0x53807834fe6f9e,
     0x102303de88670c8,
     0xf50c3ac708d8f8,
     0xff5ef8a99d75bc,
     0x2043a12100e517e,
     0xe82d19d049d706,
     0x2142631db624214,
     0xa91363b0ffa60b,
     0x858ea1137db2f9,
     0x6f4ffa06b018ec,
     0x10057e77680f034,
     0x5a5ab88b8c7272,
     0x11d196834081d82,
     0x6dee0756faeaac,
     0x1661e80c160078,
     0xcca67a1a58c313,
     0x1223683b81b13e8,
     0x65cac20345d68d,
     0x1031c1a6050ecdc,
     0x13704ec972c1905,
     0x4ec9e48b6c0b25,
     0x55c40d12a5e1dd,
     0xf0d4fcc420e40e,
     0x9bb8c1998b27f3,
     0xcac85d04041af6,
     0x20541af898eba05,
     0x2cb0263d671095,
     0x23e42ffe7ac3643,
     0x19f3624e096087,
     0x26f8d3995aa788ec
    };

 unsigned char res[0x40] = {0};

    for (int i=0; i<0x40; i++) 
    {
        res[i] = 0;
    }

res[0x3f] = 0x0;
    for(int i = 0; i < 0x3f; i++)
    {
        unsigned char chr = 0;
        bool found = false;
        for ( chr = 0x21; chr <= 0x7e; chr ++)
        {
            
            unsigned long long r8 = a[chr];
            //printf("Value from array %llx\n",r8);
            r8 = leftRotate(r8,8);
           // printf("Value after 1s rotate %llx\n",r8);

            unsigned long long r13 = r8 & 0xff;
            //printf("Value after movzx %llx\n",r13);

            unsigned long long r14 = 0;

            while (r14 < r13)
            {
             r8 = leftRotate(r8,8);
             //printf("Value after 2nd rol %llx\n",r8 & 0xff);
             //printf("Value test %llx\n",r8 & 0xff);

                if( (r8 & 0xff) == i)
                {
                    //printf("Niceeeeeeeeeee\n");
                    found = true;
                    break;
                }
                else
                 r14 += 1;
            }
            //break;
            //printf("%lld\n", r14);
            if (found) break;


        }

        res[i] = chr;
        printf("%d , %c - %d\n",i, chr, chr);
        
    }

    printf("%64s\n",res);

} 