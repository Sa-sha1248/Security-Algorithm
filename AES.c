#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

// Plaintext, Cipherkey -> state
// Plaintext State XOR Cipherkey State
// Round - 9
// SubByte
// ShiftRow
// MixColumn
// AddRoundKey
// Round - 10
// SubByte
// ShiftRow
// AddRoundKey
// 
// Ciphertext State -> bit
// 
//

//문자열을 state 형태로 바꾸기
void string_to_state(unsigned char state[4][4], unsigned char* input, int input_len) {
    int i, j, k = 0;
    for (i = 0; i < 4; i++) {
        for (j = 0; j < 4; j++) {
            if (k < input_len) {
                state[j][i] = input[k];
            }
            else {
                state[j][i] = 0x00;
            }
            k++;
        }
    }
}

//state를 문자열로 바꾸기
void state_to_string(unsigned char state[4][4], unsigned char* input) {
    int index = 0;
    for (int c = 0; c < 4; c++) {
        for (int r = 0; r < 4; r++) {
            char hex_str[3];
            sprintf(hex_str, "%02x", state[r][c]);  // 16진수 문자열로 변환
            int ascii_code = (int)strtol(hex_str, NULL, 16);  // 16진수 문자열을 ASCII 코드값으로 변환
            input[index++] = (unsigned char)ascii_code;  // ASCII 코드값을 문자로 변환하여 추가
        }
    }
    input[index] = '\0';
}

//state 형태 문자열 출력하기
void print_state(unsigned char state[4][4]) {
    int i, j;
    for (i = 0; i < 4; i++) {
        for (j = 0; j < 4; j++) {
            printf("%02x ", state[i][j]);
        }
        printf("\n");
    }
    printf("\n");
}

//===============================Round====================================
//SubByte 과정에 쓰이는 s-box
static const uint8_t sbox[16][16] = {
    //0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
    {0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76},
    {0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0},
    {0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15},
    {0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75},
    {0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84},
    {0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf},
    {0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8},
    {0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2},
    {0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73},
    {0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb},
    {0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79},
    {0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08},
    {0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a},
    {0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e},
    {0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf},
    {0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16}
};

static const uint8_t inv_sbox[16][16] = {
    {0x52,0x09,0x6A,0xD5,0x30,0x36,0xA5,0x38,0xBF,0x40,0xA3,0x9E,0x81,0xF3,0xD7,0xFB},
    {0x7C,0xE3,0x39,0x82,0x9B,0x2F,0xFF,0x87,0x34,0x8E,0x43,0x44,0xC4,0xDE,0xE9,0xCB},
    {0x54,0x7B,0x94,0x32,0xA6,0xC2,0x23,0x3D,0xEE,0x4C,0x95,0x0B,0x42,0xFA,0xC3,0x4E},
    {0x08,0x2E,0xA1,0x66,0x28,0xD9,0x24,0xB2,0x76,0x5B,0xA2,0x49,0x6D,0x8B,0xD1,0x25},
    {0x72,0xF8,0xF6,0x64,0x86,0x68,0x98,0x16,0xD4,0xA4,0x5C,0xCC,0x5D,0x65,0xB6,0x92},
    {0x6C,0x70,0x48,0x50,0xFD,0xED,0xB9,0xDA,0x5E,0x15,0x46,0x57,0xA7,0x8D,0x9D,0x84},
    {0x90,0xD8,0xAB,0x00,0x8C,0xBC,0xD3,0x0A,0xF7,0xE4,0x58,0x05,0xB8,0xB3,0x45,0x06},
    {0xD0,0x2C,0x1E,0x8F,0xCA,0x3F,0x0F,0x02,0xC1,0xAF,0xBD,0x03,0x01,0x13,0x8A,0x6B},
    {0x3A,0x91,0x11,0x41,0x4F,0x67,0xDC,0xEA,0x97,0xF2,0xCF,0xCE,0xF0,0xB4,0xE6,0x73},
    {0x96,0xAC,0x74,0x22,0xE7,0xAD,0x35,0x85,0xE2,0xF9,0x37,0xE8,0x1C,0x75,0xDF,0x6E},
    {0x47,0xF1,0x1A,0x71,0x1D,0x29,0xC5,0x89,0x6F,0xB7,0x62,0x0E,0xAA,0x18,0xBE,0x1B},
    {0xFC,0x56,0x3E,0x4B,0xC6,0xD2,0x79,0x20,0x9A,0xDB,0xC0,0xFE,0x78,0xCD,0x5A,0xF4},
    {0x1F,0xDD,0xA8,0x33,0x88,0x07,0xC7,0x31,0xB1,0x12,0x10,0x59,0x27,0x80,0xEC,0x5F},
    {0x60,0x51,0x7F,0xA9,0x19,0xB5,0x4A,0x0D,0x2D,0xE5,0x7A,0x9F,0x93,0xC9,0x9C,0xEF},
    {0xA0,0xE0,0x3B,0x4D,0xAE,0x2A,0xF5,0xB0,0xC8,0xEB,0xBB,0x3C,0x83,0x53,0x99,0x61},
    {0x17,0x2B,0x04,0x7E,0xBA,0x77,0xD6,0x26,0xE1,0x69,0x14,0x63,0x55,0x21,0x0C,0x7D},
};

// SubByte
void SubByte(unsigned char state[][4])
{
    int i, j;

    for (i = 0; i < 4; i++)
        for (j = 0; j < 4; j++)
            state[i][j] = sbox[(state[i][j] & 0xF0) >> 4][(state[i][j] & 0x0F)];
                          //sbox[상위 4비트][하위4비트]

}

//inv-subByte
void InvSubByte(unsigned char state[][4])
{
    int i, j;

    for (i = 0; i < 4; i++)
        for (j = 0; j < 4; j++)
            state[i][j] = inv_sbox[(state[i][j] & 0xF0) >> 4][(state[i][j] & 0x0F)];
    //inv_sbox[상위 4비트][하위4비트]

}

// ShiftRow
void CirshiftRows(unsigned char state[]) {
    unsigned char temp = state[0];
    state[0] = state[1];
    state[1] = state[2];
    state[2] = state[3];
    state[3] = temp;
}

void ShiftRow(unsigned char state[][4]) {
    int i, j;

    for (i = 1; i < 4; i++)
        for (j = 0; j < i; j++)
            CirshiftRows(state[i]);
}

//invShiftRow
void InvCirshiftRows(unsigned char state[]) {
    unsigned char temp = state[3];
    state[3] = state[2];
    state[2] = state[1];
    state[1] = state[0];
    state[0] = temp;
}

void InvShiftRow(unsigned char state[][4]) {
    int i, j;

    for (i = 1; i < 4; i++)
        for (j = 0; j < i; j++)
            InvCirshiftRows(state[i]);
}

//MixColumns

unsigned char a[4][4] = {
    {0x2, 0x3, 0x1, 0x1},
    {0x1, 0x2, 0x3, 0x1},
    {0x1, 0x1, 0x2, 0x3},
    {0x3, 0x1, 0x1, 0x2}
};

unsigned char inv_a[4][4] = {
    { 0x0e, 0x0b, 0x0d, 0x09 },
    { 0x09, 0x0e, 0x0b, 0x0d },
    { 0x0d, 0x09, 0x0e, 0x0b },
    { 0x0b, 0x0d, 0x09, 0x0e }
};

uint8_t x_time(uint8_t b, uint8_t n) {
    uint8_t temp = 0;
    while (n) {
        if (n & 1)
            temp ^= b;
        b = (b & 0x80) ? (b << 1) ^ 0x1B : (b << 1);
        n >>= 1;
    }
    return temp;
}


void MixColumns(unsigned char state[][4]) {
    int i, j, k;

    for (i = 0; i < 4; i++) {
        uint8_t temp[4] = { 0, };

        for (j = 0; j < 4; j++)
            for (k = 0; k < 4; k++)
                temp[j] ^= x_time(state[k][i], a[j][k]);

        state[0][i] = temp[0];
        state[1][i] = temp[1];
        state[2][i] = temp[2];
        state[3][i] = temp[3];
    }
}



//복호화 할 떄 쓰이는 InvMixColumns
void InvMixColumns(unsigned char state[][4]) {
    int i, j, k;

    for (i = 0; i < 4; i++) {
        uint8_t temp[4] = { 0, };

        for (j = 0; j < 4; j++)
            for (k = 0; k < 4; k++)
                temp[j] ^= x_time(state[k][i], inv_a[j][k]);

        state[0][i] = temp[0];
        state[1][i] = temp[1];
        state[2][i] = temp[2];
        state[3][i] = temp[3];
    }
}

// AddRoundKey
void AddRoundKey(uint8_t state[][4], uint8_t round_key[][44], int round) {
    printf("%d라운드 키\n", round);

    int i, j;

    for (i = 0; i < 4; i++) {
        for (j = 0; j < 4; j++) {
            printf("%02x ", round_key[i][j + 4* round]);
        }
        printf("\n");
    }
    printf("\n");

    for (i = 0; i < 4; i++) {
        for (j = 0; j < 4; j++) {
            state[j][i] ^= round_key[j][i + 4 * round];
        }
    }
}

//===============================KeyExpansion====================================

//round constant
static const uint8_t Rcon[10] = {
  0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 };


void RotWord(unsigned char state[]) {
    unsigned char temp = state[0];
    state[0] = state[1];
    state[1] = state[2];
    state[2] = state[3];
    state[3] = temp;
}

void key_sbox(unsigned char w[]) {
    int i;
        for (i = 0; i < 4; i++)
            w[i]= sbox[(w[i]& 0xF0) >> 4][(w[i]& 0x0F)];
    //sbox[상위 4비트][하위4비트]
}



void KeyExpansion(uint8_t RoundKey[4][44], const uint8_t Key[4][4]) {
    int i, j, k = 0;
    uint8_t temp[4][4];

    for (i = 0; i < 4; i++) {
        RoundKey[0][i] = Key[0][i];
        RoundKey[1][i] = Key[1][i];
        RoundKey[2][i] = Key[2][i];
        RoundKey[3][i] = Key[3][i];
    }

    for (i = 4; i < 44; ++i) {
        //바로 직전에 생성된 W
        temp[0][0] = RoundKey[0][i - 1];
        temp[1][0] = RoundKey[1][i - 1];
        temp[2][0] = RoundKey[2][i - 1];
        temp[3][0] = RoundKey[3][i - 1];

        //새로운 라운드 키가 생성 될 때, 실행
        if (i % 4 == 0) {
            const uint8_t u8tmp = temp[0][0];
            temp[0][0] = temp[1][0];
            temp[1][0] = temp[2][0];
            temp[2][0] = temp[3][0];
            temp[3][0] = u8tmp;

            SubByte(temp);
            temp[0][0] ^= Rcon[i / 4 - 1];
        }

        RoundKey[0][i] = RoundKey[0][i - 4] ^ temp[0][0];
        RoundKey[1][i] = RoundKey[1][i - 4] ^ temp[1][0];
        RoundKey[2][i] = RoundKey[2][i - 4] ^ temp[2][0];
        RoundKey[3][i] = RoundKey[3][i - 4] ^ temp[3][0];
    }
}


//================================AES 진행==========================================
int main() {
    //----------plaintext & key-------------------
   
    unsigned char plain_text[] = "Hi, I'm AES!!!!!!";
    unsigned char key[] = "0123456789abcdef";

    printf("plaintext: Hi, I'm AES!!!!!! \n");
    printf("key: 0123456789abcdef\n\n");

    int plain_text_len = strlen(plain_text);
    int key_text_len = strlen(key);

    unsigned char state_plain[4][4];
    unsigned char state_key[4][4];

    unsigned char str_text[32];
    unsigned char str_key[32];

    string_to_state(state_plain, plain_text, plain_text_len);
    string_to_state(state_key, key, key_text_len);

    printf("string_to_state: plaintext\n");
    print_state(state_plain);

    printf("string_to_state: key\n");
    print_state(state_key);
    //--------------plaintext & key end----------------

    unsigned char round_key[4][44];
    //---------------incryption start----------------------
    printf("암호화 시작\n");
    int round = 0;

    KeyExpansion(round_key, state_key);
    AddRoundKey(state_plain, round_key, round);
    printf("AddRoundkey\n");
    print_state(state_plain);



    //----------round 1~9------------------------------

    for (round = 1; round < 10; round++)
    {
        printf("-------Round: %d-------\n",round);
        SubByte(state_plain);
        printf("SubByte\n");
        print_state(state_plain);
        ShiftRow(state_plain);
        printf("ShiftRow\n");
        print_state(state_plain);
        MixColumns(state_plain);
        printf("MixColumns\n");
        print_state(state_plain);
        AddRoundKey(state_plain, round_key, round);
        printf("AddRoundKey\n");
        print_state(state_plain);
    }

    printf("-------Round: %d-------\n", round);
    SubByte(state_plain);
    printf("SubByte\n");
    print_state(state_plain);
    ShiftRow(state_plain);
    printf("ShiftRow\n");
    print_state(state_plain);



    AddRoundKey(state_plain, round_key, round);
    printf("AddRoundKey\n");
    print_state(state_plain);


    printf("암호화 끝\n\n");
   //------------------------incryption end-------------------

    printf("Ciphertext: ");

    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            printf("%02x", state_plain[j][i]);
        }
    }
    printf("\n"); printf("\n");
   //----------------------decryotion start-------------------    
   printf("복호화 시작\n");

   AddRoundKey(state_plain, round_key, round);
   printf("AddRoundKey\n");
   print_state(state_plain);
   
   //----------1~9라운드------------------
   for (round = 9; round > 0; round--)
   {
       printf("-------Round: %d-------\n", round);
       
       InvShiftRow(state_plain);
       printf("InvShiftRow\n");
       print_state(state_plain);

       InvSubByte(state_plain);
       printf("InvSubByte\n");
       print_state(state_plain);

       AddRoundKey(state_plain, round_key, round);
       printf("AddRoundKey\n");
       print_state(state_plain);

       InvMixColumns(state_plain);
       printf("InvMixColumns\n");
       print_state(state_plain);

   }

   printf("-------Round: %d-------\n", round);
   InvShiftRow(state_plain);
   printf("InvShiftRow\n");
   print_state(state_plain);

   InvSubByte(state_plain);
   printf("InvSubByte\n");
   print_state(state_plain);

   AddRoundKey(state_plain, round_key, round);
   printf("AddRoundKey\n");
   print_state(state_plain);
    

    
   printf("복호화 끝\n");
    
   //----------------------decryotion end-------------------    


   //----------state -> string-----------------------
   state_to_string(state_plain, str_text);
   printf("state_to_string: %s\n", str_text);
   //----------state -> string end-----------------------

    return 0;
}
