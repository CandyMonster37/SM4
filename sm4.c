#include "sm4.h"

void reverse_change_R(u32 *dst, u32 *src){
    /* 反序变换R
     * src: [A0, A1, A2, A3]
     * dst: [A3, A2, A1, A0]
     */
    dst[0] = src[3];
    dst[1] = src[2];
    dst[2] = src[1];
    dst[3] = src[0];
}

u32 round_fun_F(u32 *input128, u32 rk){
    /* 轮函数F
     * input128: [X0, X1, X2, X3], 某一轮中的4个字
     * rk: 该轮的轮密钥
     * 功能：轮函数，F(X0,X1,X2,X3,rk) = X0 xor T(X1 xor X2 xor X3 xor rk)
     * 返回值：u32
     */
    u32 result = 0;
    u32 x0 = input128[0];
    u32 x1 = input128[1];
    u32 x2 = input128[2];
    u32 x3 = input128[3];

    u32 input_t = x1 ^ x2 ^ x3 ^ rk;
    result = syn_trans_T(input_t);
    result = x0 ^ result;
    return result;
}

u32 syn_trans_T(u32 input){
    /* 合成置换T
     * T(.) = L(TOR(.))
     * 先对输入做非线性变换TOR，再做线性变换L
     */
    u32 result_trans_T = 0;
    u8 input_tor[4] = {0x0};
    u8 output_tor[4] = {0x0};

    // u32 -> 4 * u8
    int_to_four_char(input, input_tor);

    // TOR
    nl_tor(input_tor, output_tor);
    four_char_to_int(output_tor, &(result_trans_T));

    // 线性变换L
    result_trans_T = result_trans_T ^ round_rotation_left(result_trans_T, 2) 
                                    ^ round_rotation_left(result_trans_T, 20) 
                                    ^ round_rotation_left(result_trans_T, 18) 
                                    ^ round_rotation_left(result_trans_T, 24);

    return result_trans_T;
}

void gen_round_keys(u8 *usr_key, u32 *rk_array){
    /* 生成32个轮密钥
     * 输入：char array[16], 对应用户的128bit密钥
     * 输出：存放在rk_array[32]中
     */
    u32 tmp_K[36] = {0x0};
    memset(rk_array, 0x0, sizeof(u32) * 32);
    four_char_to_int(&(usr_key[0]), &(tmp_K[0]));
    tmp_K[0] = tmp_K[0] ^ SYS_PARAMS_FK[0];
    four_char_to_int(&(usr_key[4]), &(tmp_K[1]));
    tmp_K[1] = tmp_K[1] ^ SYS_PARAMS_FK[1];
    four_char_to_int(&(usr_key[8]), &(tmp_K[2]));
    tmp_K[2] = tmp_K[2] ^ SYS_PARAMS_FK[2];
    four_char_to_int(&(usr_key[12]), &(tmp_K[3]));
    tmp_K[3] = tmp_K[3] ^ SYS_PARAMS_FK[3];

    for (int i = 0; i < 32; i++){
        u32 result_tmp_T = 0;
        u8 input_tor[4] = {0x0};
        u8 output_tor[4] = {0x0};
        result_tmp_T = tmp_K[i + 1] ^ tmp_K[i + 2] ^ tmp_K[i + 3] ^ SYS_PARAMS_CK[i];
        int_to_four_char(result_tmp_T, input_tor);
        nl_tor(input_tor, output_tor);
        four_char_to_int(output_tor, &(result_tmp_T));
        result_tmp_T = result_tmp_T ^ round_rotation_left(result_tmp_T, 13) 
                                    ^ round_rotation_left(result_tmp_T, 23);
        tmp_K[i + 4] = tmp_K[i] ^ result_tmp_T;
        rk_array[i] = tmp_K[i + 4];
    }
}

void crypt_128bit_ECB(u32 *usr_data, u32 *rk_array, u32 *crypted_data, int crypt_mode){
    /* 对输入的128bit = 4 * 32bit数据做加密/解密操作, 得到128bit = 4 * 32bit输出
     * 输入：待加密/解密数据usr_data[4], 用户密钥rk_array[32], 加密/解密模式crypt_mode
     * 输出：存放在crypted_data[4]中
     */
    u32 data_copy[36] = {0x0};
    //u32 rk_array[32] = {0x0};
    memcpy(data_copy, usr_data, sizeof(u32) * 4);
    memset(crypted_data, 0x0, sizeof(u32) * 4);
    //gen_round_keys(usr_key, rk_array);  // 对于同一份文件的ECB加密过程，从始至终使用的都是同一份密钥，只在最开始计算一次就行
    for (int i = 0; i < 32; i++){
        if (crypt_mode == ENCRYPT){
            data_copy[i + 4] = round_fun_F(&(data_copy[i]), rk_array[i]);
        } else if (crypt_mode == DECRYPT){
            data_copy[i + 4] = round_fun_F(&(data_copy[i]), rk_array[31 - i]);
        } else {
            // 解码模式异常，直接退出
            exit(0);
        }
    }
    reverse_change_R(crypted_data, &(data_copy[32]));
}

void nl_tor(u8 *input_tor, u8 *output_tor){
    /*
     * 4个并行的S盒构成非线性变换TOR
     */
    for (int i = 0; i < 4; i++){
        output_tor[i] = S_BOX[input_tor[i]];
    }
}

u32 round_rotation_left(u32 input, int len){
    /*
     * 将input循环左移len位，溢出高位移至低位
     */
    u32 out = 0x0;
    out = (input << len) | (input >> (32 - len));
    return out;
}

void four_char_to_int(u8 *input8, u32 *output32){
    /*
     * 4个8bit合成1个32bit
     */
    u32 res = 0x0;
    res |= input8[0];
    res <<= 8;
    res |= input8[1];
    res <<= 8;
    res |= input8[2];
    res <<= 8;
    res |= input8[3];
    *output32 = res;
}

void int_to_four_char(u32 input32, u8 *output8){
    /*
     * 1个32bit拆成4个8bit
     */
    memset(output8, 0x0, sizeof(u8) * 4);
    for (int i = 0; i < 4; i++){
        // 从最低字节开始取的话会取到反序的，因此要用24做减法，从最高字节开始取
        u32 tmp = input32;
        tmp = tmp >> (24 - i * 8);
        output8[i] = (u8)(tmp & 0xff);
    }
}

/* **************************************  以下为固定参数  ************************************** */

/* 系统参数FK */
const u32 SYS_PARAMS_FK[4] = {
    0xA3B1BAC6,
    0x56AA3350,
    0x677D9197,
    0xB27022DC
};

/* 固定参数CK */
const u32 SYS_PARAMS_CK[32] = {
    0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
    0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
    0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
    0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
    0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
    0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
    0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
    0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279
};

/* S盒 */
const u8 S_BOX[256] = {
    0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
    0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
    0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
    0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
    0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
    0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
    0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
    0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
    0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
    0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
    0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
    0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
    0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
    0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
    0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48
};
