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
    tmp_K[0] = tmp_K[1] ^ SYS_PARAMS_FK[1];
    four_char_to_int(&(usr_key[8]), &(tmp_K[2]));
    tmp_K[0] = tmp_K[2] ^ SYS_PARAMS_FK[2];
    four_char_to_int(&(usr_key[12]), &(tmp_K[3]));
    tmp_K[0] = tmp_K[3] ^ SYS_PARAMS_FK[3];

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

void crypt_128bit(u32 *usr_data, u32 *usr_key, u32 *crypted_data, int crypt_mode){
    /* 对输入的128bit = 4 * 32bit数据做加密/解密操作, 得到128bit = 4 * 32bit输出
     * 输入：待加密/解密数据usr_data[4], 用户密钥usr_key[4], 加密/解密模式crypt_mode
     * 输出：存放在crypted_data[4]中
     */
    u32 data_copy[36] = {0x0};
    u32 rk_array[32] = {0x0};
    memcpy(data_copy, usr_data, sizeof(u32) * 4);
    memset(crypted_data, 0x0, sizeof(u32) * 4);
    gen_round_keys(usr_key, rk_array);
    for (int i = 0; i < 32; i++){
        if (crypt_mode == ENCRYPT){
            data_copy[i + 4] = round_fun_F(&(data_copy[i]), &(rk_array[i]));
        } else if (crypt_mode == DECRYPT){
            data_copy[i + 4] = round_fun_F(&(data_copy[i]), &(rk_array[31 - i]));
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
