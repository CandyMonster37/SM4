#ifndef __SM4_H_
#define __SM4_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define u8 unsigned char
#define u32 unsigned int
#define ENCRYPT 0               // 加密模式
#define DECRYPT 1               // 解密模式

void int_to_four_char(u32 input32, u8 *output8);                                            // 1个u32拆成4个u8
void four_char_to_int(u8 *input8, u32 *output32);                                           // 4个u8合成1个u32
u32 round_rotation_left(u32 input, int len);                                                // 循环左移，同汇编ROL

void gen_round_keys(u8 *usr_key, u32 *rk_array);                                            // 轮密钥生成函数
void reverse_change_R(u32 *dst, u32 *src);                                                  // 反序变换R
u32 round_fun_F(u32 *input128, u32 rk);                                                     // 轮函数F
u32 syn_trans_T(u32 input);                                                                 // 合成置换T
void nl_tor(u8 *input_tor, u8 *output_tor);                                                 // 非线性变换TOR (S_BOX)
void crypt_128bit_ECB(u32 *usr_data, u32 *rk_array, u32 *crypted_data, int crypt_mode);     // ECB模式加密/解共用的函数体

/* **************************************  以下为固定参数  ************************************** */
extern const u32 SYS_PARAMS_FK[4];		// 系统参数FK 
extern const u32 SYS_PARAMS_CK[32];		// 固定参数CK
extern const u8 S_BOX[256];				// S盒

#endif
