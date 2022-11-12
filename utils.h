#ifndef __UTILS_H_
#define __UTILS_H_

#include <stdio.h>
#include <stdlib.h>
#include "../include/sm4.h"

#define FILENAME_LENGTH 255

enum {flag_help = -4, flag_test, flag_encrypt = ENCRYPT, flag_decrypt = DECRYPT}option_flag;

typedef struct{
    char usr_data_filename[FILENAME_LENGTH] = { 0x0 };
    char usr_key_filename[FILENAME_LENGTH] = { 0x0 };
    char usr_out_filename[FILENAME_LENGTH] = { 0x0 };
    int crypt_mode = -1;
    int option = -4;
}usr_info;

int get_end_of_text(u32 *to_remove, u8 *tail_bytes);            // 解密时找到真实剩余的字节数
void check_paras(int argc, char *argv[], usr_info *info);       // 检查用户输入并获取参数
void show_help_info();                                          // 显示帮助信息
void test_speed();                                              // 使用预设参数测速

#endif
