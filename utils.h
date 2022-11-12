#ifndef __UTILS_H_
#define __UTILS_H_

#include <stdio.h>
#include <stdlib.h>
#include "sm4.h"

#define FILENAME_LENGTH 255
#define flag_help		-4
#define flag_test		-3
#define flag_encrypt	ENCRYPT
#define flag_decrypt	DECRYPT

typedef struct{
    char usr_data_filename[FILENAME_LENGTH];
    char usr_key_filename[FILENAME_LENGTH];
    char usr_out_filename[FILENAME_LENGTH];
    int crypt_mode;
    int option;
}usr_info;

int get_end_of_text(u32 *to_remove, u8 *tail_bytes);            // 解密时找到真实剩余的字节数
void check_paras(int argc, char *argv[], usr_info *info);       // 检查用户输入并获取参数
void show_help_info();                                          // 显示帮助信息
void test_speed();                                              // 使用预设参数测速

#endif
