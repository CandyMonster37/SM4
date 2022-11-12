#include "utils.h"

int get_end_of_text(u32 *to_remove, u8 *tail_bytes){
    /* 从后至前寻找文件结束符（不为0的部分）
     * 文件结束标志： 0x48 0x59 并缀以若干 0x0
     * 输入：to_remove[8]，代表最后的2组128bit数据; tail_bytes[32]，存放对应的byte数据
     * 返回值：真实的尾数据长度
    */
    // 文件结尾用 0x48 0x59 并配以若干0x0作为结束
    for(int i = 0; i < 8; i++){
        int_to_four_char(to_remove[i], &(tail_bytes[i * 4]));
    }
    int idx = 31;
    for(; idx >= 0; idx--){
        if(tail_bytes[idx] != 0){
            break;
        }
    }
    idx = (idx - 2) < 0 ? 0 : (idx - 2);  //这里可能存在问题，先这么处理
    return idx + 1;  //注意返回的是长度不是下标
}

void check_paras(int argc, char *argv[], usr_info *info){
    // sm4.exe --encrypt file_to_encrypt --out out_filename --key key_file_name
    // sm4.exe --decrypt file_to_decrypt --out out_filename --key key_file_name
    // sm4.exe --help
    // sm4.exe --test_speed
    if(argc == 2){
        if(strcmp(argv[1], "--test_speed") == 0){
            // set flag to test speed
            printf("使用预设数据进行测速！\n");
            info->option = flag_test;
        } else if(strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-H") == 0 ){
            // show help info
            info->option = flag_help;
        } else {
            printf("** 未找到可用命令，请根据帮助信息检查参数是否有误。\n");
            info->option = flag_help;
        }
        return;
    } else if(argc == 7){
        char flag_input = 0x00;
        char flag_output = 0x00;
        char flag_keyfile = 0x00;
        // do check and update idx
        for(int idx = 1; idx < argc; idx += 2){
            if(strcmp(argv[idx], "--encrypt") == 0 || strcmp(argv[idx], "--decrypt") == 0){
                flag_input = 0xff;
                if(strcmp(argv[idx], "--encrypt") == 0){
                    info->crypt_mode = ENCRYPT;
                    info->option = flag_encrypt;
                } else {
                    info->crypt_mode = DECRYPT;
                    info->option = flag_decrypt;
                }
                strcpy(info->usr_data_filename, argv[idx + 1]);
                continue;
            }
            if(strcmp(argv[idx], "--out") == 0){
                flag_output = 0xff;
                strcpy(info->usr_out_filename, argv[idx + 1]);
                continue;
            }
            if(strcmp(argv[idx], "--key") == 0){
                flag_keyfile = 0xff;
                strcpy(info->usr_key_filename, argv[idx + 1]);
                continue;
            }
        }
        char flag_right = flag_input & flag_output & flag_keyfile;
        if(flag_right == 0xff){
            // 如果参数无误，则flag_right的值为0xff
            if(info->option == flag_encrypt) {
                printf("根据用户需求对文件进行SM4加密！\n");
            } else if(info->option == flag_decrypt){
                printf("根据用户需求对文件进行SM4解密！\n");
            }
        } else {
            printf("** 未找到可用命令，请根据帮助信息检查参数是否有误。\n");
            info->option = flag_help;
        }
        return;
    } else {
        printf("** 参数有误，请查看帮助信息！\n");
        info->option = flag_help;
        return;
    }
}

void show_help_info(){
    printf("\n\n\n");
    printf("********************************************************************************\n");
    printf("*                                                                              *\n");
    printf("*                                 SM4加密/解密                                  *\n");
    printf("*                                                                              *\n");
    printf("********************************************************************************\n");
    printf("\n\n");
    printf("中文标准名称：信息安全技术SM4分组密码算法\n");
    printf("英文标准名称：Information security technology—SM4 block cipher algorthm\n");
    printf("标准状态：现行\n");
    printf("中国标准分类号（CCS）：    L80                  国际标准分类号（ICS）：  35.040\n");
    printf("发布日期：                2016-08-29           实施日期：              2017-03-01\n");
    printf("\n");
    printf("SM4算法是一个分组算法。该算法的分组长度为 128 bit，密钥长度为 128 bit。\n");
    printf("加密算法与密钥扩展算法都采用 32 轮非线性迭代结构。\n");
    printf("解密算法与加密算法的结构相同，只是轮密钥的使用顺序相反，解密轮密钥是加密轮密钥的逆序。\n");
    printf("\n\n");
    printf("使用说明：\n\n");
    printf("用 usr.key 加密 secret.txt ，并将结果保存到 encrypted.cm ，请在终端中使用如下命令：\n");
    printf("sm4.exe --encrypt secret.txt --out encrypted.txt --key usr.key\n\n");
    printf("用 usr.key 解密 received.cm ，并将结果保存到 decrypted.txt ，请在终端中使用如下命令：\n");
    printf("sm4.exe --decrypt received.cm --out decrypted.txt --key usr.key\n\n");
    printf("其他可选参数：\n");
    printf("    --help            显示本信息并退出程序\n");
    printf("    --test_speed      使用预设数据测速\n");
    printf("\n");
}

void test_speed(){
    // todo
    u8 input_data_8[16] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    };
    u8 usr_key_8[16] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    };
    printf("测试明文输入：");
    for(int i = 0; i < 15; i++){
        printf("0x%x, ", input_data_8[i]);
    }
    printf("0x%x\n", input_data_8[15]);
    printf("测试密钥：");
    for(int i = 0; i < 15; i++){
        printf("0x%x, ", usr_key_8[i]);
    }
    printf("0x%x\n", usr_key_8[15]);

    u32 input_data_32[4] = { 0x0 };
    u32 usr_key_32[32] = { 0x0 };
    u8 encrypt_data_8[16] = { 0x0 };
    u32 encrypt_data_32[4] = { 0x0 };
    gen_round_keys(usr_key_8, usr_key_32);
    for(int i = 0; i < 4; i++){
        four_char_to_int(&(input_data_8[i * 4]), &(input_data_32[i]));
    }
    crypt_128bit_ECB(input_data_32, usr_key_32, encrypt_data_32, ENCRYPT);
    for(int i = 0; i < 4; i++){
        int_to_four_char(encrypt_data_32[i], &(encrypt_data_8[i * 4]));
    }
    printf("测试密文结果：");
    for(int i = 0; i < 15; i++){
        printf("0x%x, ", encrypt_data_8[i]);
    }
    printf("0x%x\n", encrypt_data_8[15]);
    
    u8 decrypt_data_8[16] = { 0x0 };
    u32 decrypt_data_32[4] = { 0x0 };
    crypt_128bit_ECB(encrypt_data_32, usr_key_32, decrypt_data_32, DECRYPT);
    for(int i = 0; i < 4; i++){
        int_to_four_char(decrypt_data_32[i], &(decrypt_data_8[i * 4]));
    }
    printf("测试解密结果：");
    for(int i = 0; i < 15; i++){
        printf("0x%x, ", decrypt_data_8[i]);
    }
    printf("0x%x\n", decrypt_data_8[15]);
}


