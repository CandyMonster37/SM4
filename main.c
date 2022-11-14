#include "sm4.h"
#include "utils.h"
#include <sys/stat.h>

int main(int argc, char *argv[]){

    usr_info *info = (usr_info*)malloc(sizeof(usr_info));
    memset(info->usr_data_filename, 0x0, sizeof(char) * FILENAME_LENGTH);
    memset(info->usr_key_filename, 0x0, sizeof(char) * FILENAME_LENGTH);
    memset(info->usr_out_filename, 0x0, sizeof(char) * FILENAME_LENGTH);
    info->crypt_mode = -1;
    info->option = flag_help;
   
    check_paras(argc, argv, info);

    if(info->option == flag_help){
        show_help_info();
        // wait key press
        system("pause");
        return 0;
    }
    if(info->option == flag_test){
        test_speed();
        // wait key press
        system("pause");
        return 0;
    }
    if(info->option == flag_encrypt || info->option == flag_decrypt){
        // do encryption or do decryption with ECB mode
        FILE *fp_in = fopen(info->usr_data_filename, "rb");
        FILE *fp_key = fopen(info->usr_key_filename, "rb");
        FILE *fp_out = fopen(info->usr_out_filename, "wb");
        if(fp_in == NULL || fp_out == NULL || fp_key == NULL){
            printf("文件打开失败，请检查输入路径或路径权限！\n");
            system("pause");
            return 0;
        }
        fclose(fp_out);  // 清空已存在的文件
        fp_out = fopen(info->usr_out_filename, "ab");

        u8 input_data_8[16] = { 0x0 };
        u8 usr_key_8[16] = { 0x0 };
        u8 output_data_8[16] = { 0x0 };

        u32 input_data_32[4] = { 0x0 };
        u32 usr_key_32[32] = { 0x0 }; // 存储32轮子密钥
        u32 output_data_32[4] = { 0x0 };

        fread(usr_key_8, sizeof(u8), 16, fp_key);
        gen_round_keys(usr_key_8, usr_key_32);  // ECB模式下只需在最开始时生成一次密钥

        struct stat file_info;
        stat(info->usr_data_filename, &file_info);
        off_t file_size = file_info.st_size;  // 在不打开文件的情况下获取文件大小, 以字节计算
        off_t dealt_bytes = 0;
        int rest_bytes = file_size % 16;

        while(dealt_bytes < file_size){
            memset(input_data_32, 0x0, sizeof(u32) * 4);
            memset(output_data_32, 0x0, sizeof(u32) * 4);
            memset(input_data_8, 0x0, sizeof(u8) * 16);
            memset(output_data_8, 0x0, sizeof(u8) * 16);
            if(file_size - dealt_bytes <= 32){
                // 最后不管满不满16B，都要做padding、设置eof、break
                // 因此解码的时候需要在最后的32个字节中去除文件尾
                if(info->crypt_mode == DECRYPT){
                    // 如果是解密模式，则最后一定是8个字 = 2 * 16字节 = 2 * 128bit
                    u32 to_remove[8] = { 0x0 }; // 存储解出的带padding的结果

                    // 先处理前16字节
                    fread(input_data_8, sizeof(u8), 16, fp_in);
                    for(int i = 0; i < 4; i++){
                        four_char_to_int(&(input_data_8[i * 4]), &(input_data_32[i]));
                    }
                    crypt_128bit_ECB(input_data_32, usr_key_32, &(to_remove[0]), info->crypt_mode);

                    // 清除变量状态，处理后16字节
                    memset(input_data_8, 0x0, sizeof(u8) * 16);
                    memset(input_data_32, 0x0, sizeof(u32) * 4);
                    fread(input_data_8, sizeof(u8), 16, fp_in);
                    for(int i = 0; i < 4; i++){
                        four_char_to_int(&(input_data_8[i * 4]), &(input_data_32[i]));
                    }
                    crypt_128bit_ECB(input_data_32, usr_key_32, &(to_remove[4]), info->crypt_mode);

                    // 结果输出是按字（4B）输出的，要先从字转字节，再去除标志位保存
                    u8 tail_data[32] = { 0x0 };
                    int tail_bytes = 0;
                    tail_bytes = get_end_of_text(to_remove, tail_data);
                    fwrite(tail_data, sizeof(u8), tail_bytes, fp_out);
                } else {
                    // 如果是加密模式，就要先判断剩余字节数，然后打0x48 0x59 并缀以若干 0x0的padding
                    if(file_size - dealt_bytes > 16){
                        // 加密时最后的字节数可能在0-32之间
                        // 如果剩余字节数在17-32之间，就先处理16B，确保剩余字节数在0-16之间
                        fread(input_data_8, sizeof(u8), 16, fp_in);
                        for(int i = 0; i < 4; i++){
                            four_char_to_int(&(input_data_8[i * 4]), &(input_data_32[i]));
                        }
                        crypt_128bit_ECB(input_data_32, usr_key_32, output_data_32, info->crypt_mode);
                        for(int i = 0; i < 4; i++){
                            int_to_four_char(output_data_32[i], &(output_data_8[i * 4]));
                        }
                        fwrite(output_data_8, sizeof(u8), 16, fp_out);
                        dealt_bytes += 16;
                    }
                    // 当剩余字节数在0-16之间时再添加结束标志0X48 0X59，然后剩余位补0x00到32字节
                    u8 data_padding[32] = { 0x00 };
                    int rest_size = file_size - dealt_bytes;  // 理论上rest_size应该等于rest_bytes
                    if(rest_bytes != rest_size){ // 否则就出问题了
                        printf("文件大小计算出错！程序终止！\n");
                        exit(-1);
                    }
                    fread(data_padding, sizeof(u8), rest_size, fp_in);
                    data_padding[rest_size] = 0x48;             // padding
                    data_padding[rest_size + 1] = 0x59;         // padding
                    // 到这里就padding结束了，padding结束之后data_padding为cont、0x48、0x59、0x00，共32B
                    // 先对0-15B加密
                    for(int i = 0; i < 4; i++){
                        four_char_to_int(&(data_padding[i * 4]), &(input_data_32[i]));
                    }
                    crypt_128bit_ECB(input_data_32, usr_key_32, output_data_32, info->crypt_mode);
                    for(int i = 0; i < 4; i++){
                        int_to_four_char(output_data_32[i], &(output_data_8[i * 4]));
                    }
                    fwrite(output_data_8, sizeof(u8), 16, fp_out);

                    // 清除相关状态，再对16-31B加密
                    memset(input_data_32, 0x0, sizeof(u32) * 4);
                    memset(output_data_32, 0x0, sizeof(u32) * 4);
                    memset(output_data_8, 0x0, sizeof(u8) * 16);
                    for(int i = 0; i < 4; i++){
                        four_char_to_int(&(data_padding[16 + i * 4]), &(input_data_32[i]));
                    }
                    crypt_128bit_ECB(input_data_32, usr_key_32, output_data_32, info->crypt_mode);
                    for(int i = 0; i < 4; i++){
                        int_to_four_char(output_data_32[i], &(output_data_8[i * 4]));
                    }
                    fwrite(output_data_8, sizeof(u8), 16, fp_out);
                }
                break;
            }
            // if之外的部分，文件长度一定大于128bit
            // 按序每次取16B加密
            fread(input_data_8, sizeof(u8), 16, fp_in);
            for(int i = 0; i < 4; i++){
                four_char_to_int(&(input_data_8[i * 4]), &(input_data_32[i]));
            }
            crypt_128bit_ECB(input_data_32, usr_key_32, output_data_32, info->crypt_mode);
            for(int i = 0; i < 4; i++){
                int_to_four_char(output_data_32[i], &(output_data_8[i * 4]));
            }
            fwrite(output_data_8, sizeof(u8), 16, fp_out);
            dealt_bytes += 16;
        }
       
        fclose(fp_in);
        fclose(fp_key);
        fclose(fp_out);
       
        system("pause");
    }

    return 0;
}








