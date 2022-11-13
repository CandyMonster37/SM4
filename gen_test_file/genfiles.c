#include <stdio.h>
#include <stdlib.h>

int main(){
    FILE* fp = fopen("1_16B.txt", "wb");
    unsigned char cont16[16] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    };
    fwrite(cont16, sizeof(char), 16, fp);
    fclose(fp);

    fp = fopen("1_32B.txt", "wb");
    unsigned char cont32[32] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    };
    fwrite(cont32, sizeof(char), 32, fp);
    fclose(fp);

    fp = fopen("1_15B.txt", "wb");
    unsigned char cont15[15] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32
    };
    fwrite(cont15, sizeof(char), 15, fp);
    fclose(fp);

    fp = fopen("1_31B.txt", "wb");
    unsigned char cont31[31] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32
    };
    fwrite(cont31, sizeof(char), 31, fp);
    fclose(fp);

    fp = fopen("1_17B.txt", "wb");
    unsigned char cont17[17] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
        0x01
    };
    fwrite(cont17, sizeof(char), 17, fp);
    fclose(fp);

    fp = fopen("1_33B.txt", "wb");
    unsigned char cont33[33] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
        0x01
    };
    fwrite(cont33, sizeof(char), 33, fp);
    fclose(fp);

    fp = fopen("key.cr", "wb");
    unsigned char key[16] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    };
    fwrite(key, sizeof(char), 16, fp);
    fclose(fp);

    return 0;
}
