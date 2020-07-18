#ifndef __UTIL_POS_H__
#define __UTIL_POS_H__


unsigned char HexToInt(int h);
void from_hex(char *source, int size, unsigned char *dest);
void print_hex(char *desc, unsigned char *data, int size);
int HexStrTobyte(char *str, unsigned char *out, unsigned int *outlen);
int byteToHexStr(unsigned char byte_arr[],int arr_len, char* HexStr);
#endif