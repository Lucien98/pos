/*
	生成静态库用以链接
	gcc -c util_pos.c
	ar -crv libutil_pos.a util_pos.o
*/
#include "util_pos.h"
#include "string.h"
#include "secp256k1-vrf.h"
#include "util.h"
unsigned char HexToInt(int h){
  CHECK( (h>='0' && h<='9') ||  (h>='a' && h<='f') ||  (h>='A' && h<='F') );
  h += 9*(1&(h>>6));
  return (unsigned char)(h & 0xf);
}

void from_hex(char *source, int size, unsigned char *dest){
  char *end = source + size;
  while( source<end ){
    unsigned char c1 = *(source++);
    unsigned char c2 = *(source++);
    *(dest++) = (HexToInt(c1)<<4) | HexToInt(c2);
  }
}

void print_hex(char *desc, unsigned char *data, int size){
  int i;
  printf("%s=", desc);
  for(i=0; i<size; i++){
    printf("%02X", data[i]);
  }
  puts("");
}

int HexStrTobyte(char *str, unsigned char *out, unsigned int *outlen)
{
	char *p = str;
	char high = 0, low = 0;
	int tmplen = strlen(p), cnt = 0;
	tmplen = strlen(p);
	while(cnt < (tmplen / 2))
	{
		high = ((*p > '9') && ((*p <= 'F') || (*p <= 'f'))) ? *p - 48 - 7 : *p - 48;
		low = (*(++ p) > '9' && ((*p <= 'F') || (*p <= 'f'))) ? *(p) - 48 - 7 : *(p) - 48;
		out[cnt] = ((high & 0x0f) << 4 | (low & 0x0f));
		p ++;
		cnt ++;
	}
	if(tmplen % 2 != 0) out[cnt] = ((*p > '9') && ((*p <= 'F') || (*p <= 'f'))) ? *p - 48 - 7 : *p - 48;

	if(outlen != NULL) *outlen = tmplen / 2 + tmplen % 2;
	return tmplen / 2 + tmplen % 2;
}


int  byteToHexStr(unsigned char byte_arr[],int arr_len, char* HexStr){
	int  i,index = 0;
	for (i=0;i<arr_len;i++)
	{
		char hex1;
		char hex2;
		int value=byte_arr[i];
		int v1=value/16;
		int v2=value % 16;
		if (v1>=0&&v1<=9)
			hex1=(char)(48+v1);
		else
			hex1=(char)(55+v1);
		if (v2>=0&&v2<=9)
			hex2=(char)(48+v2);
		else
			hex2=(char)(55+v2);
		HexStr[index++] = hex1;
		HexStr[index++] = hex2;
	}
	HexStr[index] = '\0';
	return 0 ;
}
