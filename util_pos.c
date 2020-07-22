/*
	生成静态库用以链接
	gcc -c util_pos.c
	ar -crv libutil_pos.a util_pos.o
*/
#include "util_pos.h"
#include "string.h"
#include "secp256k1-vrf.h"
#include "util.h"
#include "hash_impl.h"
#include "testrand_impl.h"
#include "scalar_4x64_impl.h"

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


void get_hash(char *input, char *output){
    unsigned char out[32];
    secp256k1_sha256 hasher;
    secp256k1_sha256_initialize(&hasher);
    secp256k1_sha256_write(&hasher, (const unsigned char*)(input), strlen(input));
    secp256k1_sha256_finalize(&hasher, out);
    //printf("strlen(inputs[%d])=%d\nout=%s\n", i, strlen(inputs[i]), out);
    //CHECK(memcmp(out, outputs[i], 32) == 0);
    if (strlen(input) > 0) {
        int split = secp256k1_rand_int(strlen(input));
        //printf("split=%d\n", split);
        secp256k1_sha256_initialize(&hasher);
        secp256k1_sha256_write(&hasher, (const unsigned char*)(input), split);
        secp256k1_sha256_write(&hasher, (const unsigned char*)(input + split), strlen(input) - split);
        secp256k1_sha256_finalize(&hasher, out);
        byteToHexStr(out, 32, output);
        // print_hex("out", out, 32);
        // char outputsi[9];
        // sprintf(outputsi, "outputs%d", i );
        // outputsi[8] = '\0';
        // print_hex(outputsi, outputs[i], 32);
        //CHECK(memcmp(out, outputs[i], 32) == 0);
	}
	output[64] = '\0';
}

void sign(unsigned char message[32], char hex_signature[149], unsigned char sk[32]){
	secp256k1_ecdsa_signature signature;
	secp256k1_pubkey pubkey;
	secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
	CHECK(secp256k1_ec_pubkey_create(ctx, &pubkey, sk) == 1);
	CHECK(secp256k1_ecdsa_sign(ctx, &signature, message, sk, NULL, NULL) == 1);
	CHECK(secp256k1_ecdsa_verify(ctx, &signature, message, &pubkey) == 1);
	
	//method 1: serialize signature
	byteToHexStr(signature.data, 64, hex_signature);
	unsigned char data[64];
	from_hex(hex_signature, 128, data);
	memset(signature.data, '0', 64);
	memcpy(signature.data, data, 64);
	CHECK(secp256k1_ecdsa_verify(ctx, &signature, message, &pubkey) == 1);
	
	//method 2: serialize signature
	/*unsigned char sig[75];
	size_t siglen = 74;

	byteToHexStr(sig, 74, hex_signature);
	hex_signature[148] = '\0';
	CHECK(secp256k1_ecdsa_signature_serialize_der(ctx, sig, &siglen, &signature) == 1);
	CHECK(secp256k1_ecdsa_signature_parse_der(ctx, &signature, sig, siglen) == 1);
    CHECK(secp256k1_ecdsa_verify(ctx, &signature, message, &pubkey) == 1);*/
}

void get_merkle_root(char *input, char *output){
	int i =0;
	for(i=0; i<64; i++){
		output[i] = '0';
	}
	output[64] = '\0';
}