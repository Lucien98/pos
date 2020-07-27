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
//#include "scalar_4x64_impl.h"
#include "merkletree.h"

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
    if (strlen(input) > 0) {
        int split = secp256k1_rand_int(strlen(input));
        secp256k1_sha256_initialize(&hasher);
        secp256k1_sha256_write(&hasher, (const unsigned char*)(input), split);
        secp256k1_sha256_write(&hasher, (const unsigned char*)(input + split), strlen(input) - split);
        secp256k1_sha256_finalize(&hasher, out);
        byteToHexStr(out, 32, output);
	}
	output[64] = '\0';
}

void sign(unsigned char message[32], char hex_signature[149], unsigned char sk[32]){
	secp256k1_ecdsa_signature signature;
	secp256k1_pubkey pubkey;
	secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
	CHECK(secp256k1_ec_pubkey_create(ctx, &pubkey, sk) == 1);
	CHECK(secp256k1_ecdsa_sign(ctx, &signature, message, sk, NULL, NULL) == 1);
	//CHECK(secp256k1_ecdsa_verify(ctx, &signature, message, &pubkey) == 1);
	
	//method 1: serialize signature
	byteToHexStr(signature.data, 64, hex_signature);
	/*unsigned char data[64];
	from_hex(hex_signature, 128, data);
	memset(signature.data, '0', 64);
	memcpy(signature.data, data, 64);
	CHECK(secp256k1_ecdsa_verify(ctx, &signature, message, &pubkey) == 1);
	*/

	//method 2: serialize signature
	/*unsigned char sig[75];
	size_t siglen = 74;

	byteToHexStr(sig, 74, hex_signature);
	hex_signature[148] = '\0';
	CHECK(secp256k1_ecdsa_signature_serialize_der(ctx, sig, &siglen, &signature) == 1);
	CHECK(secp256k1_ecdsa_signature_parse_der(ctx, &signature, sig, siglen) == 1);
    CHECK(secp256k1_ecdsa_verify(ctx, &signature, message, &pubkey) == 1);*/
}

void get_merkle_root(char *field_tx, char *output){
	mt_t *mt;
	uint8_t tx[10][32];
	//char field_tx[] = "(\"23B7283486AD1C53A5FBB9044C94A3A70DF95EFD0B0F6CB38E0712857BF91079\", \"01672B55C1536C0F86FC666AF5CE5415BCE22353A545F7AD6B87EE1867D37219\", \"69FDCEDF2CA6F8ACD4B819D2CF4EF59E820229DFC0E83F41F83C99A35A20D2B8\", \"AA1D583271A28DA2D26F4EEB4AC27D51B4246956E97DE1427E11F59A3D9CA583\", \"150523C16F3D017836B188C5ADBF89F8C51D9C719C3E78777102AB0BF713B5CB\", \"027E6B877CDA51CD59993954A32FB203F40B6B24EBA89557BC1426223830C32B\", \"A96F43BD3B788A00C4027356943391690DC671C7703957BD74BAE97FAAD65296\", \"2108DDD310CBB3157598AB53399D1C18A109EA97E4B90C2A1705228E06E4DD38\", \"25B67DA8EAFB469BF45AE3C7913C96D5BEE9AF6FB8ECF210E9BA4E73BBBF8814\", \"63A932A5CEF2576D0F8F98CA7B51E6FAA1F03541673FE68ED2F93A15A6A4FB59\")";
	char hex_tx[10][65];
	mt_hash_t root;
	char *p;
	
	mt = mt_create();
	memset(root, 0, sizeof(mt_hash_t));

	char *delim = "\", ()";
	p = strtok(field_tx, delim);
	printf("%s\n", p);
	memcpy(hex_tx[0], p, 64);
	int i = 0;
	while(i < 9)
	{
		p = strtok(NULL, delim);
		memcpy(hex_tx[++i], p, 64);
		//printf("%s\n", p);
	}
	i = 10;
	while(i--){
		from_hex(hex_tx[9-i], 64, tx[9-i]);
	}

	for(i=0; i < 10; i++){
		// if(mt_add(mt, tx[i], 32) != MT_SUCCESS)
		// 	printf("add fails\n");
		CHECK(mt_add(mt, tx[i], 32) == MT_SUCCESS);
	}

	// for(i=0; i<10; i++){
	// 	if(mt_verify(mt, tx[i], 32, i) != MT_SUCCESS)
	// 		printf("verify fails\n");
	// }
	mt_get_root(mt, root);
	//print_hex("root", root, 32);

	mt_delete(mt);
	byteToHexStr(root, 32, output);	
	//output[64] = '\0';
}

