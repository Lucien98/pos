/*
gcc pos.c -o pos -I /usr/include/mysql -L/usr/lib/mysql -lmysqlclient
sudo ./pos
*/
#include "secp256k1-vrf.h"
#include "util.h"
#include "testrand_impl.h"

#include <stdlib.h>  
#include <stdio.h>  
#include <malloc.h>
#include <string.h>

#include "util_pos.h"
#include "util_mysql.h"

#define NUM_STKHLD 5000
void generate_stakeholder(void){
	secp256k1_context *ctx;
	unsigned char seckey[32];
	secp256k1_pubkey pubkey;
	unsigned char pk[33];
	size_t pklen = 33;
	int i;
	char *sql_gen_stkhld = (char *)malloc(2*NUM_STKHLD*(1/*(*/+7/*00000, */+36/*"sk", */ + 38/*"pk"), */) + 100);
	strcat(sql_gen_stkhld, "insert into stakeholder values ");

	ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
	for(i=0; i<NUM_STKHLD; i++){
		secp256k1_rand256(seckey);

		CHECK(secp256k1_ec_pubkey_create(ctx, &pubkey, seckey) == 1);
		CHECK(secp256k1_ec_pubkey_serialize(ctx, pk, &pklen, &pubkey, SECP256K1_EC_COMPRESSED) == 1);
		char hex_seckey[65], hex_pk[67]; 
		byteToHexStr(seckey, 32, hex_seckey);
		byteToHexStr(pk, 33, hex_pk);
		
		sprintf(sql_gen_stkhld, "%s(%d, \"%s\", \"%s\"), ", sql_gen_stkhld, i, hex_seckey, hex_pk);
		
	}
	sql_gen_stkhld[strlen(sql_gen_stkhld)-2] = '\0';
	insert_sql(sql_gen_stkhld);
	free(sql_gen_stkhld);
}

int main(){
	generate_stakeholder();
	return 0;
}