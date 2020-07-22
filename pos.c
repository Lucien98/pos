/*
gcc pos.c -o pos -I /usr/include/mysql -L/usr/lib/mysql -lmysqlclient
sudo ./pos
*/
#include "secp256k1-vrf.h"
#include "util.h"
#include "testrand_impl.h"

#include "mysql.h"

#include <stdlib.h>  
#include <stdio.h>  
#include <malloc.h>
#include <string.h>
#include <time.h>

#include "util_pos.h"
#include "util_mysql.h"

#define NUM_STKHLD 5000

#define MERKLE_ROOT_LEN 64 
#define SIGNATURE_LEN 
#define TX_LEN 100
#define NONCE "A6E3C57DD01ABE90086538398355DD4C3B17AA873382B0F24D6129493D8AAD60"
#define DIFFICULTY "0D1B71758E2196800000000000000000000000000000000000000000000000" 
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
		
		sprintf(sql_gen_stkhld, "%s(%d, \"%s\", \"%s\"), ", sql_gen_stkhld, i, hex_pk, hex_seckey);
		
	}
	sql_gen_stkhld[strlen(sql_gen_stkhld)-2] = '\0';
	insert_sql(sql_gen_stkhld);
	free(sql_gen_stkhld);
}

/*block_header hash, signature, merkle_root都是可以计算的 */
void insert_block(int height, unsigned char prevhash[], unsigned char vrf_pk[], \
	unsigned char vrf_hash[], unsigned char vrf_proof[], char tx[]){
	char *sql = (char *) malloc(10240);
	char hash[65]; 
	unsigned char signature[149];
	char merkle_root[65];
	get_merkle_root(tx, merkle_root);
	char *blk_hdr = (char *)malloc(1024);
	sprintf(blk_hdr, "%d%s%s%s%s%s", height, prevhash, vrf_pk, vrf_hash, vrf_proof, merkle_root);
	get_hash(blk_hdr, hash);

	//判断是否是genesis　block
	char zero_pk[67];
	memset(zero_pk, '0', 66);
	zero_pk[66] = '\0';
	//如果不是genesis block，则生成对区块哈希的签名
	if(memcmp(vrf_pk, zero_pk, 66) != 0){
		char hex_sk[65];
		unsigned char seckey[32];
		get_stkhld_sk(vrf_pk, hex_sk);
		from_hex(hex_sk, 64, seckey);

		unsigned char message[32];
		from_hex(hash, 64, message);
		sign(message, signature, seckey);

	}


	sprintf(sql, "insert into block values(%d, \"%s\", \"%s\", \"%s\", \"%s\", \"%s\", \"%s\", \"%s\", \"%s\")",
		height, prevhash, vrf_pk, vrf_hash, vrf_proof, merkle_root, signature, tx, hash);
	insert_sql(sql);
	free(blk_hdr);
	free(sql);
}

void generate_genblk(){
	int height = 0;
	char prevhash[65]={'0'}, vrf_proof[163]={'0'}, \
		vrf_pk[67]={'0'}, vrf_hash[65]={'0'};
	char *tx="transactions";
	memset(prevhash , '0', 64);
	memset(vrf_proof, '0', 162);
	memset(vrf_pk, '0', 66);
	memset(vrf_hash, '0', 64);
	prevhash[64] = vrf_proof[162] = vrf_pk[66] = vrf_hash[64] = '\0';
	insert_block(height, prevhash, vrf_pk, vrf_hash, vrf_proof,tx);
	
}


int mulblk_flag = 0;//一个slot出现多个合法区块的标记

/**/
void leader_election(int slot){
	

	mulblk_flag = 0;
	char *nonce = "A6E3C57DD01ABE90086538398355DD4C3B17AA873382B0F24D6129493D8AAD60";
	char *difficulty = "000D1B71758E2196800000000000000000000000000000000000000000000000";
	char *msg;
	int msglen;
	msg = (char *)malloc(100);
	sprintf(msg, "%s%.6X", nonce, slot);
	int i = 0;
	
	unsigned char proof[81];
	unsigned char seckey[32];
	unsigned char output[32];
	secp256k1_pubkey pubkey;
	unsigned char pk[33];
	size_t pklen = 33;
	secp256k1_context *sender = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
	msglen = strlen(msg);
	
	//use stakeholder's sk to compute their vrf output, proof, and pk
	char *sql = (char *)malloc(100);
	sprintf(sql,"select sk from stakeholder");
	MYSQL_RES  *res_ptr;
	select_sql(sql, &res_ptr);
	
	if(res_ptr){
		for(int i=0; i<NUM_STKHLD; i++){
			MYSQL_ROW row = mysql_fetch_row(res_ptr);//row[0] is the sk string
			//covert string version hex to unsigned char version hex(type: unsigned char )
			from_hex(row[0], 64, seckey);
			CHECK(secp256k1_ec_pubkey_create(sender, &pubkey, seckey) == 1);
			CHECK(secp256k1_ec_pubkey_serialize(sender, pk, &pklen, &pubkey, SECP256K1_EC_COMPRESSED) == 1);
			CHECK(secp256k1_vrf_prove(proof, seckey, &pubkey, msg, msglen) == 1);
			secp256k1_vrf_proof_to_hash(output, proof);
			char hex_output[65];
			byteToHexStr(output, 32, hex_output);
			
			//CHECK(secp256k1_vrf_verify(output, proof, pk, msg, msglen) == 1);

			if(strcmp(hex_output, difficulty)<0 && mulblk_flag==0){
				mulblk_flag = 1;
				
				/*get prevhash*/
				sprintf(sql, "select hash from block where height = (select max(height) from block)");
				MYSQL_RES *res_hash;
				select_sql(sql, &res_hash);
				MYSQL_ROW row_hash = mysql_fetch_row(res_hash);
				mysql_free_result(res_hash);
				char prevhash[65];
				memcpy(prevhash, row_hash[0], 64);
				prevhash[64] = '\0';
				
				/*convert pk, proof to hex string*/
				char hex_pk[67];
				char hex_proof[163];
				byteToHexStr(pk, 33, hex_pk);
				byteToHexStr(proof, 81, hex_proof);
				char *tx = "transactions";
				int height = slot;
				
				insert_block(height, prevhash, hex_pk, hex_output, hex_proof,tx);


			}
			else if(strcmp(hex_output, difficulty)<0 && mulblk_flag==1){
				//printf("\n\n\n\n\n很可惜，本轮有人先你一步产生区块了，你没有取得产生区块的资格\n\n\n\n\n");
			}else{
				//printf("您没有中奖哦\n");
			}
		}
	}
	mysql_free_result(res_ptr);
	if(mulblk_flag == 0){

	}
	free(sql);
	free(msg);
}

int validate_blockchain(){
	char *nonce = "A6E3C57DD01ABE90086538398355DD4C3B17AA873382B0F24D6129493D8AAD60";
	char *difficulty = "000D1B71758E2196800000000000000000000000000000000000000000000000";
	char *msg;
	int msglen;
	msg = (char *)malloc(100);
	secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

	char *sql = (char *)malloc(100);
	sprintf(sql, "select * from block");
	MYSQL_RES *res_blocks;
	select_sql(sql, &res_blocks);
	int rows = mysql_num_rows(res_blocks);
	int i = 0;
	MYSQL_ROW block = mysql_fetch_row(res_blocks);


	clock_t start, finish;
	start = clock();
	for(i=1; i<rows; i++){
		printf("%d\n", i);
		//从查询结果中提取数据
		block = mysql_fetch_row(res_blocks);
		int height;
		char prevhash[65];
		char vrf_pk[67];
		char vrf_hash[65];
		char vrf_proof[163];
		char merkle_root[MERKLE_ROOT_LEN + 1];
		char signature[149];
		char tx[TX_LEN + 1];
		char hash[65];
		
		height = atoi(block[0]);
		sprintf(prevhash, 		"%s", block[1]);
		sprintf(vrf_pk, 		"%s", block[2]);
		sprintf(vrf_hash, 		"%s", block[3]);
		sprintf(vrf_proof, 		"%s", block[4]);
		sprintf(merkle_root, 	"%s", block[5]);
		sprintf(signature, 		"%s", block[6]);
		sprintf(tx, 			"%s", block[7]);
		sprintf(hash, 			"%s", block[8]);
		
		sprintf(msg, "%s%.6X", nonce, height);
		msglen = strlen(msg);	
		{
				
			unsigned char pk[33], proof[81], output[32];
			from_hex(vrf_pk, 66, pk);
			from_hex(vrf_hash, 64, output);
			from_hex(vrf_proof, 162, proof);
			CHECK(secp256k1_vrf_verify(output, proof, pk, msg, msglen) == 1);
			CHECK(strcmp(vrf_hash, difficulty)<0);

		}

		/*validate block hash*/
		{
			char *blk_hdr = (char *)malloc(1024);
			char hash_compute[65];
			sprintf(blk_hdr, "%d%s%s%s%s%s", height, prevhash, vrf_pk, vrf_hash, vrf_proof, merkle_root);
			get_hash(blk_hdr, hash_compute);
			free(blk_hdr);
			CHECK(memcmp(hash, hash_compute, sizeof(hash)) == 0);
		}

		/*validate signature*/
		{
			secp256k1_ecdsa_signature ecdsa_signature;
			secp256k1_pubkey pubkey;

			unsigned char message[32];
			unsigned char pk[33];
			size_t pklen = 33;
			from_hex(hash, 64, message);
			from_hex(vrf_pk, 66, pk);
    		CHECK(secp256k1_ec_pubkey_parse(ctx, &pubkey, pk, pklen) == 1);
			unsigned char data[64];
			from_hex(signature, 128, data);
			memcpy(ecdsa_signature.data, data, 64);
			CHECK(secp256k1_ecdsa_verify(ctx, &ecdsa_signature, message, &pubkey) == 1);

		}
		/*validate prevhash*/
		{
			sprintf(sql, "select * from block where hash = \"%s\"", prevhash);
			MYSQL_RES *res_prev_block;
			select_sql(sql, &res_prev_block);
			MYSQL_ROW prev_block = mysql_fetch_row(res_prev_block);
			mysql_free_result(res_prev_block);
			int prev_height;
			char prev_prevhash[65];
			char prev_vrf_pk[67];
			char prev_vrf_hash[65];
			char prev_vrf_proof[163];
			char prev_merkle_root[MERKLE_ROOT_LEN + 1];
			char prev_signature[149];
			char prev_tx[TX_LEN + 1];
			char prev_hash[65];
			
			prev_height = atoi(prev_block[0]);
			sprintf(prev_prevhash, 		"%s", prev_block[1]);
			sprintf(prev_vrf_pk, 		"%s", prev_block[2]);
			sprintf(prev_vrf_hash, 		"%s", prev_block[3]);
			sprintf(prev_vrf_proof, 	"%s", prev_block[4]);
			sprintf(prev_merkle_root, 	"%s", prev_block[5]);
			sprintf(prev_signature, 	"%s", prev_block[6]);
			sprintf(prev_tx, 			"%s", prev_block[7]);
			sprintf(prev_hash, 			"%s", prev_block[8]);
			
			char *blk_hdr = (char *)malloc(1024);
			char hash_compute[65];
			sprintf(blk_hdr, "%d%s%s%s%s%s", prev_height, prev_prevhash, prev_vrf_pk, \
				prev_vrf_hash, prev_vrf_proof, prev_merkle_root);
			get_hash(blk_hdr, hash_compute);
			free(blk_hdr);
			CHECK(memcmp(prevhash, hash_compute, sizeof(prevhash)) == 0);

		}
	}

	finish = clock();
	printf("validation time: %.6f", (double)(finish - start)/CLOCKS_PER_SEC);
	free(msg);
	mysql_free_result(res_blocks);
	printf("validation success\n");

}

int main(){
	
	//generate_stakeholder();
	char *sql = "truncate table block";
	insert_sql(sql);

	generate_genblk();

	clock_t start, finish, start_time, finish_time;
	start_time = clock();
	for(int i=1; i<10; i++){
		printf("%dth slot leader_election\n", i);
		
		start = clock();
		leader_election(i);
		finish = clock();
		printf("using time: %f\nseconds",(double)(finish - start)/CLOCKS_PER_SEC);
	}
	validate_blockchain();
	finish_time = clock();
	printf("%f\n",(double)(finish_time - start_time)/CLOCKS_PER_SEC);
	return 0;

}
