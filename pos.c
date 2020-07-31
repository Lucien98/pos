/*
gcc pos.c -o pos -I /usr/include/mysql -L/usr/lib/mysql -lmysqlclient
sudo ./pos
*/
#include "secp256k1-vrf.h"
#include "secp256k1-vrf/util.h"
#include "secp256k1-vrf/testrand_impl.h"

#include "mysql.h"

#include <stdlib.h>  
#include <stdio.h>  
#include <malloc.h>
#include <string.h>
#include <time.h>

#include "util_pos.h"
#include "util_mysql.h"


#define HOST "127.0.0.1"
#define USERNAME "root"
#define PASSWORD ""
#define DATABASE "pos"


#define NUM_STKHLD 5000

#define MERKLE_ROOT_LEN 64 
#define SIGNATURE_LEN 
#define TX_LEN 750
#define NONCE "A6E3C57DD01ABE90086538398355DD4C3B17AA873382B0F24D6129493D8AAD60"
#define DIFFICULTY "0D1B71758E2196800000000000000000000000000000000000000000000000" 
#define MAX_TRANSFER_VALUE 1000
FILE *fp;
MYSQL *conn;
void generate_stakeholder(void){
	secp256k1_context  *ctx;
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
	//用以判断是否是genesis　block
	char zero_pk[67];
	memset(zero_pk, '0', 66);
	zero_pk[66] = '\0';
	
	if(memcmp(vrf_pk, zero_pk, 66) != 0){
		char *tx_bak = (char *)malloc(750);
		memcpy(tx_bak, tx, strlen(tx));
		get_merkle_root(tx_bak, merkle_root);
	}

	char *blk_hdr = (char *)malloc(1024);
	sprintf(blk_hdr, "%d%s%s%s%s%s", height, prevhash, vrf_pk, vrf_hash, vrf_proof, merkle_root);
	get_hash(blk_hdr, hash);

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

	sprintf(sql, "insert into block values(%d, \"%s\", \"%s\", \"%s\", \"%s\", \"%s\", \"%s\", \'%s\', \"%s\")",
		height, prevhash, vrf_pk, vrf_hash, vrf_proof, merkle_root, signature, tx, hash);
	insert_sql(sql);
	free(blk_hdr);
	free(sql);
}

void generate_genblk(){
	int height = 0;
	char prevhash[65]={'0'}, vrf_proof[163]={'0'}, \
		vrf_pk[67]={'0'}, vrf_hash[65]={'0'};
	char *tx="";
	memset(prevhash , '0', 64);
	memset(vrf_proof, '0', 162);
	memset(vrf_pk, '0', 66);
	memset(vrf_hash, '0', 64);
	prevhash[64] = vrf_proof[162] = vrf_pk[66] = vrf_hash[64] = '\0';
	insert_block(height, prevhash, vrf_pk, vrf_hash, vrf_proof,tx);
	
}


int mulblk_flag = 0;//一个slot出现多个合法区块的标记
int interval_count = 0;
//#define INTERVAL 3
int INTERVAL = 3;
/**/
void leader_election(int slot){
	
	printf("\n\n\n%dth　slot leader election\n", slot);
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
	sprintf(sql,"select sk, id from stakeholder");
	MYSQL_RES  *res_ptr;
	select_sql(sql, &res_ptr);
	int del_response, del_request;
	if(res_ptr){
		for(i=0; i<NUM_STKHLD; i++){
			MYSQL_ROW row = mysql_fetch_row(res_ptr);//row[0] is the sk string
			//covert string version hex to unsigned char version hex(type: unsigned char )
			from_hex(row[0], 64, seckey);
			CHECK(secp256k1_ec_pubkey_create(sender, &pubkey, seckey) == 1);
			CHECK(secp256k1_ec_pubkey_serialize(sender, pk, &pklen, &pubkey, SECP256K1_EC_COMPRESSED) == 1);
			CHECK(secp256k1_vrf_prove(proof, seckey, &pubkey, msg, msglen) == 1);
			secp256k1_vrf_proof_to_hash(output, proof);
			char hex_output[65];
			byteToHexStr(output, 32, hex_output);
			
			if(strcmp(hex_output, difficulty)<0 && mulblk_flag==0){
				printf("stakeholder %s is elected as the %dth slot leader\n", row[1], slot);

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
				
				printf("generating tx\n");
				char *tx = (char *)malloc(750);
				tx[0] = '\0';
				interval_count = (interval_count + 1) % INTERVAL;
				del_response = generate_tx_del_response(tx);
				if(interval_count == 0) del_request = generate_tx_del_request(tx);
				else del_request = 0;
				
				generate_tx(tx, 10 - del_request - del_response);
				
				int height = slot;
				printf("generating a block \n");				
				insert_block(height, prevhash, hex_pk, hex_output, hex_proof,tx);
				mysql_free_result(res_ptr);
				free(sql);
				free(msg);
				return ;

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
		printf("no one is chosen for slot leader\n");
	}
	free(sql);
	free(msg);
}

int compare(const void *p1, const void *p2){
	return memcmp((char *)p1, (char *)p2, 64);
}

int validate_blockchain(){
	char *nonce = "A6E3C57DD01ABE90086538398355DD4C3B17AA873382B0F24D6129493D8AAD60";
	char *difficulty = "000D1B71758E2196800000000000000000000000000000000000000000000000";
	char *msg = (char *)malloc(66+66+5+228114);
	int msglen;

	secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

	insert_sql("update stxo set stxo = '()'");
	char *sql = (char *)malloc(1000);
	sprintf(sql, "select * from block order by height");
	MYSQL_RES *res_blocks;

	struct timespec begin, end;
	//long long start, finish;
	clock_gettime(CLOCK_MONOTONIC, &begin);
	select_sql(sql, &res_blocks);
	clock_gettime(CLOCK_MONOTONIC, &end);
	printf("select sql using time: %f\n", (double) (end.tv_nsec - begin.tv_nsec)/1000000000 + end.tv_sec - begin.tv_sec);
	
	int rows = mysql_num_rows(res_blocks);
	int i = 0;
	MYSQL_ROW block = mysql_fetch_row(res_blocks);
	
	int height;
	char prevhash[65];
	char vrf_pk[67];
	char vrf_hash[65];
	char vrf_proof[163];
	char merkle_root[MERKLE_ROOT_LEN + 1];
	char signature[149];
	char tx[TX_LEN + 1];
	char hash[65];
	char prev_prevhash[65];
	
	unsigned char pk[33], proof[81], output[32];		

	char *blk_hdr = (char *)malloc(1024);
	char hash_compute[65];
	
	secp256k1_ecdsa_signature ecdsa_signature;
	secp256k1_pubkey pubkey;
	unsigned char message[32];
	size_t pklen = 33;
	unsigned char data[64];

	//int start_a, finish_a;
	//start_a = time(NULL);
	MYSQL_RES *res_prev_block;
	MYSQL_RES *res;
	MYSQL_RES *del_response;
	MYSQL_ROW del_resp_message;
	MYSQL_ROW row;
	char *tx_bak = (char *)malloc(750);
	char root[65];
	char hex_pk[67];
	char hex_tx[10][65];
	char *delim = "\", ()";
	char *p;
	int j;

	char *del_resp_tx_msg = (char *)malloc(228114);

	printf("\n\n\nvalidating starts\n");
	clock_gettime(CLOCK_MONOTONIC, &begin);
	for(i=1; i<rows; i++){
		//从查询结果中提取数据
		block = mysql_fetch_row(res_blocks);
		if(block == NULL){
			printf("block is null\n");
		}
		printf("\n\n\nvalidating block in slot %s\n", block[0]);
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
			
			from_hex(vrf_pk, 66, pk);
			from_hex(vrf_hash, 64, output);
			from_hex(vrf_proof, 162, proof);
			CHECK(secp256k1_vrf_verify(output, proof, pk, msg, msglen) == 1);
			CHECK(strcmp(vrf_hash, difficulty)<0);

		}

		/*validate block hash*/
		{
			sprintf(blk_hdr, "%d%s%s%s%s%s", height, prevhash, vrf_pk, vrf_hash, vrf_proof, merkle_root);
			get_hash(blk_hdr, hash_compute);
			CHECK(memcmp(hash, hash_compute, 64) == 0);
		}

		/*validate signature*/
		{
			from_hex(hash, 64, message);
			from_hex(vrf_pk, 66, pk);
    		CHECK(secp256k1_ec_pubkey_parse(ctx, &pubkey, pk, pklen) == 1);
			
			from_hex(signature, 128, data);
			memcpy(ecdsa_signature.data, data, 64);
			CHECK(secp256k1_ecdsa_verify(ctx, &ecdsa_signature, message, &pubkey) == 1);

		}
		/*validate prevhash*/
		{
			sprintf(sql, "select * from block where hash = \"%s\"", prevhash);
			
			select_sql(sql, &res_prev_block);

			MYSQL_ROW prev_block = mysql_fetch_row(res_prev_block);
			sprintf(blk_hdr, "%s%s%s%s%s%s", prev_block[0], prev_block[1], prev_block[2], \
				prev_block[3], prev_block[4], prev_block[5]);
			get_hash(blk_hdr, hash_compute);
			
			CHECK(memcmp(prevhash, hash_compute, sizeof(prevhash)) == 0);

		}

		/*validate transaction
		* first, verify transaction hash
		*	
		* second, verify merkle_root
		* third, verify that transaction output has not been spent
		*	
		*/

		//verify merkle_root
		{
			memcpy(tx_bak, tx, strlen(tx));
			get_merkle_root(tx_bak, root);
			CHECK(memcmp(block[5], root, 64) == 0);
		}
		//verify tx hash and sig
		{
			sprintf(sql, "select * from transaction where tx_hash in (%s)", tx);
			select_sql(sql, &res);
			while(row = mysql_fetch_row(res)){
				sprintf(msg, "%s%s%s%s", row[1], row[2], row[3], row[6]);
				if(memcmp(row[7], "1", 1) != 0){
					get_hash(msg, hash);
					CHECK(memcmp(hash, row[0], 64) == 0);
				}else{
					printf("\n\n\n\n\n\n\n\n\n\n");
					//get the deletion response transaction
					//char *del_req_message = (char *)malloc(120);
					sprintf(sql, "select tx_hash from transaction where message like '%%deletion request@%s%%'", row[0]);
					select_sql(sql, &del_response);
					//printf("%s\n", sql);
					del_resp_message = mysql_fetch_row(del_response);
					
					// sprintf(del_resp_tx_msg, "%s", del_resp_message[0]);
					// char *p;
					// p = strchr(del_resp_tx_msg, '@');
					// printf("-.200%s\n", p);
					// p++;
					sprintf(sql, "select message from transaction where message like '%%deletion response@%s%%'", del_resp_message[0]);
					select_sql(sql, &del_response);
					//printf("%s\n", sql);
					del_resp_message = mysql_fetch_row(del_response);
					
					sprintf(del_resp_tx_msg, "%s", del_resp_message[0]);
					//char *p;
					p = strchr(del_resp_tx_msg, '@');
					
					p = strchr(++p, '@');
					++p;
					//printf("-.200%s\n", p);
					//deletion response@txid@(vrf msgs)
					//						 |->now p is pointing here	
					secp256k1_pubkey pubkey;
					secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
					size_t pklen = 33;
					unsigned char vrf_pk[33];
					unsigned char vrf_proof[81];
					unsigned char vrf_output[32];
					unsigned char seckey[32];

					char hex_pk[67];
					char hex_proof[163];
					char hex_output[65];

					int vrf_count = 667;
					char *sql_pks = (char *)malloc(667*76);
					sprintf(sql_pks, "select count(*) from stakeholder where pk in (");
					//pks[0] = '\0';
					while(vrf_count--){
						sscanf(p, "%[^,], %[^,], %[^,]", hex_output, hex_proof, hex_pk);
						from_hex(hex_output, 64, vrf_output);
						from_hex(hex_proof, 162, vrf_proof);
						from_hex(hex_pk, 66, vrf_pk);
						CHECK(secp256k1_vrf_verify(vrf_output, vrf_proof, vrf_pk, row[0], 64) == 1);
						sprintf(sql_pks, "%s\"%s\",", sql_pks, hex_pk);
						p = strchr(p, ',');
						p++;
						//printf("-.200%s\n", p);
						p = strchr(p, ',');
						p++;
						p = strchr(p, ',');
						p++;
					}
					sql_pks[strlen(sql_pks)-1] = ')';
					printf("check vrf_pks is in stakeholder list\n");
					select_sql(sql_pks, &del_response);//reuse the variable del_response
					del_resp_message = mysql_fetch_row(del_response);
					CHECK(memcmp(del_resp_message[0], "667", 3) == 0);
					mysql_free_result(del_response);
					free(sql_pks);
					memcpy(hash, row[0], 64);

				}
				if(strlen(row[1]) == 66){
					from_hex(row[1], 66, pk);
				}else{
					get_tx_pk(row[1], hex_pk);//ref_tx
					from_hex(hex_pk, 66, pk);
				}
				from_hex(hash, 64, message);
				CHECK(secp256k1_ec_pubkey_parse(ctx, &pubkey, pk, pklen) == 1);
			
				from_hex(row[4], 128, data);
				memcpy(ecdsa_signature.data, data, 64);
				CHECK(secp256k1_ecdsa_verify(ctx, &ecdsa_signature, message, &pubkey) == 1);
			}
		}
		//verify there is no stxo according to the field tx
		{
			memcpy(tx_bak, tx, strlen(tx));
			p = strtok(tx_bak, delim);
			memcpy(hex_tx[0], p, 64);
			j = 0;
			while(p = strtok(NULL, delim))
				memcpy(hex_tx[++j], p, 64);
			qsort(hex_tx, 10, sizeof(char)*65, compare);
			for(j=0; j < 9; j++){
				CHECK(memcmp(hex_tx[j], hex_tx[j+1], 64) != 0);
			}
			sprintf(sql, "select count(stxo) from stxo where stxo like '%%%-.64s%%'", hex_tx[0]);
			for(j=1; j<10; sprintf(sql, "%s or stxo like '%%%-.64s%%'", sql, hex_tx[j++]));
			select_sql(sql, &res);
			row = mysql_fetch_row(res);
			CHECK(memcmp(row[0], "0", 1) == 0);
			sprintf(sql, "update stxo set stxo = concat(stxo, '%s')", tx);
			printf("mark tx in this block as spent tx\n");
			insert_sql(sql);

		}
	}
	//finish_a = time(NULL);
	//printf("validation time: %d\n", (finish_a - start_a));
	clock_gettime(CLOCK_MONOTONIC, &end);
	double validate_time = (double) (end.tv_nsec - begin.tv_nsec)/1000000000 + end.tv_sec - begin.tv_sec;
	printf("validate blockchain using time: %f\n", validate_time);
	fprintf(fp, "total validate time,%.9lf\n", validate_time);
	free(msg);
	free(blk_hdr);
	free(sql);
	free(tx_bak);
	mysql_free_result(res_blocks);
	mysql_free_result(res_prev_block);
	mysql_free_result(res);

	printf("validation success\n");

}


/*
  generate all utxo, to make each stakeholder have about 10 utxo.
  including fields as follows: 
  	tx_hash: the hash of ref_hash | receiver_pk | value
  	ref_hash: 	is the referenced tx hash, it records the sender's pk,
  				in case where creating some utxo from zero, this field will record the 
  				specific pk that is specific in genesis block
  	receiver_pk: send this utxo to the receiver
  	value: the value of this utxo
  	sig: sender's signature on the tx_hash
  	has_spent: a flag marked whether this tx output has been spent by receiver
*/
void generate_utxo(){
	char *sql = (char *)malloc(400*10*NUM_STKHLD);
	//generate a pair of (sk, pk), used to generate 10 utxo for each stkhld
	unsigned char seckey[32];
	secp256k1_rand256(seckey);
	secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
	secp256k1_pubkey pubkey;
	unsigned char pk[33];//this pk will fill the ref_hash field while there is no utxo has been created
	size_t pklen = 33;

	CHECK(secp256k1_ec_pubkey_create(ctx, &pubkey, seckey) == 1);
	CHECK(secp256k1_ec_pubkey_serialize(ctx, pk, &pklen, &pubkey, SECP256K1_EC_COMPRESSED) == 1);


	char ref_hash[67];
	byteToHexStr(pk, 33, ref_hash);
	
	int value;

	char *msg = (char *)malloc(66+66+5+64);
	unsigned char msg_hash[32];
	char hex_hash[65];
	char hex_sig[129];
	MYSQL_RES *res_pk;
	int has_spent = 0;
	int utxo_count = 0;
	sprintf(sql, "insert into transaction (tx_hash, ref_hash, receiver_pk, value, sig, has_spent, message, is_deleted) values ");
	MYSQL_ROW row_pk; 
	int i = 100;

	char *tx_hex_message = (char *)malloc(65);
	unsigned char tx_message[32];

	clock_t start, finish;
	start = clock();
	for(select_sql("select pk from stakeholder", &res_pk);row_pk = mysql_fetch_row(res_pk) && i--;){
		row_pk = mysql_fetch_row(res_pk);
		do{
			secp256k1_rand256(tx_message);
			byteToHexStr(tx_message, 32, tx_hex_message);
			value = secp256k1_rand_int(MAX_TRANSFER_VALUE);
			//concatenate ref_hash | row_pk[0] | value and hash it 
			sprintf(msg, "%s%s%d%s", ref_hash, row_pk[0], value, tx_hex_message);
			get_hash(msg, hex_hash);
			from_hex(hex_hash, 64, msg_hash);
			sign(msg_hash, hex_sig, seckey);
			sprintf(sql, "%s(\"%s\", \"%s\", \"%s\", %d, \"%s\", %d, \"%s\", 0), ", sql, hex_hash, ref_hash, row_pk[0], value, hex_sig, has_spent, tx_hex_message);
		}while(9 > utxo_count++);
		utxo_count = 0;
	}
	finish = clock();
	printf("time: %f seconds\n", (double) (finish - start)/CLOCKS_PER_SEC);
	mysql_free_result(res_pk);
	sql[strlen(sql)-2] = '\0';
	sprintf(sql, "%s ON DUPLICATE KEY UPDATE has_spent = 0", sql);
	insert_sql(sql);
	free(sql);
	free(msg);
}

/*in response tx, */
int generate_tx_del_response(char *tx){

	char *sql = (char *)malloc(228114);

	MYSQL_RES *res;
	MYSQL_ROW del_req_tx;

	sprintf(sql, "select message, tx_hash from transaction where is_deleted = 4 and message like '%%deletion request@%%' order by rand() limit 1, 1");
	select_sql(sql, &res);
	if(mysql_num_rows(res) == 0){
		free(sql);
		return 0;
	}
	//sprintf(sql, "update transaction set message = concat('@', message)")
	char *hex_del_resp_message = (char *)malloc(667*(64+66+162+50));
	del_req_tx = mysql_fetch_row(res);
	
	sprintf(hex_del_resp_message, "deletion response@%s@", del_req_tx[1]);
	
	char *del_req_message = (char *)malloc(120);
	sprintf(del_req_message, "%s", del_req_tx[0]);
	char *p = strchr(del_req_message, '@');
	p++;
	char del_tx_id[65];
	sprintf(del_tx_id, "%s", p);
	
	//spends a tx
	sprintf(sql, "select * from transaction where has_spent <> 1 order by rand() limit 1, 1");
	select_sql(sql, &res);
	MYSQL_ROW tx2be_spent = mysql_fetch_row(res);
	//sprintf(tx, "%s", tx2be_spent[0]);
	//to get a receiver 
	//MYSQL_RES *res;
	MYSQL_ROW row_pk;
	sprintf(sql, "select pk from stakeholder order by rand() limit 1, 1");
	select_sql(sql, &res);
	row_pk = mysql_fetch_row(res);

	char *msg = (char *)malloc(228114);
	unsigned char msg_hash[32];
	char hex_hash[65];
	char hex_sig[129];
	unsigned char seckey[32];
	char sk[65];
	char hex_pk[67];
	int has_spent = 0;

	//sprintf(sql, "insert into transaction values ");
	
	sprintf(sql, "select pk, sk from stakeholder order by rand() limit 1, 667");
	select_sql(sql, &res);
	secp256k1_pubkey pubkey;
	secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
	size_t pklen = 33;
	unsigned char vrf_pk[33];
	unsigned char vrf_proof[81];
	unsigned char vrf_output[32];
	//unsigned char seckey[32];

	//char hex_pk[67];
	char hex_proof[163];
	char hex_output[65];
	MYSQL_ROW row;
	while(row = mysql_fetch_row(res)){
		//sprintf(hex_vrf_pk, "%s", row[0]);
		from_hex(row[0], 66, vrf_pk);
		from_hex(row[1], 64, seckey);
		CHECK(secp256k1_ec_pubkey_parse(ctx, &pubkey, vrf_pk, pklen) == 1);
		CHECK(secp256k1_vrf_prove(vrf_proof, seckey, &pubkey, del_tx_id, 64) == 1);
		CHECK(secp256k1_vrf_proof_to_hash(vrf_output, vrf_proof) == 1);
		//verify
		//CHECK(secp256k1_vrf_verify(vrf_output, vrf_proof, vrf_pk, del_tx_id, 64) == 1);

		byteToHexStr(vrf_output, 32, hex_output);
		byteToHexStr(vrf_proof, 81, hex_proof);
		sprintf(hex_del_resp_message, "%s%s,%s,%s,", hex_del_resp_message, hex_output, hex_proof, row[0]);	
	}

	sprintf(msg, "%s%s%s%s", tx2be_spent[0]/*curr tx's ref_hash*/, row_pk[0], tx2be_spent[3], hex_del_resp_message);
	get_hash(msg, hex_hash);
	
	get_tx_pk(tx2be_spent[0], hex_pk);//ref_tx
	get_stkhld_sk(hex_pk, sk);
	from_hex(sk, 64, seckey);
	from_hex(hex_hash, 64, msg_hash);
	sign(msg_hash, hex_sig, seckey);

	sprintf(sql, "insert into transaction values (\"%s\", \"%s\", \"%s\", %s, \"%s\", %d, \"%s\", 3) ", 
		hex_hash, tx2be_spent[0], row_pk[0], tx2be_spent[3], hex_sig, has_spent, hex_del_resp_message);
	mysql_free_result(res);
	printf("inseting a new tx into tx table: deletion response\n");
	insert_sql(sql);
	
	sprintf(sql, "update transaction set has_spent = 1 where tx_hash = \"%s\"", tx2be_spent[0]);
	printf("mark which tx output has been spent\n");
	insert_sql(sql);
	
	sprintf(sql, "update transaction set is_deleted = 1 where tx_hash = \"%s\"", del_tx_id);
	printf("response: tx deleted, update the is_deleted field in tx table\n");
	insert_sql(sql);

	sprintf(sql, "update transaction set is_deleted = 5 where tx_hash = \"%s\"", del_req_tx[1]);
	printf("the deletion request is responsed, mark it\n");
	insert_sql(sql);

	sprintf(tx, "\"%s\", ", hex_hash);
	free(sql);
	free(msg);
	free(hex_del_resp_message);
	free(del_req_message);
	return 1;
}

int generate_tx_del_request(char *tx){
	// int threshold = 400000000;
	// if(secp256k1_rand_int(2000000000) > threshold){
	// 	return 0;
	// }
	printf("\ngenerate a deletion request tx:\n\n");
	char *sql = (char *)malloc(10240);

	MYSQL_RES *res;
	MYSQL_ROW del_tx;

	//sprintf(sql, "select tx_hash from transaction where is_deleted = 0 order by rand() limit 1, 1");
	
	sprintf(sql, "select tx from block where height =(select max(height) from block)");
	select_sql(sql, &res);
	del_tx = mysql_fetch_row(res);

	sprintf(sql, "select tx_hash from transaction where tx_hash in (%s) and is_deleted = 0", del_tx[0]);
	select_sql(sql, &res);
	/*if(mysql_num_rows(res) == 0){
		free(sql);
		return 0;
	}*/
	char *hex_del_req_message = (char *)malloc(120);
	del_tx = mysql_fetch_row(res);
	
	sprintf(hex_del_req_message, "deletion request@%s", del_tx[0]);
	
	//spends a tx
	sprintf(sql, "select * from transaction where has_spent <> 1 order by rand() limit 1, 1");
	select_sql(sql, &res);
	MYSQL_ROW tx2be_spent = mysql_fetch_row(res);

	sprintf(sql, "update transaction set has_spent = 1 where tx_hash = \"%s\"", tx2be_spent[0]);
	printf("spends a tx in del request\n");
	insert_sql(sql);
	//to get a receiver 
	//MYSQL_RES *res;
	MYSQL_ROW row_pk;
	sprintf(sql, "select pk from stakeholder order by rand() limit 1, 1");
	select_sql(sql, &res);
	row_pk = mysql_fetch_row(res);

	char *msg = (char *)malloc(66+66+5+120);
	unsigned char msg_hash[32];
	char hex_hash[65];
	char hex_sig[129];
	unsigned char seckey[32];
	char sk[65];
	char hex_pk[67];
	int has_spent = 0;

	sprintf(msg, "%s%s%s%s", tx2be_spent[0]/*curr tx's ref_hash*/, row_pk[0], tx2be_spent[3], hex_del_req_message);
	get_hash(msg, hex_hash);
	
	get_tx_pk(tx2be_spent[0], hex_pk);//ref_tx
	get_stkhld_sk(hex_pk, sk);
	from_hex(sk, 64, seckey);
	from_hex(hex_hash, 64, msg_hash);
	sign(msg_hash, hex_sig, seckey);

	sprintf(sql, "insert into transaction values (\"%s\", \"%s\", \"%s\", %s, \"%s\", %d, \"%s\", 4) ", 
		hex_hash, tx2be_spent[0], row_pk[0], tx2be_spent[3], hex_sig, has_spent, hex_del_req_message);
	sprintf(tx, "%s\"%s\",",tx, hex_hash);
	mysql_free_result(res);
	printf("inseting a new tx into tx table: deletion request\n");
	insert_sql(sql);
	
	sprintf(sql, "update transaction set is_deleted = 2 where tx_hash = \"%s\"", del_tx[0]);
	printf("tx request to be deleted, update the is_deleted field in tx table\n");
	insert_sql(sql);

	free(sql);
	free(msg);
	free(hex_del_req_message);
	return 1;

}

/*
	*@brief: generate 10 tx, insert them into the tx table
	*@params: string tx, when function ends, the value of tx will be 10 tx hash, splitted by ","
*/

/*
	how 2 modify this function 2 adapt 2 the new demand 4 this prj,
	first we will generate 
*/
void generate_tx(char *tx, int tx_num){
	char *sql = (char *)malloc(10240);
	MYSQL_RES *res_tx;
	MYSQL_RES *res_pk;
	MYSQL_ROW row_tx;
	MYSQL_ROW row_pk;

	sprintf(sql, "select * from transaction where has_spent <> 1 order by rand() limit 1, %d", tx_num);
	select_sql(sql, &res_tx);
	sprintf(sql, "select pk from stakeholder order by rand() limit 1, %d", tx_num);
	select_sql(sql, &res_pk);

	char *msg = (char *)malloc(66+66+5+65);
	unsigned char msg_hash[32];
	char hex_hash[65];
	char hex_sig[129];
	unsigned char seckey[32];
	char sk[65];
	char hex_pk[67];
	int has_spent = 0;

	char *tx_hex_message = (char *)malloc(65);
	unsigned char tx_message[32];
	
	char tx_update[750];
	tx_update[0] = '\0';

	sql[0] = '\0';
	sprintf(sql, "insert into transaction values ");
	//tx[0] = '\0';
	for(int i=0; i < tx_num; i++){
		row_tx = mysql_fetch_row(res_tx);//this is the ref_tx
		row_pk = mysql_fetch_row(res_pk);
		/*需要更新has_spent字段，　*/
		sprintf(tx_update, "%s\"%s\", ", tx, row_tx[0]);
		secp256k1_rand256(tx_message);
		byteToHexStr(tx_message, 32, tx_hex_message);
		sprintf(msg, "%s%s%s%s", row_tx[0]/*curr tx's ref_hash*/, row_pk[0], row_tx[3], tx_hex_message);
		get_hash(msg, hex_hash);
		
		sprintf(tx, "%s\"%s\", ",tx, hex_hash);

		get_tx_pk(row_tx[0], hex_pk);//ref_tx
		get_stkhld_sk(hex_pk, sk);
		from_hex(sk, 64, seckey);
		from_hex(hex_hash, 64, msg_hash);
		sign(msg_hash, hex_sig, seckey);

		
		sprintf(sql, "%s(\"%s\", \"%s\", \"%s\", %s, \"%s\", %d, \"%s\", 0), ", 
			sql, hex_hash, row_tx[0], row_pk[0], row_tx[3], hex_sig, has_spent, tx_hex_message);

	}

	mysql_free_result(res_tx);
	mysql_free_result(res_pk);
	sql[strlen(sql)-2] = '\0';
	printf("inseting %d new tx into tx table\n", tx_num);
	insert_sql(sql);
	tx[strlen(tx)-2] = '\0';
	tx_update[strlen(tx_update)-2] = '\0';
	sprintf(sql, "update transaction set has_spent = 1 where tx_hash in (%s)", tx_update);
	printf("mark which %d tx output has been spent\n", tx_num);
	insert_sql(sql);
	free(sql);
	free(msg);

}

void validate_transaction(){
	char hex_pk[67] = "0229513AF2E52156FCB2AF80ABA7889F9CDB0002124BE0E7C6D0BD3CFF1F572710";
	char * sql = "select * from transaction";
	MYSQL_RES *res_tx;
	select_sql(sql, &res_tx);
	MYSQL_ROW row_tx;
	char *msg = (char *)malloc(66+66+5);
	char compute_hash[65];

	unsigned char message[32];
	unsigned char pk[33];
	size_t pklen = 33;
	secp256k1_pubkey pubkey;
	secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
	secp256k1_ecdsa_signature signature;

	unsigned char data[64];
	/*need to validate hash and signature*/
	while(row_tx = mysql_fetch_row(res_tx)){
		/*validate hash*/
		{
			sprintf(msg, "%s%s%s", row_tx[1], row_tx[2], row_tx[3]);
			get_hash(msg, compute_hash);
			CHECK(memcmp(row_tx[0], compute_hash, sizeof(compute_hash)) == 0);
		}

		/*validate sig*/
		{
			from_hex(row_tx[0], 64, message);
			from_hex(hex_pk, 66, pk);
			CHECK(secp256k1_ec_pubkey_parse(ctx, &pubkey, pk, pklen) == 1);
			from_hex(row_tx[4], 128, data);
			memcpy(signature.data, data, 64);
			CHECK(secp256k1_ecdsa_verify(ctx, &signature, message, &pubkey) == 1);
		}
	}
}

void validate_single_block(int slot){
	/*char *sql = (char *)malloc(120);
	sprintf(sql, "select * from block where height = %d", slot);
	MYSQL_RES *res;
	MYSQL_ROW row;
	select_sql(sql, &res);
	int block_num = mysql_num_rows(res);
	if(!block_num){
		mysql_free_result(res);
		return;
	}

	row = mysql_fetch_row(res);


	mysql_free_result(res);
*/

	char *sql = (char *)malloc(1000);
	sprintf(sql, "select * from block where height = %d", slot);
	MYSQL_RES *res_blocks;
	MYSQL_ROW row;
	select_sql(sql, &res_blocks);
	int block_num = mysql_num_rows(res_blocks);
	if(!block_num){
		mysql_free_result(res_blocks);
		free(sql);
		return;
	}
	MYSQL_RES *res;

	//char *sql = (char *)malloc(1000);
	//sprintf(sql, "select * from block");
	//MYSQL_RES *res_blocks;

	//select_sql(sql, &res_blocks);
	
	char *nonce = "A6E3C57DD01ABE90086538398355DD4C3B17AA873382B0F24D6129493D8AAD60";
	char *difficulty = "000D1B71758E2196800000000000000000000000000000000000000000000000";
	char *msg = (char *)malloc(66+66+5+228114);
	int msglen;

	secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

	//insert_sql("update stxo set stxo = '()'");
	
	
	int rows = mysql_num_rows(res_blocks);
	int i = 0;
	//MYSQL_ROW block = mysql_fetch_row(res_blocks);
	
	int height;
	char prevhash[65];
	char vrf_pk[67];
	char vrf_hash[65];
	char vrf_proof[163];
	char merkle_root[MERKLE_ROOT_LEN + 1];
	char signature[149];
	char tx[TX_LEN + 1];
	char hash[65];
	char prev_prevhash[65];
	
	unsigned char pk[33], proof[81], output[32];		

	char *blk_hdr = (char *)malloc(1024);
	char hash_compute[65];
	
	secp256k1_ecdsa_signature ecdsa_signature;
	secp256k1_pubkey pubkey;
	unsigned char message[32];
	size_t pklen = 33;
	unsigned char data[64];

	MYSQL_RES *res_prev_block;
	//MYSQL_RES *res;
	MYSQL_RES *del_response;
	MYSQL_ROW del_resp_message;
	//MYSQL_ROW row;
	char *tx_bak = (char *)malloc(750);
	char root[65];
	char hex_pk[67];
	char hex_tx[10][65];
	char *delim = "\", ()";
	char *p;
	int j;

	char *del_resp_tx_msg = (char *)malloc(228114);

	printf("\n\n\nvalidating starts\n");
	struct timespec begin, end;
	MYSQL_ROW block;
	int is_edited = 0;
	clock_gettime(CLOCK_MONOTONIC, &begin);
	for(i=0; i<rows; i++){
		//从查询结果中提取数据
		block = mysql_fetch_row(res_blocks);
		if(block == NULL){
			printf("block is null\n");
		}
		printf("\n\n\nvalidating block in slot %s\n", block[0]);
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
			
			from_hex(vrf_pk, 66, pk);
			from_hex(vrf_hash, 64, output);
			from_hex(vrf_proof, 162, proof);
			CHECK(secp256k1_vrf_verify(output, proof, pk, msg, msglen) == 1);
			CHECK(strcmp(vrf_hash, difficulty)<0);

		}

		/*validate block hash*/
		{
			sprintf(blk_hdr, "%d%s%s%s%s%s", height, prevhash, vrf_pk, vrf_hash, vrf_proof, merkle_root);
			get_hash(blk_hdr, hash_compute);
			CHECK(memcmp(hash, hash_compute, 64) == 0);
		}

		/*validate signature*/
		{
			from_hex(hash, 64, message);
			from_hex(vrf_pk, 66, pk);
    		CHECK(secp256k1_ec_pubkey_parse(ctx, &pubkey, pk, pklen) == 1);
			
			from_hex(signature, 128, data);
			memcpy(ecdsa_signature.data, data, 64);
			CHECK(secp256k1_ecdsa_verify(ctx, &ecdsa_signature, message, &pubkey) == 1);

		}
		/*validate prevhash*/
		{
			sprintf(sql, "select * from block where hash = \"%s\"", prevhash);
			
			select_sql(sql, &res_prev_block);

			MYSQL_ROW prev_block = mysql_fetch_row(res_prev_block);
			sprintf(blk_hdr, "%s%s%s%s%s%s", prev_block[0], prev_block[1], prev_block[2], \
				prev_block[3], prev_block[4], prev_block[5]);
			get_hash(blk_hdr, hash_compute);
			
			CHECK(memcmp(prevhash, hash_compute, sizeof(prevhash)) == 0);

		}

		/*validate transaction
		* first, verify transaction hash
		*	
		* second, verify merkle_root
		* third, verify that transaction output has not been spent
		*	
		*/

		//verify merkle_root
		{
			memcpy(tx_bak, tx, strlen(tx));
			get_merkle_root(tx_bak, root);
			CHECK(memcmp(block[5], root, 64) == 0);
		}
		//verify tx hash and sig
		{
			sprintf(sql, "select * from transaction where tx_hash in (%s)", tx);
			select_sql(sql, &res);
			while(row = mysql_fetch_row(res)){
				sprintf(msg, "%s%s%s%s", row[1], row[2], row[3], row[6]);
				get_hash(msg, hash);
				CHECK(memcmp(hash, row[0], 64) == 0);
				
				if(memcmp(row[7], "3", 1) == 0){
					is_edited = 1;
					printf("\n\n\n\n\n\n\n\n\n\n");
					sprintf(del_resp_tx_msg, "%s", row[6]);
					//char *p;
					p = strchr(del_resp_tx_msg, '@');
					memcpy(msg, p+1, 64); //reuse the variable msg, as the txid to be deleted
					msg[64] = '\0';
					sprintf(sql, "select message from transaction where tx_hash = \"%s\"", msg);
					//mysql_free_result(res_blocks);
					select_sql(sql, &res_blocks);//res_blocks is unused, so use it
					MYSQL_ROW row_msg = mysql_fetch_row(res_blocks);
					char *q;
					q = strchr(row_msg[0], '@');
					q++;
					memcpy(msg, q, 64);
					msg[64] = '\0';
					p = strchr(++p, '@');
					++p;
					//printf("-.200%s\n", p);
					//deletion response@txid@(vrf msgs)
					//						 |->now p is pointing here	
					secp256k1_pubkey pubkey;
					secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
					size_t pklen = 33;
					unsigned char vrf_pk[33];
					unsigned char vrf_proof[81];
					unsigned char vrf_output[32];
					unsigned char seckey[32];

					char hex_pk[67];
					char hex_proof[163];
					char hex_output[65];

					int vrf_count = 667;
					char *sql_pks = (char *)malloc(667*76);
					sprintf(sql_pks, "select count(*) from stakeholder where pk in (");
					//pks[0] = '\0';
					while(vrf_count--){
						sscanf(p, "%[^,], %[^,], %[^,]", hex_output, hex_proof, hex_pk);
						
						//printf("%s\n%s\n%s\n%s\n", hex_output, hex_proof, hex_pk, msg);
						from_hex(hex_output, 64, vrf_output);
						from_hex(hex_proof, 162, vrf_proof);
						from_hex(hex_pk, 66, vrf_pk);
						CHECK(secp256k1_vrf_verify(vrf_output, vrf_proof, vrf_pk, msg, 64) == 1);
						sprintf(sql_pks, "%s\"%s\",", sql_pks, hex_pk);
						p = strchr(p, ',');
						p++;
						//printf("-.200%s\n", p);
						p = strchr(p, ',');
						p++;
						p = strchr(p, ',');
						p++;
					}
					sql_pks[strlen(sql_pks)-1] = ')';
					printf("check vrf_pks is in stakeholder list\n");
					select_sql(sql_pks, &del_response);//reuse the variable del_response
					del_resp_message = mysql_fetch_row(del_response);
					CHECK(memcmp(del_resp_message[0], "667", 3) == 0);
					
					sprintf(sql_pks, "update transaction set is_deleted = 1, message = message where tx_hash = \"%s\"", msg); //reuse of msg

					mysql_free_result(del_response);
					free(sql_pks);
					memcpy(hash, row[0], 64);

				}
				if(strlen(row[1]) == 66){
					from_hex(row[1], 66, pk);
				}else{
					get_tx_pk(row[1], hex_pk);//ref_tx
					from_hex(hex_pk, 66, pk);
				}
				from_hex(hash, 64, message);
				CHECK(secp256k1_ec_pubkey_parse(ctx, &pubkey, pk, pklen) == 1);
			
				from_hex(row[4], 128, data);
				memcpy(ecdsa_signature.data, data, 64);
				CHECK(secp256k1_ecdsa_verify(ctx, &ecdsa_signature, message, &pubkey) == 1);
			}
		}
		//verify there is no stxo according to the field tx
		{
			memcpy(tx_bak, tx, strlen(tx));
			p = strtok(tx_bak, delim);
			memcpy(hex_tx[0], p, 64);
			j = 0;
			while(p = strtok(NULL, delim))
				memcpy(hex_tx[++j], p, 64);
			qsort(hex_tx, 10, sizeof(char)*65, compare);
			for(j=0; j < 9; j++){
				CHECK(memcmp(hex_tx[j], hex_tx[j+1], 64) != 0);
			}
			sprintf(sql, "select count(stxo) from stxo where stxo like '%%%-.64s%%'", hex_tx[0]);
			for(j=1; j<10; sprintf(sql, "%s or stxo like '%%%-.64s%%'", sql, hex_tx[j++]));
			select_sql(sql, &res);
			row = mysql_fetch_row(res);
			CHECK(memcmp(row[0], "0", 1) == 0);
			sprintf(sql, "update stxo set stxo = concat(stxo, '%s')", tx);
			printf("mark tx in this block as spent tx\n");
			insert_sql(sql);

		}
	}
	clock_gettime(CLOCK_MONOTONIC, &end);
	
	double validate_time = (double) (end.tv_nsec - begin.tv_nsec)/1000000000 + end.tv_sec - begin.tv_sec;
	printf("validate a block using time: %.9lf\n", validate_time);
	fprintf(fp, "%d,%.9lf,%d\n", slot, validate_time, is_edited);
	free(msg);
	free(blk_hdr);
	free(sql);
	free(tx_bak);
	mysql_free_result(res_blocks);
	mysql_free_result(res);
	mysql_free_result(res_prev_block);

	printf("validation success\n");

}


int main(int argc, char **argv){
	
	//generate_stakeholder();
	/*char *sql = "truncate table block";
	insert_sql(sql);

	*/

	//generate_genblk();
	// generate_utxo();
	if(argc != 3){
		printf("need 2 params. 1:file name num, 2:INTERVAL\n");
		exit(1);
	}
	conn = mysql_init(NULL);

	conn = mysql_real_connect(conn, HOST, USERNAME, PASSWORD, DATABASE, 0, NULL, 0);
	if(!conn){
		printf("insert_sql: Connection failed\n%s\n", mysql_error(conn));
		exit(1);
	}

	int start, finish, start_time, finish_time;
	insert_sql("update stxo set stxo = '()'");
	start_time = time(NULL);
	char *file_name = (char *)malloc(20);
	sprintf(file_name, "data%s.csv", argv[1]);
	INTERVAL = atoi(argv[2]);
	fp = fopen(file_name, "a+");
	fprintf(fp, "slot,validate time,is_edited\n");
	for(int i=1; i<700; i++){
		//printf("%dth slot leader_election\n", i);
		
		start = time(NULL);
		leader_election(i);
		finish = time(NULL);
		printf("using time: %dseconds\n",(finish - start));
		validate_single_block(i);
	}
	validate_blockchain();
	fclose(fp);
	finish_time = time(NULL);
	printf("total time:%d\n",(finish_time - start_time));
	mysql_close(conn);
	return 0;

}
