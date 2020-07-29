/*
测试:
gcc util_mysql.c -I /usr/include/mysql -L/usr/lib/mysql -lmysqlclient -o util_mysql
sudo ./util_mysql
生成静态库:
gcc -c util_mysql.c -I /usr/include/mysql -L/usr/lib/mysql -lmysqlclient
ar -crv libutil_mysql.a util_mysql.o
*/
 
#include <stdlib.h>  
#include <stdio.h>  
#include "mysql.h"
#include "util_mysql.h"

//#define HOST "192.168.148.1"
#define HOST "127.0.0.1"
#define USERNAME "root"
#define PASSWORD ""
#define DATABASE "pos"

/*	exec the sql statements that do not involve with a result set 
	such as insert, delele, update, truncate
*/
void insert_sql(char *sql){
	MYSQL *conn;	
	conn = mysql_init(NULL);
	
	conn = mysql_real_connect(conn, HOST, USERNAME, PASSWORD, DATABASE, 0, NULL, 0);
	if(!conn){
		printf("insert_sql: Connection failed\n%s\n", mysql_error(conn));
		exit(1);
	}
	int res;
	res = mysql_query(conn, sql);
	if(res){
		printf("failure in insert＿sql function\n%s\n%s\n", mysql_error(conn),sql);
		mysql_close(conn);
		getchar();
		system("read");
	}else{
		my_ulonglong affected_row = mysql_affected_rows(conn);
		printf("%d rows affected.\n", (int)affected_row);
		mysql_close(conn);
	}
}

/*exec select statement in sql, modifies the result pointer */
void select_sql(char *sql, MYSQL_RES **res_ptr){
	MYSQL *conn = mysql_init(NULL);
	int res;

	conn = mysql_real_connect(conn, HOST, USERNAME, PASSWORD, DATABASE, 0, NULL, 0);
	if(!conn){
		printf("query_sql: Connection failed\n%s\n", mysql_error(conn));
		exit(1);
	}
	
	res = mysql_query(conn, sql);
	if(res){
		printf("\nselect query failed\n%s\n\n", mysql_error(conn));
		getchar();
		mysql_close(conn);
		exit(1);
	}	
	*res_ptr = mysql_store_result(conn);

	mysql_close(conn);
}


void get_stkhld_sk(char *pk, char *sk){
	MYSQL *conn = mysql_init(NULL);
	conn = mysql_real_connect(conn, HOST, USERNAME, PASSWORD, DATABASE, 0, NULL, 0);
	if(!conn) {
		printf("get_stkhld_sk:Connection failed\n%s\n", mysql_error(conn));
		getchar();
		exit(1);
	}
	char *sql = (char *)malloc(200);
	sprintf(sql, "select sk from stakeholder where pk = \"%s\"", pk);
	int res = mysql_query(conn, sql);
	if(res){
		printf("get stakeholder sk failed\n%s\n", mysql_error(conn));
		mysql_close(conn);
		exit(1);
	}
	MYSQL_RES *res_ptr = mysql_store_result(conn);
	MYSQL_ROW row = mysql_fetch_row(res_ptr);
	mysql_free_result(res_ptr);
	sprintf(sk, "%s", row[0]);
	free(sql);
	mysql_close(conn);

}

void get_tx_pk(char *tx_hash, char *pk){
	MYSQL *conn = mysql_init(NULL);
	conn = mysql_real_connect(conn, HOST, USERNAME, PASSWORD, DATABASE, 0, NULL, 0);
	if(!conn){ 
		printf("get_tx_pk:Connection success\n%s\n", mysql_error(conn));
		exit(1);
	}
	char *sql = (char *)malloc(200);
	sprintf(sql, "select receiver_pk from transaction where tx_hash = \"%s\"", tx_hash);
	int res = mysql_query(conn, sql);
	if(res){
		printf("get_tx_pk failed\n%s\n", mysql_error(conn));
		mysql_close(conn);
		exit(1);
	}
	MYSQL_RES *res_ptr = mysql_store_result(conn);
	MYSQL_ROW row = mysql_fetch_row(res_ptr);
	mysql_free_result(res_ptr);
	sprintf(pk, "%s", row[0]);
	free(sql);
	mysql_close(conn);

}
