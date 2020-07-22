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

#define HOST "192.168.148.1"
#define USERNAME "root"
#define PASSWORD "root"
#define DATABASE "pos"

/*执行sql插入语句*/
void insert_sql(char *sql){
	MYSQL *conn;	
	conn = mysql_init(NULL);
	
	if(!conn){
		fprintf(stderr,"mysql_init failed\n");
		exit(1);	
	}	
	conn = mysql_real_connect(conn, HOST, USERNAME, PASSWORD, DATABASE, 0, NULL, 0);
	if(conn)
		printf("insert_sql: Connection success\n");	
	else	
		printf("insert_sql: Connection failed\n");
	int res;
	res = mysql_query(conn, sql);
	if(res){
		printf("插入数据失败\n%s\n", mysql_error(conn));
		mysql_close(conn);
		getchar();
		system("read");
		//exit(1);
	}else{
		my_ulonglong affected_row = mysql_affected_rows(conn);
		printf("%d rows affected.\n", (int)affected_row);
	}
}

/*对传入的res_ptr指针进行修改，使之记录结果*/
void select_sql(char *sql, MYSQL_RES **res_ptr){
	MYSQL *conn = mysql_init(NULL);//初始化一个mysql连接的对象
	//conn = mysql_init(NULL);
	int res;

	if(!conn)
		printf("select_sql: mysql_init failed\n");
	conn = mysql_real_connect(conn, HOST, USERNAME, PASSWORD, DATABASE, 0, NULL, 0);
	if(conn)
		printf("query_sql: Connection success\n");
	else
		printf("query_sql: Connection failed\n");
	res = mysql_query(conn, sql);
	if(res){
		printf("查询失败\n%s\n", mysql_error(conn));
		mysql_close(conn);
		exit(1);
	}	
	//MYSQL_RES *result = mysql_store_result(conn);
	*res_ptr = mysql_store_result(conn);

	mysql_close(conn);
}


void get_stkhld_sk(char *pk, char *sk){
	MYSQL *conn = mysql_init(NULL);
	conn = mysql_real_connect(conn, HOST, USERNAME, PASSWORD, DATABASE, 0, NULL, 0);
	if(conn) printf("get_stkhld_sk:Connection success\n");
	else printf("get_stkhld_sk:Connection failed\n");
	char *sql = (char *)malloc(10240);
	sprintf(sql, "select sk from stakeholder where pk = \"%s\"", pk);
	int res = mysql_query(conn, sql);
	if(res){
		printf("查询失败\n%s\n", mysql_error(conn));
		mysql_close(conn);
		exit(1);
	}
	MYSQL_RES *res_ptr = mysql_store_result(conn);
	MYSQL_ROW row = mysql_fetch_row(res_ptr);
	mysql_free_result(res_ptr);
	//if(row==NULL) {printf("row is null\n");exit(1);}
	sprintf(sk, "%s", row[0]);
	free(sql);
	mysql_close(conn);

}

/*int main(){
	char *sql = "INSERT INTO `block` VALUES ('1', 'prehash', 'vrf_pk', 'vrf_hash', 'vrf_proof', 'merkle_root', 'signatue', 'tx', 'hash')";
	insert_sql(sql);
	return 0;
}*/