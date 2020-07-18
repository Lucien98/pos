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
		//return EXIT_FAILURE;	
	}	
	conn = mysql_real_connect(conn,HOST,USERNAME,PASSWORD,DATABASE,0,NULL,0);
	if(conn)
		printf("Connection success\n");	
	else	
		printf("Connection failed\n");
	int res;
	res = mysql_query(conn, sql);
	if(res){
		printf("插入数据失败\n");
		mysql_close(conn);
	}else{
		my_ulonglong affected_row = mysql_affected_rows(conn);
		printf("%d rows affected.\n", (int)affected_row);
	}
}

/*int main(){
	char *sql = "INSERT INTO `block` VALUES ('1', 'prehash', 'vrf_pk', 'vrf_hash', 'vrf_proof', 'merkle_root', 'signatue', 'tx', 'hash')";
	insert_sql(sql);
	return 0;
}*/