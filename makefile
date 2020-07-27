pos_simu: pos.o util_pos.o util_mysql.o
	gcc -g -o pos_simu pos.o util_pos.o util_mysql.o \
	-I /usr/include/mysql -L/usr/lib/mysql -lmysqlclient -lsecp256k1-vrf -lMerkleTree 

pos.o: pos.c
	gcc -g -c pos.c -I /usr/include/mysql -L/usr/lib/mysql -lmysqlclient

util_pos.o: util_pos.c util_pos.h
	gcc -g -c util_pos.c -lMerkleTree 

util_mysql.o: util_mysql.c util_mysql.h
	gcc -g -c util_mysql.c -I /usr/include/mysql -L/usr/lib/mysql -lmysqlclient

clean: 
	rm pos_simu pos.o util_mysql.o util_pos.o 
