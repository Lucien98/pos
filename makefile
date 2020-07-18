pos_simu: pos.o util_pos.o util_mysql.o
	gcc -o pos_simu pos.o util_pos.o util_mysql.o \
	-I /usr/include/mysql -L/usr/lib/mysql -lmysqlclient -lsecp256k1-vrf 

pos.o: pos.c
	gcc -c pos.c

util_pos.o: util_pos.c util_pos.h
	gcc -c util_pos.c

util_mysql.o: util_mysql.c util_mysql.h
	gcc -c util_mysql.c -I /usr/include/mysql -L/usr/lib/mysql -lmysqlclient

clean: 
	rm pos_simu pos.o util_mysql.o util_pos.o 