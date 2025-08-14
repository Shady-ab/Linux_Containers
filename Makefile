decrypter: decrypter.c mta_crypt.c mta_rand.c
	$(CC) -o decrypter decrypter.c mta_crypt.c mta_rand.c -lpthread -lssl -lcrypto

