
all: x509 pkcs7 rsa x509_debug pkcs7_debug rsa_debug x509_klee_debug pkcs7_klee_debug rsa_klee_debug 

X509_SRC=misc.c oid_registry.c asn1_decoder.c x509-asn1.c x509_rsakey-asn1.c x509_cert_parser.c x509_main.c 
PKCS7_SRC=misc.c oid_registry.c asn1_decoder.c pkcs7-asn1.c pkcs7_parser.c x509_cert_parser.c x509-asn1.c x509_rsakey-asn1.c pkcs7_main.c
RSA_SRC=misc.c oid_registry.c asn1_decoder.c rsapubkey-asn1.c rsaprivkey-asn1.c rsa_helper.c rsa_main.c

x509:
	$(CC) $(CFLAGS) $(X509_SRC) -o x509

x509_debug:
	$(CC) -g -O0 -DDEBUG $(CFLAGS) $(X509_SRC) -o x509_debug

x509_klee_debug:
	$(CC) -g -O0 -DDEBUG -DKLEE_DEBUG $(CFLAGS) $(X509_SRC) -o x509_klee_debug

x509_klee:
	cat $(X509_SRC) > x509_klee.c
	clang -I klee_src/include/ -DKLEE -emit-llvm -g -c -O0 -Xclang -disable-O0-optnone x509_klee.c -o x509_klee.bc

x509_test:
	$(CC) -g -O0 -DDEBUG $(CFLAGS) x509_test.c -o x509_test

pkcs7:
	$(CC) $(CFLAGS) $(PKCS7_SRC) -o pkcs7

pkcs7_debug:
	$(CC) -g -O0 -DDEBUG $(CFLAGS) $(PKCS7_SRC) -o pkcs7_debug

pkcs7_klee_debug:
	$(CC) -g -O0 -DDEBUG -DKLEE_DEBUG $(CFLAGS) $(PKCS7_SRC) -o pkcs7_klee_debug

pkcs7_klee:
	cat $(PKCS7_SRC) > pkcs7_klee.c
	clang -I klee_src/include/ -DKLEE -emit-llvm -g -c -O0 -Xclang -disable-O0-optnone pkcs7_klee.c -o pkcs7_klee.bc

pkcs7_test:
	$(CC) -g -O0 -DDEBUG $(CFLAGS) pkcs7_test.c -o pkcs7_test

rsa:
	$(CC) $(CFLAGS) $(RSA_SRC) -o rsa_pub -DRSA_PUB_KEY
	$(CC) $(CFLAGS) $(RSA_SRC) -o rsa_priv

rsa_debug:
	$(CC) -g -O0 -DDEBUG $(CFLAGS) $(RSA_SRC) -o rsa_pub_debug -DRSA_PUB_KEY
	$(CC) -g -O0 -DDEBUG $(CFLAGS) $(RSA_SRC) -o rsa_priv_debug

rsa_klee_debug:
	$(CC) -g -O0 -DDEBUG -DKLEE_DEBUG $(CFLAGS) $(RSA_SRC) -o rsa_pub_klee_debug -DRSA_PUB_KEY
	$(CC) -g -O0 -DDEBUG -DKLEE_DEBUG $(CFLAGS) $(RSA_SRC) -o rsa_priv_klee_debug

rsa_klee:
	cat $(RSA_SRC) > rsa_klee.c
	clang -I klee_src/include/ -DKLEE -emit-llvm -g -c -O0 -Xclang -disable-O0-optnone rsa_klee.c -o rsa_klee_pub.bc -DRSA_PUB_KEY
	clang -I klee_src/include/ -DKLEE -emit-llvm -g -c -O0 -Xclang -disable-O0-optnone rsa_klee.c -o rsa_klee_priv.bc

clean:
	rm -f *.o *.bc
	rm -f x509 x509_debug x509_klee_debug x509_test x509_klee.c
	rm -f pkcs7 pkcs7_debug pkcs7_klee_debug pkcs7_test pkcs7_klee.c
	rm -f rsa_klee.c rsa_klee_priv.c rsa_pub rsa_priv rsa_pub_debug rsa_priv_debug rsa_pub_klee_debug rsa_priv_klee_debug

.PHONY: x509 x509_debug x509_klee x509_klee_debug pkcs7 pkcs7_debug pkcs7_klee pkcs7_klee_debug rsa rsa_debug rsa_klee rsa_klee_debug
