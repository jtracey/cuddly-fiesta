all: release test

release: verify client auth

debug: main.o verify.debug.o base64.o b64lib.o
	g++ main.o verify.debug.o base64.o cencode.o cdecode.o -lcrypto -o capbac

verify: main.o verify.o base64.o b64lib.o
	g++ main.o verify.o base64.o cencode.o cdecode.o -lcrypto -o capbac

client: client.o base64.o b64lib.o
	g++ client.o base64.o cencode.o cdecode.o -lcrypto -o client

auth: auth.o base64.o b64lib.o
	g++ auth.o base64.o cencode.o cdecode.o -lcrypto -o auth

test: test.cc base64.o b64lib.o
	g++ test.cc base64.o cencode.o cdecode.o -lcrypto -o test

main.o: main.cc
	g++ -c main.cc -o main.o

verify.o: verify.cc
	g++ -std=c++11 -c verify.cc -o verify.o

verify.debug.o: verify.cc
	g++ -std=c++11 -c -DDEBUG verify.cc -o verify.debug.o

client.o: subject.cpp
	g++ -std=c++11 -c subject.cpp -o client.o

auth.o: issuer_new.cpp
	g++ -std=c++11 -c issuer_new.cpp -o auth.o

base64.o: base64.cc
	g++ -c base64.cc -o base64.o

b64lib.o: cencode.c cencode.c
	g++ -c cencode.c cdecode.c

clean:
	rm -f *.o test capbac
