all: release test

release: main.o verify.o
	g++ main.o verify.o -lcrypto -o capbac

debug: main.o verify.debug.o
	g++ main.o verify.debug.o -lcrypto -o capbac

test: test.cc
	g++ test.cc -o test

main.o: main.cc
	g++ -c main.cc

verify.o: verify.cc
	g++ -c verify.cc

verify.debug.o: verify.cc
	g++ -c -DDEBUG verify.cc -o verify.debug.o

clean:
	rm -f *.o test capbac
