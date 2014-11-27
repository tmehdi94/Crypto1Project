all:
	g++ atm.cpp -lcryptopp -static -L./cryptopp -o atm
	g++ bank.cpp -lcryptopp -static -L./cryptopp -o bank -lpthread
	g++ proxy.cpp -m32 -o proxy -lpthread

clean:
	rm atm bank proxy
