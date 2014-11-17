/**
	@file bank.cpp
	@brief Top level bank implementation file
 */
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>
#include <string.h>


void* client_thread(void* arg);
void* console_thread(void* arg);

class Account{
	std::string name;
	int balance;
	const int pin;
	// mutex so multiple cant access account at same time??
  public:
  	Account(std::string, int, int);
  	/*Account & operator= (const Account & a){
  		if (this != a){
            
        }
        return *this;
  	}*/
};

Account::Account(std string::n, int m, int p){
	balance = m;
	name = n;
	pin = p;
}



std::vector<Account> Accounts;


int main(int argc, char* argv[])
{
	//Account a("Alice", 100, );
	//Account b("Bob", 50, );
	//Account e("Eve", 0 , );
	//Account.push_back(a);
	//Account.push_back(b);
	//Account.push_back(e);

	if(argc != 2)
	{
		printf("Usage: bank listen-port\n");
		return -1;
	}
	
	unsigned short ourport = atoi(argv[1]);
	
	//socket setup
	int lsock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if(!lsock)
	{
		printf("fail to create socket\n");
		return -1;
	}
	
	//listening address
	sockaddr_in addr_l;
	addr_l.sin_family = AF_INET;
	addr_l.sin_port = htons(ourport);
	unsigned char* ipaddr = reinterpret_cast<unsigned char*>(&addr_l.sin_addr);
	ipaddr[0] = 127;
	ipaddr[1] = 0;
	ipaddr[2] = 0;
	ipaddr[3] = 1;
	if(0 != bind(lsock, reinterpret_cast<sockaddr*>(&addr_l), sizeof(addr_l)))
	{
		printf("failed to bind socket\n");
		return -1;
	}
	if(0 != listen(lsock, SOMAXCONN))
	{
		printf("failed to listen on socket\n");
		return -1;
	}
	
	pthread_t cthread;
	pthread_create(&cthread, NULL, console_thread, NULL);
	
	//loop forever accepting new connections
	while(1)
	{
		sockaddr_in unused;
		socklen_t size = sizeof(unused);
		int csock = accept(lsock, reinterpret_cast<sockaddr*>(&unused), &size);
		if(csock < 0)	//bad client, skip it
			continue;
			
		pthread_t thread;
		pthread_create(&thread, NULL, client_thread, (void*)csock);
	}
}

void* client_thread(void* arg)
{
	int csock = (int)arg;
	
	printf("[bank] client ID #%d connected\n", csock);
	
	//input loop
	int length;
	char packet[1024];
	Account current;
	while(1)
	{
		//read the packet from the ATM
		if(sizeof(int) != recv(csock, &length, sizeof(int), 0))
			break;
		if(length >= 1024)
		{
			printf("packet too long\n");
			break;
		}
		if(length != recv(csock, packet, length, 0))
		{
			printf("[bank] fail to read packet\n");
			break;
		}
		
		//TODO: process packet data

		//decrypt and authenticate
		//store in buffer after decryption


		std::vector<std::string> commands;
		std::string hold = buffer;
		std:string token = strtok(hold," ");
		int i = 0;
		while(token != NULL){
			commands[i] = token;
			i++;
			token = strtok(NULL," ");
		}

		if(commands[0] == "login"){
			for(int i = 0; i < Accounts.size(); i++){
				if(commands[1] == Accounts[i].name){
					char pin[20];
					//read for pin
					if(atoi(pin) == Accounts[i].pin){
						//write that logged in;
						current = &Accounts[i];
						break;
					}
				}
			}
			if(current == NULL){
				//login and pin dont match
			}

		}
		else if(commands[0] == "balance"){
			buffer = current.balance;
		}
		else if(commands[0] == "withdraw"){
			//lock mutex
			if(current.balance > commands[1]){
				current.balance -= commands[1];
				//set buffer
			}
			else{
				//not enough money 
			}
			//unlock mutex
		}
		else if(commands[0] == "transfer"){
			//lock mutex
			if(current.balance > commands[1]){
				int i;
				for(i = 0; i < Accounts.size(); i++){
					if(Accounts[i].name == commands[2]){
						current.balance -= commands[1];
						Accounts[i].balance += commands[1];
						//confirm transfer
						break;
					}
				}
				if(i == Accounts.size()){
					//user account not found;
				}
			}
			//unlock mutex
		}
		

		//encrypt
		//TODO: put new data in packet
		
		//send the new packet back to the client
		if(sizeof(int) != send(csock, &length, sizeof(int), 0))
		{
			printf("[bank] fail to send packet length\n");
			break;
		}
		if(length != send(csock, (void*)packet, length, 0))
		{
			printf("[bank] fail to send packet\n");
			break;
		}

	}

	printf("[bank] client ID #%d disconnected\n", csock);

	close(csock);
	return NULL;
}

void* console_thread(void* arg)
{
	char buf[80];
	while(1)
	{
		printf("bank> ");
		fgets(buf, 79, stdin);
		buf[strlen(buf)-1] = '\0';	//trim off trailing newline
		
		//TODO: your input parsing code has to go here
		std::vector<std::string> commands;
		std::string hold = buf;
		std:string token = strtok(hold," ");
		int i = 0;
		while(token != NULL){
			commands[i] = token;
			i++;
			token = strtok(NULL," ");
		}


		if(commands[0] == "deposit"){
			int i;
			for(i = 0; i < Accounts.size(); i++){
				if(Accounts[i].name == commands[1]){
					//lock mutex
					Accounts[i].balance += commands[2];
					break;
				}
			}
			if(i == Accounts.size()){
				//account not found
			}
		}
		else if(commands[0] == "balance"){
			int i;
			for(i = 0; i < Accounts.size(); i++){
				if(Accounts[i].name == commands[1]){
					//print account balance
				}
			}
		}
		else{
			//not valid;
		}
	}
}
