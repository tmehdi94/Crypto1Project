/**
	@file atm.cpp
	@brief Top level ATM implementation file
 */
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <iostream>
#include <vector>

int main(int argc, char* argv[])
{
	if(argc != 2)
	{
		printf("Usage: atm proxy-port\n");
		return -1;
	}
	
	//socket setup
	unsigned short proxport = atoi(argv[1]);
	int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if(!sock)
	{
		printf("fail to create socket\n");
		return -1;
	}
	sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(proxport);
	unsigned char* ipaddr = reinterpret_cast<unsigned char*>(&addr.sin_addr);
	ipaddr[0] = 127;
	ipaddr[1] = 0;
	ipaddr[2] = 0;
	ipaddr[3] = 1;
	if(0 != connect(sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)))
	{
		printf("fail to connect to proxy\n");
		return -1;
	}

	//bool loggedIn = false;
	//input loop
	char buf[80];
	while(1)
	{
		bzero(buf, strlen(buf));

		printf("atm> ");
		fgets(buf, 79, stdin);
		buf[strlen(buf)-1] = '\0';	//trim off trailing newline
		std::vector<std::string> commands;
		char hold[strlen(buf)];
		strcpy(hold,buf);
		char* token = strtok(hold," ");
		int i = 0;
		while(token != NULL){
			
			commands.push_back(std::string(token));
			i++;
			token = strtok(NULL," ");
		}
		//TODO: your input parsing code has to put data here
		char packet[1024];
		bzero(packet,strlen(packet));
		int length = 1;
		
		//input parsing
		bool pass = true;
		if(!strcmp(buf, "logout")){
			break;
		}
		else if(commands[0] == "login"){
			if(commands.size() != 2){
				std::cout << "Not valid input" << std::endl;
				pass = false;
			}
			char pin[5];
			bzero(pin, strlen(pin));
			std::cout << "Enter PIN: ";
			fgets(pin, 5, stdin);
			pin[strlen(pin)] = '\0';
			//int n = send(sock, pin, 5, 0);
			//std::cout << n;
			//send(sock, (void*)pin, strlen(pin), 0);
			//confirmation and authentication.
			//if good, loggedIn = true;
		}
		else if(commands[0] == "balance"){

		}
		else if(commands[0] == "withdraw"){
			if(commands.size() != 2){
				std::cout << "Not valid input" << std::endl;
				pass = false;
			}


		}
		else if(commands[0] == "transfer"){
			if(commands.size() != 3){
				std::cout << "Not valid input" << std::endl;
				pass = false;
			}

		}
		else{
			std::cout << "Not valid input" << std::endl;
			pass = false;
		}
		//TODO: other commands
		strcpy(packet, buf);
		length = strlen(buf);

		//send the packet through the proxy to the bank

		if(pass){// && loggedIn){//if no error in input
			//encrypt and pad packet. 

			if(sizeof(int) != send(sock, &length, sizeof(int), 0))
			{
				printf("fail to send packet length\n");
				break;
			}
			if(length != send(sock, (void*)packet, length, 0))
			{
				printf("fail to send packet\n");
				break;
			}
			
		}
		length = 0;
		//TODO: do something with response packet
		if(sizeof(int) != recv(sock, &length, sizeof(int), 0))
		{
			std::cout << length;
			printf("fail to read packet length\n");
			break;
		}
		if(length >= 1024)
		{
			printf("packet too long\n");
			break;
		}
		if(length != recv(sock, packet, length, 0))
		{
			printf("fail to read packet\n");
			break;
		}

		//decrypt and authenticate packet
		std::cout << packet << std::endl;


	}
	
	//cleanup
	close(sock);
	return 0;
}
