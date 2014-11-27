/**
	@file atm.cpp
	@brief Top level ATM implementation file
 */
#include <unistd.h>
#include <termios.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <iostream>
#include <fstream>
#include <vector>
#include "crypto++/modes.h"
#include "crypto++/aes.h"
#include "crypto++/filters.h"
#include "crypto++/integer.h"
#include "crypto++/rsa.h"
#include "crypto++/osrng.h"
#include "crypto++/sha.h"
#include "crypto++/hex.h"

#include "account.h"

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
    const std::string appSalt = "THISISAFUCKINGDOPESALT";
	char buf[80];
	char packet[1024];
    std::string accountHash;
	std::vector<std::string> commands;
	while(1)
	{
		bzero(buf, strlen(buf));
		bzero(packet,strlen(packet));
		commands.clear();

		printf("atm> ");
		fgets(buf, 79, stdin);
		buf[strlen(buf)-1] = '\0';	//trim off trailing newline
		
		char hold[strlen(buf)];
		strcpy(hold,buf);
		char* token = strtok(hold," ");
		int i = 0;
		while(token != NULL)
        {
			commands.push_back(std::string(token));
			i++;
			token = strtok(NULL," ");
		}
		//TODO: your input parsing code has to put data here
		
		int length = 1;
		
        if (commands.size() != 0)
        {
            //input parsing
            bool pass = true;
            if(!strcmp(buf, "logout"))
            {
                break;
            }
            else if(commands[0] == "login") // and not loggedIn
            {
                if(commands.size() != 2)
                {
                    std::cout << "Not valid input for login" << std::endl;
                    pass = false;
                }
                else
                {
                    std::string username = commands[1];
                    /*
                    char pin[10];
                    std::cout << "Enter PIN: ";
                    fgets(pin, 9, stdin);
                    pin[strlen(pin) - 1] = '\0';
                    strcat(buf, " ");
                    strcat(buf, pin);
                    */

                    std::ifstream cardFile(("cards/" + username + ".card").c_str());
                    if(cardFile) {
                        //atmSession.handshake(sock);
                        //if(atmSession.state != 2) {
                        //    cout << "Unexpected error.\n";
                        //    break;
                        //}
                        //sendPacket = 1; // Send packet because valid command

                        //obtain card hash
                        std::string cardHash;
                        cardFile >> cardHash;
                        cardHash = cardHash.substr(0,128);
                        
                        //this block prompts for PIN for login and puts it in the pin var
                        std::string pin;
                        pin = getpass("PIN: ", true);
                       
                        //Now we'll figure out the hash that we need to send
                        accountHash = createHash(cardHash + appSalt + pin);
                        
                        // send account hash to bank to verify.

                        //if good, loggedIn = true;
                    }
                    else {
                        std::cout << "ATM Card not found" << std::endl;
                    }
                }
            }
            else if(commands[0] == "balance")
            {
                if(commands.size() != 1)
                {
                    std::cout << "Not valid input for balance" << std::endl;
                    pass = false;
                }
            }
            else if(commands[0] == "withdraw")
            {
                if(commands.size() != 2)
                {
                    std::cout << "Not valid input for withdraw" << std::endl;
                    pass = false;
                }
            }
            else if(commands[0] == "transfer")
            {
                if(commands.size() != 3)
                {
                    std::cout << "Not valid input transfer" << std::endl;
                    pass = false;
                }
            }
            else
            {
                std::cout << "Unknown input" << std::endl;
                pass = false;
            }
            //TODO: other commands
            //strcpy(packet, buf);
            //length = strlen(buf);

            //send the packet through the proxy to the bank

            if(pass)// && loggedIn)
            {
                //if no error in input encrypt and pad packet.
                std::string ciphertext = createPacket(std::string(buf), accountHash);
                std::cout << ciphertext.size() << std::endl;
                strcpy(packet, ciphertext.data());
                length = strlen(packet);

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

                length = 1;
                bzero(packet, strlen(packet));
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
        }
        else
        {
            std::cout << std::endl;
        }
    }
	
	//cleanup
	close(sock);
	return 0;
}
