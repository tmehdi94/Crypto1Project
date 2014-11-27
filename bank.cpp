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
#include <limits.h>
#include <iostream>
#include <vector>
#include <sstream>
#include "crypto++/modes.h"
#include "crypto++/aes.h"
#include "crypto++/filters.h"
#include "crypto++/integer.h"
#include "crypto++/rsa.h"
#include "crypto++/osrng.h"
#include "crypto++/sha.h"
#include "crypto++/hex.h"

#include "account.h"

void* client_thread(void* arg);
void* console_thread(void* arg);



std::string randomString(const unsigned int len) {

    static const char alphanum[] =
        "0123456789"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz";
        
    std::string s = "";
    
    //When adding each letter, generate a new word32,
    //then compute it modulo alphanum's size - 1
    
    for(unsigned int i = 0; i < len; ++i) {
        s += alphanum[rand() % (sizeof(alphanum) - 1)];
    } 
    return s;
}

void padCommand(std::string &command){
    
    // pad end of packet with '~' then 'a's to separate command
    // from string for parsing
    
    //if (command.size() < 460){ //1022 because buildPacket() has two '\0's
    if (command.size() < 1007){
        command += "~";
    }
    while(command.size() < 1007){
        command += "a";
    }
}

void unpadCommand(std::string &plaintext) {
    // find index of ~ and truncate string
    bool positionFound = false;
    int position = -1;
    for(unsigned int i = 0; i < plaintext.size(); ++i) {
        if(plaintext[i] == '~') {
            positionFound = true;
            position = i;
            break;
        }
    }

    if(position > 0 && positionFound) {
        plaintext = plaintext.substr(0,position);
    }
    else {
        // that was some bad input
    }
    return;
}

void encryptCommand(std::string& ciphertext, std::string& command, byte* key, byte* iv) {
    CryptoPP::AES::Encryption aesEncryption(key, CryptoPP::AES::DEFAULT_KEYLENGTH);
    CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEncryption( aesEncryption, iv );

    CryptoPP::StreamTransformationFilter stfEncryptor(cbcEncryption, new CryptoPP::StringSink( ciphertext ) );
    stfEncryptor.Put( reinterpret_cast<const unsigned char*>( command.c_str() ), command.length() + 1 );
    stfEncryptor.MessageEnd();
}

void decryptCommand(std::string& decipher, std::string& command, byte* key, byte* iv) {
    CryptoPP::AES::Decryption aesDecryption(key, CryptoPP::AES::DEFAULT_KEYLENGTH);
    CryptoPP::CBC_Mode_ExternalCipher::Decryption cbcDecryption( aesDecryption, iv );

    CryptoPP::StreamTransformationFilter stfDecryptor(cbcDecryption, new CryptoPP::StringSink( decipher ) );
    stfDecryptor.Put( reinterpret_cast<const unsigned char*>( command.c_str() ), command.size() );
    stfDecryptor.MessageEnd();
}

std::string createHash(const std::string& input) {
    CryptoPP::SHA512 hash;
    byte digest[ CryptoPP::SHA512::DIGESTSIZE ];
    //input.resize(CryptoPP::SHA512::DIGESTSIZE);
    hash.CalculateDigest( digest, (byte*) input.c_str(), input.length() );
    CryptoPP::HexEncoder encoder;
    std::string output;
    encoder.Attach( new CryptoPP::StringSink( output ) );
    encoder.Put( digest, sizeof(digest) );
    encoder.MessageEnd();
    return output;
}

void decryptPacket(char* packet){
    //printf("%s\n", packet);
    std::string ciphertext = std::string(packet), plaintext;
    std::cout << ciphertext.size();
    byte key[ CryptoPP::AES::DEFAULT_KEYLENGTH ], iv[ CryptoPP::AES::BLOCKSIZE ];
    memset( key, 0x00, CryptoPP::AES::DEFAULT_KEYLENGTH );
    memset( iv, 0x00, CryptoPP::AES::BLOCKSIZE );
    decryptCommand(plaintext, ciphertext, key, iv);
    std::cout << plaintext;
}


//Perhaps we should write this to a file so a power out attack cant erase accounts
std::vector<Account> Accounts;

int main(int argc, char* argv[])
{
    const std::string APPSALT = "THISISAFUCKINGDOPESALT";

    Account acc;
    
    std::string name = "Alice";
    std::string pin = "1234";
    acc.makeAccount(name, pin, APPSALT );
    acc.deposit(100);
    Accounts.push_back(acc);

    name = "Bob";
    pin = "1234";
    acc.makeAccount(name, pin, APPSALT );
    acc.deposit(50);
    Accounts.push_back(acc);

    name = "Eve";
    pin = "1234";
    acc.makeAccount(name, pin, APPSALT );
    Accounts.push_back(acc);

    /*
    Account a("Alice", "1234", APPSALT);
    Account b("Bob", 50, "1234");
    Account e("Eve", 0 , "1234");
    Accounts.push_back(a);
    Accounts.push_back(b);
    Accounts.push_back(e);
    */

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
        if(csock < 0)   //bad client, skip it
            continue;

        pthread_t thread;
        pthread_create(&thread, NULL, client_thread, (void*)&csock);
    }
}

void* client_thread(void* arg)
{
    int csock = *(int*)arg;

    printf("[bank] client ID #%d connected\n", csock);

    //input loop
    int length;
    char packet[1024];
    Account* current;
    while(1)
    {
        bzero(packet, strlen(packet));
        //read the packet from the ATM
        if(sizeof(int) != recv(csock, &length, sizeof(int), 0)){
            break;
        }
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
        decryptPacket(packet);
        //decrypt and authenticate
        //store in buffer after decryption
        //unpad?

        std::vector<std::string> commands;
        char hold[strlen(packet)];
        strcpy(hold, packet);
        //char* hold = buffer;
        char* token = strtok(hold," ");
        int i = 0;
        while(token != NULL)
        {
            //printf("%s\n", "shit");
            commands.push_back(std::string(token));
            i++;
            token = strtok(NULL," ");
        }
        std::string buffer;

        if(commands[0] == "login")
        {
            for(int i = 0; i < Accounts.size(); i++)
            {
                if(commands[1] == Accounts[i].getName())
                {
                    // this needs to be changed to compare the hashes
                    //if(commands[2] == Accounts[i].getPin())
                    if(Accounts[i].tryLogin())
                    {
                        buffer = "Logged in";
                        current = &Accounts[i];
                        break;
                    }
                }
            }
            if(current == NULL)
            {
                //login and pin dont match
                buffer = "Username and PIN don't match";
            }

        }
        else if(commands[0] == "balance")
        {
            std::stringstream s;
            s << current->getBalance();
            buffer = s.str();
        }
        else if(commands[0] == "withdraw")
        {   
            if (atoi(commands[1].c_str()) <= 0)
            {
                buffer = "Invalid amount";
            }
            else if (current->withdraw(atoi(commands[1].c_str())))
            {
                buffer = commands[1] + " withdrawn";
            }
            else{
                buffer = "Insufficient funds";
            }
        }
        else if(commands[0] == "transfer")
        {
            if (commands[2] != current->getName())
            {
                Account *other = NULL;
                for(unsigned int i = 0; i < Accounts.size(); i++)
                {
                    if(Accounts[i].getName() == commands[2])
                    {
                        other = &Accounts[i];
                        break;
                    }
                }
                if(other == NULL)
                {
                    //user account not found;
                    buffer = "User could not be found";
                }
                else
                {
                    if (atoi(commands[1].c_str()) <= 0)
                    {
                        buffer = "Invalid amount";
                    }
                    else
                    {
                        if (current->transfer(atoi(commands[1].c_str()), other))
                        {
                            buffer = commands[1] + " Transferred to " + commands[2];
                        }
                        else
                        {
                            buffer = "Insufficient funds";
                        }
                    }
                }
            }
            else
            {
                buffer = "Can't transfer to yourself";
            }
        }
        bzero(packet, strlen(packet));
        
        strcat(packet, buffer.c_str());
        length = strlen(packet);
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
    std::vector<std::string> commands;
    while(1)
    {
        bzero(buf,strlen(buf));
        commands.clear();

        printf("bank> ");
        fgets(buf, 79, stdin);
        buf[strlen(buf)-1] = '\0';  //trim off trailing newline

        //TODO: your input parsing code has to go here

        char hold[strlen(buf)];
        strcpy(hold, buf);
        char * token = strtok(hold," ");
        int i = 0;
        while(token != NULL)
        {
            commands.push_back(std::string(token));
            i++;
            token = strtok(NULL," ");
        }


        if(commands[0] == "deposit")
        {
            Account *current = NULL;
            for(i = 0; i < Accounts.size(); i++)
            {
                if(Accounts[i].getName() == commands[1])
                {
                    current = &Accounts[i];
                    break;
                }
            }
            if(atoi(commands[2].c_str()) <= 0)
            {
                std::cout << "Invalid amount" << std::endl;
            }
            else if(current == NULL)
            {
                printf("No account found\n");
            }
            else
            {
                current->deposit(atoi(commands[2].c_str()));
            }
        }
        else if(commands[0] == "balance")
        {
            Account *current = NULL;
            for(i = 0; i < Accounts.size(); i++)
            {
                if(Accounts[i].getName() == commands[1])
                {
                    current = &Accounts[i];
                    break;
                }
            }
            if (current == NULL)
            {
                printf("No account found\n");
            }
            else
            {
                printf("Balance: %d\n", current->getBalance());
            }
        }
        else
        {
            std::cout << "Command not valid" << std::endl;
        }
    }
}
