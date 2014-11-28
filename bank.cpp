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
#include <fstream>
#include "crypto++/modes.h"
#include "crypto++/aes.h"
#include "crypto++/filters.h"
#include "crypto++/integer.h"
#include "crypto++/rsa.h"
#include "crypto++/osrng.h"
#include "crypto++/sha.h"
#include "crypto++/hex.h"
#include "crypto++/files.h"
#include "crypto++/cryptlib.h"

#include "account.h"

const std::string APPSALT = "THISISAFUCKINGDOPESALT";
CryptoPP::AutoSeededRandomPool prng;

void* client_thread(void* arg);
void* console_thread(void* arg);
void* backup_thread(void* arg);

struct rsa {
   CryptoPP::RSA::PrivateKey priv;
   CryptoPP::RSA::PublicKey pub;

};
rsa keys;

void Save(const std::string& filename, const CryptoPP::BufferedTransformation& bt)
{
    CryptoPP::FileSink file(filename.c_str());

    bt.CopyTo(file);
    file.MessageEnd();
}

void SavePublicKey(const std::string& filename, const CryptoPP::RSA::PublicKey& key)
{
    CryptoPP::ByteQueue queue;
    key.Save(queue);

    Save(filename, queue);
}


void Load(const std::string& filename, CryptoPP::BufferedTransformation& bt)
{
    CryptoPP::FileSource file(filename.c_str(), true /*pumpAll*/);

    file.TransferTo(bt);
    bt.MessageEnd();
}

void LoadPublicKey(const std::string& filename, CryptoPP::RSA::PublicKey& key)
{
    CryptoPP::ByteQueue queue;
    Load(filename, queue);

    key.Load(queue);    
}


void padCommand(std::string &command){
    
    // pad end of packet with '~' then 'a's to separate command
    // from string for parsing
    
    //if (command.size() < 460){ //1022 because buildPacket() has two '\0's
    if (command.size() < 494){
        command += "~";
    }
    while(command.size() < 494){
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


void encryptCommand(std::string& ciphertext, std::string& command,const byte key[],const byte iv[]) {
    CryptoPP::AES::Encryption aesEncryption(key, CryptoPP::AES::DEFAULT_KEYLENGTH);
    CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEncryption( aesEncryption, iv );

    CryptoPP::StreamTransformationFilter stfEncryptor(cbcEncryption, new CryptoPP::StringSink( ciphertext ) );
    stfEncryptor.Put( reinterpret_cast<const unsigned char*>( command.c_str() ), command.length() + 1 );
    stfEncryptor.MessageEnd();


}

void decryptCommand(std::string& decipher, std::string& command,const byte key[], const byte iv[]) {
    CryptoPP::AES::Decryption aesDecryption(key, CryptoPP::AES::DEFAULT_KEYLENGTH);
    CryptoPP::CBC_Mode_ExternalCipher::Decryption cbcDecryption( aesDecryption, iv );

    CryptoPP::StreamTransformationFilter stfDecryptor(cbcDecryption, new CryptoPP::StringSink( decipher ) );
    stfDecryptor.Put( reinterpret_cast<const unsigned char*>( command.c_str() ), command.size() );
    stfDecryptor.MessageEnd();
}

std::string createPacket(std::string input, byte* key, byte* iv){
    std::string hash = createHash(input + APPSALT);
    input = input + " " + hash;
    /*
    byte key[ CryptoPP::AES::DEFAULT_KEYLENGTH ], iv[ CryptoPP::AES::BLOCKSIZE ];
    memset( key, 0x00, CryptoPP::AES::DEFAULT_KEYLENGTH );
    memset( iv, 0x00, CryptoPP::AES::BLOCKSIZE );*/
    std::string ciphertext;
    //printf("%s\n", key);
    //string decipher;

    padCommand(input);
    //std::cout << input << std::endl;
    encryptCommand(ciphertext, input,(const byte*) key,(const byte*) iv);
    std::string encodedCipher;
    CryptoPP::StringSource(ciphertext, true,
        new CryptoPP::HexEncoder(new CryptoPP::StringSink(encodedCipher)) // HexEncoder
    );
    ciphertext = encodedCipher;
    //std::cout << ciphertext << std::endl;
    return ciphertext;
}

void decryptPacket(std::string& packet, byte* key, byte* iv){
    //std::cout << packet.size() << std::endl;
    //std::cout << packet << std::endl;
    std::string ciphertext;
    //std::cout << packet << std::endl;
    CryptoPP::StringSource(packet, true,
        new CryptoPP::HexDecoder(new CryptoPP::StringSink(ciphertext)) // HexEncoder
    );
    std::string plaintext;
    /*
    byte key[ CryptoPP::AES::DEFAULT_KEYLENGTH ], iv[ CryptoPP::AES::BLOCKSIZE ];
    memset( key, 0x00, CryptoPP::AES::DEFAULT_KEYLENGTH );
    memset( iv, 0x00, CryptoPP::AES::BLOCKSIZE );*/
    //std::cout << strlen((char*)keys.key);
    //std::cout <<"keys: " << strlen((char*)keys.key) << keys.key << std::endl << "iv: "<< strlen((char*)keys.iv) << keys.iv << std::endl;
    //fflush(NULL);
    decryptCommand(plaintext, ciphertext,(const byte*) key, (const byte*) iv);
    //std::cout << plaintext << std::endl;
    unpadCommand(plaintext);
    packet = plaintext;
    //std::cout << packet << std::endl;
}

std::vector<Account> Accounts;

int main(int argc, char* argv[])
{
    std::ifstream account_data("account_data.data");
    CryptoPP::RSA::PrivateKey privKey;
    privKey.GenerateRandomWithKeySize(prng,1024);
    CryptoPP::RSA::PublicKey pubKey(privKey);
    SavePublicKey("keys/bank.key", pubKey);
    keys.pub = pubKey;
    keys.priv = privKey;
    //keys.key = (const byte*) "";
    //keys.iv = (const byte*) "";
    

    if (account_data)
    {
        std::string line;
        byte key[ CryptoPP::AES::DEFAULT_KEYLENGTH ], iv[ CryptoPP::AES::BLOCKSIZE ];
        memset( key, 0x00, CryptoPP::AES::DEFAULT_KEYLENGTH );
        memset( iv, 0x00, CryptoPP::AES::BLOCKSIZE );

        while(getline(account_data, line))
        {
            std::string plaintext;
            decryptAccount(plaintext, line, key, iv);
            std::istringstream iss(plaintext);

            std::string info_name;
            int info_amount;

            iss >> info_name >> info_amount;

            Account acc;

            std::string pin = "1234";
            acc.makeAccount(info_name, pin, APPSALT );
            acc.deposit(info_amount);
            Accounts.push_back(acc);
        }
    }
    else
    {
        Account accAlice;
        std::string name = "Alice";
        std::string pin = "1234";
        accAlice.makeAccount(name, pin, APPSALT );
        accAlice.deposit(100);
        Accounts.push_back(accAlice);

        Account accBob;
        name = "Bob";
        pin = "1234";
        accBob.makeAccount(name, pin, APPSALT );
        accBob.deposit(50);
        Accounts.push_back(accBob);

        Account accEve;
        name = "Eve";
        pin = "1234";
        accEve.makeAccount(name, pin, APPSALT );
        Accounts.push_back(accEve);
    }

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

    pthread_t bthread;
    pthread_create(&bthread, NULL, backup_thread, NULL);

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
    //TODO handshake and establish keys
    int csock = *(int*)arg;
    struct timeval tv;
 
    tv.tv_sec = 15;       /* Timeout in seconds */
 
    setsockopt(csock, SOL_SOCKET, SO_SNDTIMEO,(struct timeval *)&tv,sizeof(struct timeval));
    setsockopt(csock, SOL_SOCKET, SO_RCVTIMEO,(struct timeval *)&tv,sizeof(struct timeval));

    byte key[CryptoPP::AES::DEFAULT_KEYLENGTH];
    byte iv[CryptoPP::AES::BLOCKSIZE];
    memset((void*) key, 0x00, CryptoPP::AES::DEFAULT_KEYLENGTH );
    memset((void*) iv, 0x00, CryptoPP::AES::BLOCKSIZE );

    int m_length;
    char m_packet[1024];
    if(sizeof(int) != recv(csock, &m_length, sizeof(int), 0)){
        return NULL;
    }
    if(m_length >= 1024)
    {
        printf("packet too long\n");
        return NULL;
    }
    if(m_length != recv(csock, m_packet, m_length, 0))
    {
        printf("[bank] fail to read packet\n");
        return NULL;
    }
    std::string m = std::string(m_packet);
    //std::cout << m;
    std::string message = m.substr(0, m.find(" "));
    //std::cout << createHash(message + APPSALT) << std::endl;
    if(m.substr(m.find(" ")+1) != createHash(message + APPSALT)){
        printf("Hackers!!\n");
        return NULL;
    }
    CryptoPP::Integer cipher(message.c_str());//std::atol(message.c_str()));
    CryptoPP::Integer plain = (keys.priv).CalculateInverse(prng, cipher);
    //std::cout << std::hex << plain << std::endl;
    std::string recovered;
    size_t req = plain.MinEncodedSize();
    recovered.resize(req);
    plain.Encode((byte *)recovered.data(), recovered.size());

    CryptoPP::RSA::PublicKey atmKey;
    LoadPublicKey(recovered, atmKey);

    //create AES key
    CryptoPP::AutoSeededRandomPool rnd;
    // Generate a random key
    //byte key[CryptoPP::AES::DEFAULT_KEYLENGTH];
    rnd.GenerateBlock( key, CryptoPP::AES::DEFAULT_KEYLENGTH );
    //printf("%s\n", key);

    // Generate a random IV
    //byte iv[CryptoPP::AES::BLOCKSIZE];
    rnd.GenerateBlock(iv, CryptoPP::AES::BLOCKSIZE);
    //std::string k = std::string((const byte*)key) + " " + std::string((const byte*)iv);
    
    //memset( keys.key, (char*)key, CryptoPP::AES::DEFAULT_KEYLENGTH );
    //memset( keys.iv, (char*)iv, CryptoPP::AES::BLOCKSIZE );
    //keys.iv = (byte*) iv;
    //keys.key = (byte*) key;
    //printf("%d\n",CryptoPP::AES::DEFAULT_KEYLENGTH );
    //fflush(NULL);
    std::stringstream hold;
    hold <<key << ",," << iv;
    std::string k = hold.str();
    std::cout << "concat: " << k << std::endl;
    std::cout << "key: " << key << std::endl << "iv: " << iv << std::endl;

    CryptoPP::Integer id((const byte *)k.data(), k.size());
    CryptoPP::Integer c = atmKey.ApplyFunction(id);
    std::stringstream ss;
    ss << std::hex << c;//ss << c.ConvertToLong();
    message = ss.str();
    //std::cout << "message: " << message << std::endl;
    //std::cout << message << std::endl;
    std::string handCheck = createHash(message + APPSALT);
    message = message + " " + handCheck;



    bzero(m_packet, strlen(m_packet));
    strcpy(m_packet, message.c_str());

    if(sizeof(int) != send(csock, &m_length, sizeof(int), 0))
    {
        printf("fail to send packet length\n");
        return NULL;
    }
    if(m_length != send(csock, (void*)m_packet, m_length, 0))
    {
        printf("fail to send packet\n");
        return NULL;
    }
    //std::cout << std::hex << keys.aes << std::endl << std::hex << keys.iv << std::endl;



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
        //std::cout << length << std::endl;
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
        
        std::string text = std::string(packet);
        decryptPacket(text, key, iv);
        //std::cout << text <<std::endl;
        //decrypt and authenticate
        //store in buffer after decryption
        //unpad?

        std::vector<std::string> commands;
        char hold[text.size()];
        strcpy(hold, text.c_str());
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
        //expected input: login    user,card&passhash,checksum
        //                  0        1         2          3
        std::string input = text.substr(0, text.find_last_of(' '));
        std::string checksum = createHash(input + APPSALT);
        if(checksum == commands[commands.size()-1]){
            if(commands[0] == "login")
            {
                for(int i = 0; i < Accounts.size(); i++)
                {
                    if(commands[1] == Accounts[i].getName())
                    {
                        // this needs to be changed to compare the hashes
                        //if(commands[2] == Accounts[i].getPin())
                        if(Accounts[i].tryLogin(commands[2]))
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
                    buffer = "Username/PIN/card don't match";
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
            else if(commands[0] == "logout"){
                current->tryLogout();
                break;
            }
            else
            {
                buffer = "Shit is Fucked";
            }
        }
        else
        {
            printf("Tampering with packet\n");
            break;
        }
        bzero(packet, strlen(packet));
        
        std::string ciphertext = createPacket(buffer,key, iv);
        strcpy(packet, ciphertext.data());
        length = strlen(packet);
        std::cout << ciphertext.size() << std::endl;
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


        if(commands[0] == "deposit" && commands.size() == 3)
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
        else if(commands[0] == "balance" && commands.size() == 2)
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

void* backup_thread(void* arg)
{
    while(1)
    {
        //Every 5 seconds the accounts will be backed up.
        sleep(5);
        std::ofstream account_data("account_data.data");

        for (unsigned int i = 0; i < Accounts.size(); i++)
        {
            account_data << Accounts[i].getFileInfo() << std::endl;
        }
    }
}
