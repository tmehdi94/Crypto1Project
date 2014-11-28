/**
  Taha Mehdi
  Pratik Patel
  Chris Renus

  Cryptography and Network Security I
  CSCI-4971-01
  Final Project

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

// used in random number generation
CryptoPP::AutoSeededRandomPool prng;

// atm thread
void* client_thread(void* arg);

// bank thread
void* console_thread(void* arg);

// file backup thread
void* backup_thread(void* arg);

// struct to hold RSA keys
struct rsa {
   CryptoPP::RSA::PrivateKey priv;
   CryptoPP::RSA::PublicKey pub;

};
rsa keys;

// functions to save public key to file
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

// functions to load public key from file
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

// pad end of packet with '~' then 'a's to separate command from string for parsing
void padCommand(std::string &command){
    if (command.size() < 494){
        command += "~";
    }
    while(command.size() < 494){
        command += "a";
    }
}

void unpadCommand(std::string &plaintext) {
    bool positionFound = false;
    int position = -1;

    // find index of ~
    for(unsigned int i = 0; i < plaintext.size(); ++i) {
        if(plaintext[i] == '~') {
            positionFound = true;
            position = i;
            break;
        }
    }

    // truncate string
    if(position > 0 && positionFound) {
        plaintext = plaintext.substr(0,position);
    }
    else {
        // that was some bad input
    }
    return;
}

// encrypt and decrypt account information with Advanced Encryption Standard
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
    // hash input
    std::string hash = createHash(input + APPSALT);
    input = input + " " + hash;

    padCommand(input);

    // encrypt and encode packet
    std::string ciphertext;
    encryptCommand(ciphertext, input,(const byte*) key,(const byte*) iv);
    std::string encodedCipher;
    CryptoPP::StringSource(ciphertext, true,
        new CryptoPP::HexEncoder(new CryptoPP::StringSink(encodedCipher)) // HexEncoder
    );
    ciphertext = encodedCipher;
    return ciphertext;
}

void decryptPacket(std::string& packet, byte* key, byte* iv){

    // first get ciphertext by decoding
    std::string ciphertext;
    CryptoPP::StringSource(packet, true,
        new CryptoPP::HexDecoder(new CryptoPP::StringSink(ciphertext)) // HexEncoder
    );

    // now decrypt that
    std::string plaintext;
    decryptCommand(plaintext, ciphertext,(const byte*) key, (const byte*) iv);
    
    // finally unpad
    unpadCommand(plaintext);
    packet = plaintext;
}

// hold all accounts in the banks
std::vector<Account> Accounts;

int main(int argc, char* argv[])
{

    // set up RSA public and private keys
    CryptoPP::RSA::PrivateKey privKey;
    privKey.GenerateRandomWithKeySize(prng,1024);
    CryptoPP::RSA::PublicKey pubKey(privKey);
    SavePublicKey("keys/bank.key", pubKey);
    keys.pub = pubKey;
    keys.priv = privKey;
    
    // account_data.data holds the account information from previous sessions
    // recover data if available
    std::ifstream account_data("account_data.data");
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
    // if not available generate new account information
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

    

    // AES set up
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
    
    // space delimits message 
    std::string message = m.substr(0, m.find(" "));
    
    // check if tampered with
    if(m.substr(m.find(" ")+1) != createHash(message + APPSALT)){
        printf("Hackers!!\n");
        return NULL;
    }
    
    // get RSA keys
    CryptoPP::Integer cipher(message.c_str());
    CryptoPP::Integer plain = (keys.priv).CalculateInverse(prng, cipher);
    std::string recovered;
    size_t req = plain.MinEncodedSize();
    recovered.resize(req);
    plain.Encode((byte *)recovered.data(), recovered.size());
    CryptoPP::RSA::PublicKey atmKey;
    LoadPublicKey(recovered, atmKey);

    // Create random AES key
    CryptoPP::AutoSeededRandomPool rnd;
    rnd.GenerateBlock( key, CryptoPP::AES::DEFAULT_KEYLENGTH );

    // Generate a random IV
    rnd.GenerateBlock(iv, CryptoPP::AES::BLOCKSIZE);
    
    
    std::stringstream hold;
    hold << key << ",," << iv;
    std::string k = hold.str();
    CryptoPP::Integer id((const byte *)k.data(), k.size());
    CryptoPP::Integer c = atmKey.ApplyFunction(id);
    std::stringstream ss;
    ss << std::hex << c;
    message = ss.str();

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
  
    printf("[bank] client ID #%d connected\n", csock);

    // input loop
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
        
        std::string text = std::string(packet);
        
        decryptPacket(text, key, iv);

        // parse commands
        std::vector<std::string> commands;
        char hold[text.size()];
        strcpy(hold, text.c_str());
        char* token = strtok(hold," ");
        int i = 0;
        while(token != NULL)
        {
            commands.push_back(std::string(token));
            i++;
            token = strtok(NULL," ");
        }
        std::string buffer;
        // expected input: login user passhash checksum
        //      commands[]   0    1       2       3
        std::string input = text.substr(0, text.find_last_of(' '));
        std::string checksum = createHash(input + APPSALT);
        if(checksum == commands[commands.size()-1]){
            if(commands[0] == "login")
            {
                for(int i = 0; i < Accounts.size(); i++) // locate account
                {
                    if(commands[1] == Accounts[i].getName())
                    {
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
                    //login and pin dont match, or time out, or other general error
                    buffer = "Login error";
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
                        //user account not found
                        buffer = "User could not be found";
                    }
                    else
                    {
                        if (atoi(commands[1].c_str()) <= 0) // negative number check
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
                buffer = "Error encountered";
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
        buf[strlen(buf)-1] = '\0';  

        // parse commands
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
            for(i = 0; i < Accounts.size(); i++) // find account
            {
                if(Accounts[i].getName() == commands[1]) 
                {
                    current = &Accounts[i];
                    break;
                }
            }
            if(atoi(commands[2].c_str()) <= 0)
            {
                printf( "Invalid amount\n");
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
            printf( "Command not valid\n");
        }
    }
}

void* backup_thread(void* arg)
{
    while(1)
    {
        //Every 5 seconds the accounts will be backed up to the data file
        sleep(5);
        std::ofstream account_data("account_data.data");

        for (unsigned int i = 0; i < Accounts.size(); i++)
        {
            account_data << Accounts[i].getFileInfo() << std::endl;
        }
    }
}
