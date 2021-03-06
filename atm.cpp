/**
  Taha Mehdi
  Pratik Patel
  Chris Renus

  Cryptography and Network Security I
  CSCI-4971-01
  Final Project

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
#include <sstream>
#include <vector>
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

const std::string APPSALT = "THISISAFUCKINGDOPESALT";
byte* AES_iv;
byte* AES_key;

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

// functions used to mask password input
int getch() {
    int ch;
    struct termios t_old, t_new;

    tcgetattr(STDIN_FILENO, &t_old);
    t_new = t_old;
    t_new.c_lflag &= ~(ICANON | ECHO);
    tcsetattr(STDIN_FILENO, TCSANOW, &t_new);

    ch = getchar();

    tcsetattr(STDIN_FILENO, TCSANOW, &t_old);
    return ch;
}
std::string getpass(const char *prompt, bool show_asterisk=true)
{
  const char BACKSPACE=127;
  const char RETURN=10;

  std::string password;
  unsigned char ch=0;

  std::cout << prompt << std::endl;

  while((ch=getch())!=RETURN)
    {
       if(ch==BACKSPACE)
         {
            if(password.length()!=0)
              {
                 if(show_asterisk)
                 std::cout <<"\b \b";
                 password.resize(password.length()-1);
              }
         }
       else
         {
             password+=ch;
             if(show_asterisk)
                 std::cout <<'*';
         }
    }
  std::cout << std::endl;
  return password;
}

// generate random string of length len with given character sets 
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

// create hash using SHA-512 algorithm with given input
std::string createHash(const std::string& input) {
    CryptoPP::SHA512 hash;
    byte digest[ CryptoPP::SHA512::DIGESTSIZE ];
    hash.CalculateDigest( digest, (byte*) input.c_str(), input.length() );
    CryptoPP::HexEncoder encoder;
    std::string output;
    encoder.Attach( new CryptoPP::StringSink( output ) );
    encoder.Put( digest, sizeof(digest) );
    encoder.MessageEnd();
    return output;
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

    std::string encodedCipher;
    CryptoPP::StringSource(ciphertext, true,
        new CryptoPP::HexEncoder(new CryptoPP::StringSink(encodedCipher)) // HexEncoder
    );
    ciphertext = encodedCipher;
}

void decryptCommand(std::string& decipher, std::string& command,const byte key[],const byte iv[]) {
    CryptoPP::AES::Decryption aesDecryption(key, CryptoPP::AES::DEFAULT_KEYLENGTH);
    CryptoPP::CBC_Mode_ExternalCipher::Decryption cbcDecryption( aesDecryption, iv );

    CryptoPP::StreamTransformationFilter stfDecryptor(cbcDecryption, new CryptoPP::StringSink( decipher ) );
    stfDecryptor.Put( reinterpret_cast<const unsigned char*>( command.c_str() ), command.size() );
    stfDecryptor.MessageEnd();
}

void decryptPacket(std::string& packet){
    
    // first get ciphertext by decoding
    std::string ciphertext;
    CryptoPP::StringSource(packet, true,
        new CryptoPP::HexDecoder(new CryptoPP::StringSink(ciphertext)) // HexEncoder
    );
    // now decrypt that
    std::string plaintext;
    decryptCommand(plaintext, ciphertext, (const byte*) AES_key, (const byte*) AES_iv);
    
    // finally unpad
    unpadCommand(plaintext);
    packet = plaintext;
}

// prepare packet for communication to bank
std::string createPacket(std::string input, std::string account){
    std::string output = input + " " + account;
    std::string hash = createHash(output + APPSALT);
    output = output + " " + hash;
    
    padCommand(output);

    std::string ciphertext;
    encryptCommand(ciphertext, output,(const byte*) AES_key, (const byte*) AES_iv);
    return ciphertext;
}

int main(int argc, char* argv[])
{
	if(argc != 2)
	{
		printf("Usage: atm proxy-port\n");
		return -1;
	}

    // set up RSA
    CryptoPP::AutoSeededRandomPool prng;
    CryptoPP::RSA::PrivateKey privKey;
    privKey.GenerateRandomWithKeySize(prng, 1024);
    CryptoPP::RSA::PublicKey pubKey(privKey);
    
    //id generation
    std::string id_path;
    unsigned int possible_id = 1;
    while (1)
    {
        id_path = "";
        std::stringstream ss;
        ss << possible_id;
        ss >> id_path;

        // check if ATM already has key
        id_path = "keys/atm" + id_path + ".key";
        std::ifstream check_file(id_path.c_str());

        if (!check_file)
        {
            // create new key file
            std::ofstream id_file(id_path.c_str());
            SavePublicKey(id_path, pubKey);
            break;
        }
        possible_id++;
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

    //TODO establish handshake and transfer keys

    // get RSA key
    CryptoPP::RSA::PublicKey bankKey;
    LoadPublicKey("keys/bank.key", bankKey);
    CryptoPP::Integer id((const byte *)id_path.data(), id_path.size());
    CryptoPP::Integer c = bankKey.ApplyFunction(id);
    
    // prepare message
    std::stringstream ss;
    ss << std::hex << c;
    std::string message = ss.str();
    std::string handCheck = createHash(message + APPSALT);
    message = message + " " + handCheck;

    char m_packet[1024];
    strcpy(m_packet, message.c_str());
    int m_length = strlen(m_packet);
    if(sizeof(int) != send(sock, &m_length, sizeof(int), 0))
    {
        printf("fail to send packet length\n");
        return -1;
    }
    if(m_length != send(sock, (void*)m_packet, m_length, 0))
    {
        printf("fail to send packet\n");
        return -1;
    }

    bzero(m_packet, strlen(m_packet));
    if(sizeof(int) != recv(sock, &m_length, sizeof(int), 0)){
        return -1;
    }
    if(m_length >= 1024)
    {
        printf("packet too long\n");
        return -1;
    }
    if(m_length != recv(sock, m_packet, m_length, 0))
    {
        printf("[bank] fail to read packet\n");
        return -1;
    }

    std::string m = std::string(m_packet);
    message = m.substr(0, m.find(" "));

    // check if message has been tampered with
    if(m.substr(m.find(" ")+1) != createHash(message + APPSALT)){
        printf("Hackers!!\n");
        return -1;
    }
    
    CryptoPP::Integer cipher(message.c_str());
    CryptoPP::Integer plain = privKey.CalculateInverse(prng, cipher);
    
    std::string recovered;
    size_t req = plain.MinEncodedSize();
    recovered.resize(req);
    plain.Encode((byte *)recovered.data(), recovered.size());

    // parse out AES key and iv
    std::string holder = recovered.substr(0, recovered.find(",,"));
    AES_key = (byte*)holder.data();
    std::string holder1 = recovered.substr(recovered.find(",,") + 2);
    AES_iv = (byte*)holder1.data();

	char buf[80];
	char packet[1024];
    std::string accountHash;
	std::vector<std::string> commands;
	while(1)
	{
        fflush(NULL);
		bzero(buf, strlen(buf));
		bzero(packet,strlen(packet));
		commands.clear();

		printf("atm> ");
		fgets(buf, 79, stdin);
		buf[strlen(buf)-1] = '\0';
		
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
		
		int length = 1;
		
        if (commands.size() != 0)
        {
            //input parsing
            bool pass = true;
            if(commands[0] == "logout")
            {
                pass = true;
            }
            else if(commands[0] == "login")
            {
                if(commands.size() != 2)
                {
                    std::cout << "Not valid input for login" << std::endl;
                    pass = false;
                }
                else
                {
                    std::string username = commands[1];

                    // open card
                    std::ifstream cardFile(("cards/" + username + ".card").c_str());
                    if(cardFile) {

                        //obtain card hash
                        std::string cardHash;
                        cardFile >> cardHash;
                        cardHash = cardHash.substr(0,128);
                        
                        // prompts for PIN for login and puts it in the pin var
                        std::string pin;
                        pin = getpass("PIN: ", true);
                       
                        //Now we'll figure out the hash that we need to send
                        accountHash = createHash(cardHash + APPSALT + pin);
                        
                        // send account hash to bank to verify.
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

            //send the packet through the proxy to the bank

            if(pass)
            {
                //if no error in input encrypt and pad packet.
                std::string ciphertext = createPacket(std::string(buf), accountHash);
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
                if(!strcmp(buf, "logout"))
                {
                    break;
                }
                
                length = 1;
                bzero(packet, strlen(packet));
                
                if(sizeof(int) != recv(sock, &length, sizeof(int), 0))
                {
                    std::cout << length;
                    printf("fail to read packet length: possible timeout?\n");
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
                
                std::string plaintext = std::string(packet);
                decryptPacket(plaintext);
                std::string input = plaintext.substr(0, plaintext.find_last_of(' '));
                std::string hash = plaintext.substr(plaintext.find_last_of(' ') + 1);
                std::string checksum = createHash(input + APPSALT);
                
                if(checksum != hash){
                    printf("Hackers!!!\n");
                    break;
                }
                //decrypt and authenticate packet
                std::cout << input << std::endl;
                //std::cout << packet << std::endl;
            }
        }
        else
        {
            std::cout << std::endl;
        }
    }

    //Delete atm key file
    if (remove(id_path.c_str()) != 0 )
    {
        perror( "Error deleting file" );
        return -1;
    }
	//cleanup
	close(sock);
	return 0;
}
