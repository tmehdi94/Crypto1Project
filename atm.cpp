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
    const std::string appSalt = "THISISAFUCKINGDOPESALT";


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

void encryptCommand(std::string& ciphertext, std::string& command, byte* key, byte* iv) {
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

void decryptCommand(std::string& decipher, std::string& command, byte* key, byte* iv) {
    CryptoPP::AES::Decryption aesDecryption(key, CryptoPP::AES::DEFAULT_KEYLENGTH);
    CryptoPP::CBC_Mode_ExternalCipher::Decryption cbcDecryption( aesDecryption, iv );

    CryptoPP::StreamTransformationFilter stfDecryptor(cbcDecryption, new CryptoPP::StringSink( decipher ) );
    stfDecryptor.Put( reinterpret_cast<const unsigned char*>( command.c_str() ), command.size() );
    stfDecryptor.MessageEnd();
}

void decryptPacket(std::string& packet){
    std::cout << packet.size() << std::endl;
    std::string ciphertext;

    CryptoPP::StringSource(packet, true,
        new CryptoPP::HexDecoder(new CryptoPP::StringSink(ciphertext)) // HexEncoder
    );
    std::string plaintext;

    byte key[ CryptoPP::AES::DEFAULT_KEYLENGTH ], iv[ CryptoPP::AES::BLOCKSIZE ];
    memset( key, 0x00, CryptoPP::AES::DEFAULT_KEYLENGTH );
    memset( iv, 0x00, CryptoPP::AES::BLOCKSIZE );
    decryptCommand(plaintext, ciphertext, key, iv);
    std::cout << plaintext << std::endl;
    unpadCommand(plaintext);
    packet = plaintext;
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


std::string createPacket(std::string input, std::string account){
    const std::string APPSALT = "THISISAFUCKINGDOPESALT";
    std::string output = input + " " + account;
    std::string hash = createHash(output + APPSALT);
    output = output + " " + hash;

    byte key[ CryptoPP::AES::DEFAULT_KEYLENGTH ], iv[ CryptoPP::AES::BLOCKSIZE ];
    memset( key, 0x00, CryptoPP::AES::DEFAULT_KEYLENGTH );
    memset( iv, 0x00, CryptoPP::AES::BLOCKSIZE );
    std::string ciphertext;
    printf("%s\n", key);
    //string decipher;

    padCommand(output);
    std::cout << output << std::endl;
    //ciphertext = output;
    encryptCommand(ciphertext, output, key, iv);
    //std::cout <<"encryption: " <<  ciphertext << " " << ciphertext.size() << std::endl;
    //std::cout << ciphertext.size() << std::endl;
    return ciphertext;

}





int main(int argc, char* argv[])
{
	if(argc != 2)
	{
		printf("Usage: atm proxy-port\n");
		return -1;
	}

    //id generation
    std::string id_path;
    unsigned int possible_id = 1;
    while (1)
    {
        id_path = "";
        std::stringstream ss;
        ss << possible_id;
        ss >> id_path;
        id_path = "keys/atm" + id_path + ".key";
        std::ifstream check_file(id_path.c_str());

        if (!check_file)
        {
            //Open id, create key
            std::ofstream id_file(id_path.c_str());

            //TODO Write key to file
            id_file << "HELLO\n";
            //Do stuff with it
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

	//bool loggedIn = false;
	//input loop

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
                
                std::string plaintext = std::string(packet);
                decryptPacket(plaintext);
                std::string input = plaintext.substr(0, plaintext.find_last_of(' '));
                std::string hash = plaintext.substr(plaintext.find_last_of(' ') + 1);
                std::string checksum = createHash(input + appSalt);
                std::cout << checksum << std::endl << hash << std::endl;
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
