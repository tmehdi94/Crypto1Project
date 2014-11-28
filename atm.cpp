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
#include "crypto++/files.h"
#include "crypto++/cryptlib.h"
const std::string appSalt = "THISISAFUCKINGDOPESALT";
byte AES_iv[CryptoPP::AES::BLOCKSIZE];
byte AES_key[CryptoPP::AES::DEFAULT_KEYLENGTH];



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
    //std::cout << packet.size() << std::endl;
    std::string ciphertext;

    CryptoPP::StringSource(packet, true,
        new CryptoPP::HexDecoder(new CryptoPP::StringSink(ciphertext)) // HexEncoder
    );
    std::string plaintext;
    /*
    byte key[ CryptoPP::AES::DEFAULT_KEYLENGTH ], iv[ CryptoPP::AES::BLOCKSIZE ];
    memset( key, 0x00, CryptoPP::AES::DEFAULT_KEYLENGTH );
    memset( iv, 0x00, CryptoPP::AES::BLOCKSIZE );*/
    decryptCommand(plaintext, ciphertext, (const byte*) AES_key, (const byte*) AES_iv);
    //std::cout << plaintext << std::endl;
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
    /*
    byte key[ CryptoPP::AES::DEFAULT_KEYLENGTH ], iv[ CryptoPP::AES::BLOCKSIZE ];
    memset( key, 0x00, CryptoPP::AES::DEFAULT_KEYLENGTH );
    memset( iv, 0x00, CryptoPP::AES::BLOCKSIZE );*/
    std::string ciphertext;
    //printf("%s\n", key);
    //string decipher;
    //std::cout << output <<std::endl;
    padCommand(output);
    //std::cout << output.size() << std::endl;
    //std::cout << output << std::endl;
    //ciphertext = output;
    //std::cout <<"keys: " << strlen((char*)AES_key) <<AES_key << std::endl << "iv: "<< strlen((char*)AES_iv) <<AES_iv << std::endl;
    encryptCommand(ciphertext, output,(const byte*) AES_key, (const byte*) AES_iv);
    //std::cout <<"encryption: " <<  ciphertext << " " << ciphertext.size() << std::endl;
    //std::cout << ciphertext.size() << std::endl;
    //std::cout << ciphertext << std::endl;
    return ciphertext;

}





int main(int argc, char* argv[])
{
	if(argc != 2)
	{
		printf("Usage: atm proxy-port\n");
		return -1;
	}
    memset( AES_key, 0x00, CryptoPP::AES::DEFAULT_KEYLENGTH );
    memset( AES_iv, 0x00, CryptoPP::AES::BLOCKSIZE );
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
        id_path = "keys/atm" + id_path + ".key";
        std::ifstream check_file(id_path.c_str());

        if (!check_file)
        {
            //Open id, create key
            std::ofstream id_file(id_path.c_str());
            //close(id_file);
            //TODO Write key to file
            SavePublicKey(id_path, pubKey);
            //id_file << "HELLO\n";
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

    //TODO establish handshake and transfer keys
    CryptoPP::RSA::PublicKey bankKey;
    LoadPublicKey("keys/bank.key", bankKey);
    CryptoPP::Integer id((const byte *)id_path.data(), id_path.size());
    CryptoPP::Integer c = bankKey.ApplyFunction(id);
    std::stringstream ss;
    ss << std::hex << c;//ss << c.ConvertToLong();
    std::string message = ss.str();
    //std::cout << message << std::endl;
    std::string handCheck = createHash(message + appSalt);
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
    //printf("%s\n",m_packet );

    std::string m = std::string(m_packet);
    message = m.substr(0, m.find(" "));
    if(m.substr(m.find(" ")+1) != createHash(message + appSalt)){
        printf("Hackers!!\n");
        return -1;
    }
    //std::cout << "message: " << message << std::endl;
    CryptoPP::Integer cipher(message.c_str());//std::atol(message.c_str()));
    CryptoPP::Integer plain = privKey.CalculateInverse(prng, cipher);
    //std::cout <<"decrypted: " << std::hex << plain << std::endl;
    std::string recovered;
    size_t req = plain.MinEncodedSize();
    recovered.resize(req);
    plain.Encode((byte *)recovered.data(), recovered.size());
    //std::cout << "encoded: " << recovered << std::endl;

    std::string holder = recovered.substr(0, recovered.find(" "));
    //AES_key = (const byte*) holder.data();//recovered.substr(0, recovered.find(" ")).data();//result;
    //memset( (void*)AES_key, (int) holder.data(), CryptoPP::AES::DEFAULT_KEYLENGTH );
    //AES_key = (byte*)holder.data();
    //strcpy(AES_key, (byte*)holder.data());
    std::string holder1 = recovered.substr(recovered.find(" ") + 1);
    for(int i=0; i < 16; i++){
        AES_key[i] = holder.data()[i];
        AES_iv[i] = holder1.data()[i];
    }


    //result;
     //memset( (void*)AES_iv, (int) holder1.data(), CryptoPP::AES::BLOCKSIZE );
    //std::cout << "key: " << AES_key << std::endl << "iv: " << AES_iv << std::endl;
    //std::cout << AES_key.size() << std::endl << AES_iv.size() << std::endl;
	//bool loggedIn = false;
	//input loop

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
            if(commands[0] == "logout")
            {
                pass = true;
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
                //std::cout << ciphertext.size() << std::endl;
                strcpy(packet, ciphertext.data());
                length = strlen(packet);
                //std::cout << length << std::endl;

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
                //std::cout << "FUCK" << std::endl; fflush(NULL);
                length = 1;
                bzero(packet, strlen(packet));
                //TODO: do something with response packet
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
                std::string checksum = createHash(input + appSalt);
                //std::cout << checksum << std::endl << hash << std::endl;
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
