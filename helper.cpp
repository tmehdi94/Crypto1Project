#include <iostream>
#include <iomanip>
#include <stdlib.h>
#include <time.h>       
#include "crypto++/modes.h"
#include "crypto++/aes.h"
#include "crypto++/filters.h"

using namespace std;

// generate random string with given length n
std::string randomString(const unsigned int len) {

	static const char alphanum[] =
		"0123456789"
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		"abcdefghijklmnopqrstuvwxyz";
		
	string s = "";
	
	//When adding each letter, generate a new word32,
	//then compute it modulo alphanum's size - 1
	
	for(unsigned int i = 0; i < len; ++i) {
		s += alphanum[rand() % (sizeof(alphanum) - 1)];
	} 
	return s;
}

void padCommand(string &command){
	
	// pad end of packet with '~' then 'a's to separate command
	// from string for parsing
	
	//if (command.size() < 460){ //1022 because buildPacket() has two '\0's
	if (command.size() < 1008){
		command += "~";
	}
	while(command.size() < 1008){
		command += "a";
	}
}

void unpadCommand(string &plaintext) {
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

void encryptCommand(string& ciphertext, string& command, byte* key, byte* iv) {
	CryptoPP::AES::Encryption aesEncryption(key, CryptoPP::AES::DEFAULT_KEYLENGTH);
    CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEncryption( aesEncryption, iv );

    CryptoPP::StreamTransformationFilter stfEncryptor(cbcEncryption, new CryptoPP::StringSink( ciphertext ) );
    stfEncryptor.Put( reinterpret_cast<const unsigned char*>( command.c_str() ), command.length() + 1 );
    stfEncryptor.MessageEnd();
}

void decryptCommand(string& decipher, string& command, byte* key, byte* iv) {
	CryptoPP::AES::Decryption aesDecryption(key, CryptoPP::AES::DEFAULT_KEYLENGTH);
    CryptoPP::CBC_Mode_ExternalCipher::Decryption cbcDecryption( aesDecryption, iv );

    CryptoPP::StreamTransformationFilter stfDecryptor(cbcDecryption, new CryptoPP::StringSink( decipher ) );
    stfDecryptor.Put( reinterpret_cast<const unsigned char*>( command.c_str() ), command.size() );
    stfDecryptor.MessageEnd();
}

int main() {
	srand (time(NULL));

	byte key[ CryptoPP::AES::DEFAULT_KEYLENGTH ], iv[ CryptoPP::AES::BLOCKSIZE ];
    memset( key, 0x00, CryptoPP::AES::DEFAULT_KEYLENGTH );
    memset( iv, 0x00, CryptoPP::AES::BLOCKSIZE );

	string str = "hello there!!!!!!!!!!!!!!!!";
	string ciphertext;
	string decipher;

	//char packet[1024];
	padCommand(str);
	cout << str << " " << str.size() << endl;
	
	/*
	if(str.size() <= 1022) {
		strcpy(packet, (str+'\0').c_str());
		packet[str.size()-1] = '\0';
	}*/
	
	//cout << str << endl;
	encryptCommand(ciphertext, str, key, iv);
	cout <<"encryption: " <<  ciphertext << " " << ciphertext.size() << endl;
	decryptCommand(decipher, ciphertext, key, iv);
	cout <<"decryption: " << decipher << " " << decipher.size() << endl;
	unpadCommand(decipher);
	cout << decipher << endl;
}


