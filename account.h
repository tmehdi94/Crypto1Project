/**
  Taha Mehdi
  Pratik Patel
  Chris Renus

  Cryptography and Network Security I
  CSCI-4971-01
  Final Project

  @file account.h
  @brief Account implementation file
  */

#include <iostream>
#include <fstream>
#include <string>
#include <sstream>

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

// Account class implementation
class Account
{
    public:
        Account();
        Account & operator= (const Account & a);
        bool makeAccount(const std::string& n, const std::string& p, const std::string& APPSALT);
        bool setHash(const std::string& p, const std::string& APPSALT);
        bool tryLogin(const std::string& tryHash);
        bool validCard(const std::string& cardHash);
        std::string getName();
        int getBalance();
        void setBalance(int b);
        std::string getPin();
        bool withdraw(int amount);
        bool deposit(int amount);
        bool transfer(int amount, Account *other);
        std::string getFileInfo();
        bool tryLogout();

    private:
        //int accountnum;
        std::string name;
        std::string card;
        std::string salt;
        int balance;
        std::string hash;
        int loginattempts;
        bool lockedout;
        bool loggedin;
        pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
};

// encrypt and decrypt account information with Advanced Encryption Standard
void encryptAccount(std::string& ciphertext, std::string& account_info, byte* key, byte* iv) {
    CryptoPP::AES::Encryption aesEncryption(key, CryptoPP::AES::DEFAULT_KEYLENGTH);
    CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEncryption( aesEncryption, iv );

    CryptoPP::StreamTransformationFilter stfEncryptor(cbcEncryption, new CryptoPP::StringSink( ciphertext ) );
    stfEncryptor.Put( reinterpret_cast<const unsigned char*>( account_info.c_str() ), account_info.length() + 1 );
    stfEncryptor.MessageEnd();
}

void decryptAccount(std::string& decipher, std::string& account_info, byte* key, byte* iv) {
    CryptoPP::AES::Decryption aesDecryption(key, CryptoPP::AES::DEFAULT_KEYLENGTH);
    CryptoPP::CBC_Mode_ExternalCipher::Decryption cbcDecryption( aesDecryption, iv );

    CryptoPP::StreamTransformationFilter stfDecryptor(cbcDecryption, new CryptoPP::StringSink( decipher ) );
    stfDecryptor.Put( reinterpret_cast<const unsigned char*>( account_info.c_str() ), account_info.size() );
    stfDecryptor.MessageEnd();
}

// account constructor
Account::Account ()
{
    name = "";
    card = "";
    balance = 0;
    hash  = "0000";
    loginattempts = 0;
    loggedin = false;
    lockedout = false;
}

Account &Account::operator= (const Account & a)
{
    if (this != &a){
        this->name = a.name;
        this->balance = a.balance;
        this->hash = a.hash;
    }
    return *this;
}


bool Account::makeAccount(const std::string& n, const std::string& p, const std::string& APPSALT)
{
    if (n == "") { //account must have name
        return false;
    }

    this->name = n;

    // card hash: createHash(account salt + account name)
    this->salt = createHash(randomString(128));
    this->card = createHash(this->salt + n);

    std::string cardFilename = "cards/" + n + ".card";
    std::ofstream outfile(cardFilename.c_str());
    if(outfile.is_open()) {
        outfile << this->card;
    }
    else {
        return false;
    }
    outfile.close();
    
    // set pin hash
    if(!setHash(p, APPSALT)) {
        return false;
    }
    this->loginattempts = 3;
    this->lockedout = false;
    return true;
}

// create pin hash
bool Account::setHash(const std::string& p, const std::string& APPSALT)
{
    // pin must be more than 4 chars, less than 16
    if (p.length() > 16 || p.length() < 3) {
        return false;
    }
    // account hash: createHash(card hash + appwide salt + pin)
    std::string hash = createHash(this->card + APPSALT + p);
    this->hash = hash;
    return true;
}

// check if provided card is valid for account
bool Account::validCard(const std::string& cardHash) {
    if(this->card != cardHash) {
        return false;
    }
    return true;
}

bool Account::tryLogin(const std::string& tryHash) {
    // if already logged in or locked out can't login
    if(this->loggedin || this->lockedout ) {
        return false;
    }
    if(this->hash == tryHash) { // logged in
        this->loggedin = true;
        return true;
    }
    else { // fail login
        if (loginattempts != 0) { // still has remaining attempts
            loginattempts--;
        }
        else { // all attempts used
            this->lockedout = true;
        }
        return false;
    }
    return false;
}

std::string Account::getName()
{
    return name;
}

int Account::getBalance()
{
    return balance;
}

void Account::setBalance(int b)
{
    balance = b;
}

std::string Account::getPin()
{
    return hash;
}

bool Account::withdraw(int amount)
{
    pthread_mutex_lock(&lock);
    bool status = false;
    if(balance >= amount)
    {
        balance -= amount;
        status = true;
    }
    else
    {
        status = false;
    }
    pthread_mutex_unlock(&lock);
    return status;
}

bool Account::deposit(int amount)
{
    pthread_mutex_lock(&lock);
    bool status = false;
    if(amount > 0)
    {
        int temp_balance = balance + amount;
        if (temp_balance < 0)
        {
            status = false;
            //Too much money for bank to handle
        }
        else
        {
            balance = temp_balance;
            status = true;
        }
    }
    pthread_mutex_unlock(&lock);
    return status;
}

bool Account::transfer(int amount, Account *other)
{
    pthread_mutex_lock(&lock);
    bool status = false;
    if(balance >= amount && amount > 0)
    {
        balance -= amount;
        if (other->deposit(amount))
        {
            status = true;
        }
        else
        {
            //add back
            balance += amount;
        }
    }
    else
    {
        status = false;
    }
    pthread_mutex_unlock(&lock);
    return status;
}

// used for outputting to file
std::string Account::getFileInfo()
{
    byte key[ CryptoPP::AES::DEFAULT_KEYLENGTH ], iv[ CryptoPP::AES::BLOCKSIZE ];
    memset( key, 0x00, CryptoPP::AES::DEFAULT_KEYLENGTH );
    memset( iv, 0x00, CryptoPP::AES::BLOCKSIZE );
    
    std::stringstream ss;
    ss << balance;

    std::string temp;
    ss >> temp;

    temp = name + " " + temp;

    std::string ciphertext;
    encryptAccount(ciphertext, temp, key, iv);
    return ciphertext;
}

bool Account::tryLogout()
{
    if(loggedin)
    {
        loggedin = false;
        return true;
    }
    else
    {
        return false;
    }
}