#include <iostream>
#include <fstream>
#include <string>
#include <sstream>

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

void encryptAccount(std::string& ciphertext, std::string& account_info, byte* key, byte* iv) {
    CryptoPP::AES::Encryption aesEncryption(key, CryptoPP::AES::DEFAULT_KEYLENGTH);
    CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEncryption( aesEncryption, iv );

    CryptoPP::StreamTransformationFilter stfEncryptor(cbcEncryption, new CryptoPP::StringSink( ciphertext ) );
    stfEncryptor.Put( reinterpret_cast<const unsigned char*>( account_info.c_str() ), account_info.length() + 1 );
    stfEncryptor.MessageEnd();

    std::string encodedCipher;
    CryptoPP::StringSource(ciphertext, true,
        new CryptoPP::HexEncoder(new CryptoPP::StringSink(encodedCipher)) // HexEncoder
    );
    ciphertext = encodedCipher;
}

void decryptAccount(std::string& decipher, std::string& account_info, byte* key, byte* iv) {
    CryptoPP::AES::Decryption aesDecryption(key, CryptoPP::AES::DEFAULT_KEYLENGTH);
    CryptoPP::CBC_Mode_ExternalCipher::Decryption cbcDecryption( aesDecryption, iv );

    CryptoPP::StreamTransformationFilter stfDecryptor(cbcDecryption, new CryptoPP::StringSink( decipher ) );
    stfDecryptor.Put( reinterpret_cast<const unsigned char*>( account_info.c_str() ), account_info.size() );
    stfDecryptor.MessageEnd();
}

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

    if (n == "") {
        //account must have name
        return false;
    }
    this->name = n;
    // card hash = createHash(account salt + account name)
    this->salt = createHash(randomString(128));
    this->card = createHash(this->salt + n);
    std::string cardFilename = "cards/" + n + ".card";
    std::ofstream outfile(cardFilename.c_str());
    if(outfile.is_open()) {
        outfile << this->card;
        //cout << "AYYYYYY" << endl;
    }
    else {
        return false;
    }
    outfile.close();
    
    if(!setHash(p, APPSALT)) {
        return false;
    }
    this->loginattempts = 3;
    this->lockedout = false;
    return true;
}

bool Account::setHash(const std::string& p, const std::string& APPSALT)
{
    // account hash = createHash(card hash + appwide salt + pin)

    // more than 4 chars, less than 16
    if (p.length() > 16 || p.length() < 3) {
        return false;
    }
    std::string hash = createHash(this->card + APPSALT + p);
    this->hash = hash;
    return true;
}

bool Account::validCard(const std::string& cardHash) {
    if(this->card != cardHash) {
        return false;
    }
    return true;
}

bool Account::tryLogin(const std::string& tryHash) {
    if(this->loggedin || this->lockedout ) {
        return false;
    }
    //std::string tryHash = makeHash(this->card + p + APPSALT);
    if(this->hash == tryHash) {
        this->loggedin = true;
        return true;
    }
    else {
        if (loginattempts != 0) {
            // still has remaining accounts
            loginattempts--;
        }
        else {
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
