class Account
{
    public:
        Account();
        Account & operator= (const Account & a);
        bool makeAccount(const std::string& n, const std::string& p, const std::string& APPSALT);
        void setHash(const std::string& p, const std::string& APPSALT);
        std::string getName();
        int getBalance();
        void setBalance(int b);
        std::string getPin();
        bool withdraw(int amount);
        bool deposit(int amount);
        bool transfer(int amount, Account *other);

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


bool makeAccount(const std::string& n, const std::string& p, const std::string& APPSALT)
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
    string hash = createHash(this->card + APPSALT + p);
    this->hash = hash;
    return true;
}

bool Account::tryLogin(const std::string& p, const std::string& APPSALT) {
    if(this->loggedin || this->lockedout ) {
        return false;
    }
    std::string tryHash = makeHash(this->card + p + APPSALT);
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