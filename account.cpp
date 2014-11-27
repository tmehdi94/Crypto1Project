class Account
{
    public:
        Account(std::string, int, std::string);
        Account();
        Account & operator= (const Account & a);
        std::string getName();
        int getBalance();
        void setBalance(int b);
        std::string getPin();
        void setPin(std::string p);
        bool withdraw(int amount);
        bool deposit(int amount);
        bool transfer(int amount, Account *other);

    private:
        int accountnum;
        std::string name;
        int balance;
        std::string pinhash;
        int loginattempts;
        bool loggedin;
        pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
};

Account::Account (std::string n, int m, std::string p)
{
    balance = m;
    name = n;
    pinhash = p;
}

Account::Account ()
{
    balance = 0;
    name = "";
    pinhash  = "0000";
}

Account &Account::operator= (const Account & a)
{
    if (this != &a){
        this->name = a.name;
        this->balance = a.balance;
        this->pinhash = a.pinhash;
    }
    return *this;
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
    return pinhash;
}

void Account::setPin(std::string p)
{
    pinhash = p;
}

/*
bool Account::tryLogin(std::string l) {
    // pthread_mutex_lock(&lock); <-- do we need this
    bool status = false;

}*/

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