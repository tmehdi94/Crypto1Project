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

void* client_thread(void* arg);
void* console_thread(void* arg);

class Account
{
    public:
        Account(std::string, int, int);
        Account();
        Account & operator= (const Account & a);
        std::string getName();
        int getBalance();
        void setBalance(int b);
        int getPin();
        void setPin(int p);
        bool withdraw(int amount);
        bool deposit(int amount);
        bool transfer(int amount, Account *other);

    private:
        std::string name;
        int balance;
        std::string pinhash;
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
    std::string  = "0000";
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

int Account::getPin()
{
    return pinhash;
}

void Account::setPin(std::string p)
{
    pinhash = p;
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

//Perhaps we should write this to a file so a power out attack cant erase accounts
std::vector<Account> Accounts;

int main(int argc, char* argv[])
{
    Account a("Alice", 100, "1234");
    Account b("Bob", 50, "1234");
    Account e("Eve", 0 , "1234");
    Accounts.push_back(a);
    Accounts.push_back(b);
    Accounts.push_back(e);

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
    int csock = *(int*)arg;

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

        //decrypt and authenticate
        //store in buffer after decryption
        //unpad?

        std::vector<std::string> commands;
        char hold[strlen(packet)];
        strcpy(hold, packet);
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

        if(commands[0] == "login")
        {
            for(int i = 0; i < Accounts.size(); i++)
            {
                if(commands[1] == Accounts[i].getName())
                {
                    if(atoi(commands[2].c_str()) == Accounts[i].getPin())
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
                buffer = "Username and PIN don't match";
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
        bzero(packet, strlen(packet));
        
        strcat(packet, buffer.c_str());
        length = strlen(packet);
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


        if(commands[0] == "deposit")
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
        else if(commands[0] == "balance")
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
