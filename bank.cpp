#include <cmath>
#include <iostream>
#include <sstream>
#include <string>
#include <cstring>
#include <unistd.h>
#include <cstdint>
#include <netinet/in.h>
using namespace std;

#include "config.h"
#include "sha1.h"
#include "hmac_sha1.h"
#include "powmod.h"
#include "aes.h"

void handleClient(int clientSocket) {
    char buffer[MAX_MSG_SIZE] = {0};
    std::string command;
    double balance = 1000.0;

    // getting the private key
    std::uintmax_t priv_key = rand();

    // calculating the shared private key 
    std::uintmax_t shared_private; 
    unsigned char str_priv[16];
    std::uintmax_t shared_self = powmod(DHKE_G, priv_key, DHKE_P);
    read(clientSocket, buffer, MAX_MSG_SIZE);
    std::uintmax_t shared_other = std::stoull(buffer);
    shared_private = powmod(shared_other, priv_key, DHKE_P); 
    memcpy(str_priv, &shared_private, 8); 
    memcpy(str_priv+8, &shared_private, 8); 
    command = std::to_string(shared_self);
    send(clientSocket, command.c_str(), command.size() + 1, 0);
    std::cout << "Connection Established..." << std::endl;

    // ------------------------------------------------------------------------- //
    while(1) {
        command = "";

        // reciving the digest 
        char received_digest[SHA1_DIGEST_SIZE];
        read(clientSocket, received_digest, SHA1_DIGEST_SIZE);
        
        // recieve and decrypt the ciphertext         
        read(clientSocket, buffer, 16);
        unsigned char ciphertext[16];
        unsigned char decryptedtext[16];
        Decrypt((unsigned char *)buffer, decryptedtext, str_priv);

        {
            char computed_digest[SHA1_DIGEST_SIZE];
            hmac_sha1(&str_priv, 16, decryptedtext, 16, computed_digest);
            if (memcmp(computed_digest, received_digest, SHA1_DIGEST_SIZE) != 0) {
                std::cout << "Bank: mismatched HMACs" << std::endl;
                return;
            }
        }


        std::istringstream iss(std::string((char*)decryptedtext));
        iss >> command;

        std::string response = "";

        if (command == "DEPOSIT") {
            double amount;
            iss >> amount;
            balance += amount;

            response += "Successful";
        } else if (command == "WITHDRAW") {
            double amount;
            iss >> amount;
            if (amount <= balance) {
                balance -= amount;
                response += "Successful";
            } else {
                response += "not enough";
            }
        } else if (command == "CHECK") {
            response += std::to_string(balance);
        } else if (command == "END") {
            response += "Ended";
        }
         else {
            response += "Not a command";
        }


        unsigned char response_temp[16];
        strncpy((char*)response_temp, response.c_str(), 16);
        {
            char digest[SHA1_DIGEST_SIZE];
            hmac_sha1(&str_priv, 16, response_temp, 16, digest);
            send(clientSocket, digest, SHA1_DIGEST_SIZE, 0);
        }
        Encrypt(response_temp, ciphertext, str_priv);
        send(clientSocket, ciphertext, 16, 0);

        if( command == "END" ) { return; }
    }
}

int main() {
    int server_fd, new_socket;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);
    srand((unsigned) time(NULL));

    // Creating socket file descriptor
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    // Forcefully attaching socket to the port
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    // Bind the socket to the port
    if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    // Listen for incoming connections
    if (listen(server_fd, 3) < 0) {
        perror("listen");
        exit(EXIT_FAILURE);
    }
    std::cout << "Bank Online." << std::endl;
    while (1) {
        if ((new_socket = accept(server_fd, (struct sockaddr*)&address, (socklen_t*)&addrlen)) < 0) {
            perror("accept");
            continue;
        }

        handleClient(new_socket);
        close(new_socket);
        std::cout << "Connection Terminated." << std::endl;
    }

    return 0;
}
