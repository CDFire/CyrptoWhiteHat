#include <iostream>
#include <stdio.h>
#include <cstdint>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>

#include "config.h"
#include "sha1.h"
#include "hmac_sha1.h"
#include "powmod.h"
#include "aes.h"

int main() {
    srand((unsigned) time(NULL));
    int sock = 0;
    struct sockaddr_in serv_addr;
    char buffer[1024] = {0};

    std::cout << "ATM Online.\n";

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        std::cout << "Socket error" << std::endl;
        return -1;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    if (inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0) {
        std::cout << "Invalid address" << std::endl;
        return -1;
    }

    if (connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        std::cout << "Connection Failed" << std::endl;
        return -1;
    }

    // getting original P and G values, alongside the random private key
    std::uintmax_t priv_key = rand();
    std::uintmax_t shared_self = powmod(DHKE_G, priv_key, DHKE_P);
    std::string command = std::to_string(shared_self);
    // send over to host the first step of dfhlm
    send(sock, command.c_str(), command.length() + 1, 0);
    // read in the host's side of the first step and calc the shared priv key
    read(sock, buffer, 1024);
    std::uintmax_t shared_other = std::stoull(buffer);
    std::uintmax_t shared_private = powmod(shared_other, priv_key, DHKE_P);
    unsigned char str_priv[16];
    memcpy(str_priv, &shared_private, 8); 
    memcpy(str_priv+8, &shared_private, 8); 

    std::cout << "Connection Established..."<< std::endl;

    // ------------------------------------------------------------------------- //
    while(1){
        command = "";
        std::cout << "Enter command (DEPOSIT, WITHDRAW, CHECK, END): ";
        std::getline(std::cin, command);

        // compute and send digest
        {
            char digest[SHA1_DIGEST_SIZE];
            unsigned char temp[16];
            strncpy((char*)temp, command.c_str(), 16);
            hmac_sha1(&str_priv, 16, temp, 16, digest);
            send(sock, digest, SHA1_DIGEST_SIZE, 0);   
        }
        
        unsigned char ciphertext[16];
        unsigned char decryptedtext[16];
        unsigned char command_temp[16];
        strncpy((char*)command_temp, command.c_str(), 16);

        // encrypting the command and sending it over as ciphertext
        Encrypt(command_temp, ciphertext, str_priv);
        send(sock, ciphertext, 16, 0);

        char received_digest[SHA1_DIGEST_SIZE];
        // reciving digest
        read(sock, received_digest, SHA1_DIGEST_SIZE);

        // reciving and decrypting buffer
        read(sock, buffer, 1024);
        Decrypt((unsigned char *)buffer, decryptedtext, str_priv);
        {
            char computed_digest[SHA1_DIGEST_SIZE];
            hmac_sha1(&str_priv, 16, decryptedtext, 16, computed_digest);

            if (memcmp(computed_digest, received_digest, SHA1_DIGEST_SIZE) != 0) {
                std::cout << "ATM: mismatched HMACs" << std::endl;
                return EXIT_FAILURE;
            }
        }

        std::cout << decryptedtext << std::endl;
        if( command == "END" ) { break; }
    }

    close(sock);
    return 0;
}
