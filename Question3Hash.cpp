#include <iostream>
#include <string>
#include <openssl/sha.h>

std::string computeHash(const std::string& message) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, message.c_str(), message.length());
    SHA256_Final(hash, &sha256);

    std::string hashString;
    char hexChar[3];
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        sprintf(hexChar, "%02x", hash[i]);
        hashString += hexChar;
    }

    return hashString;
}

int main() {
    std::string message, originalMessage, receivedMessage, originalHash, receivedHash;

    // Sender
    std::cout << "Sender: Enter the message: ";
    std::getline(std::cin, message);
    originalMessage = message;
    originalHash = computeHash(message);

    // Receiver
    std::cout << "Receiver: Enter the received message: ";
    std::getline(std::cin, receivedMessage);
    std::cout << "Receiver: Enter the received hash value: ";
    std::getline(std::cin, receivedHash);

    // Simulating message integrity check
    std::string computedHash = computeHash(receivedMessage);
    bool isIntegrityIntact = (computedHash == receivedHash);

    std::cout << "\nOriginal Message: " << originalMessage << std::endl;
    std::cout << "Original Hash: " << originalHash << std::endl;
    std::cout << "Received Message: " << receivedMessage << std::endl;
    std::cout << "Received Hash: " << receivedHash << std::endl;
    std::cout << "Computed Hash: " << computedHash << std::endl;
    std::cout << "Integrity Intact: " << (isIntegrityIntact ? "Yes" : "No") << std::endl;

    return 0;
}
