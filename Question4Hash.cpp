#include <iostream>
#include <fstream>
#include <string>
#include <unordered_map>
#include <openssl/sha.h>

std::unordered_map<std::string, std::string> readPasswordFile(const std::string& filename) {
    std::unordered_map<std::string, std::string> passwords;
    std::ifstream file(filename);
    if (!file.is_open()) {
        std::cerr << "Error opening file: " << filename << std::endl;
        return passwords;
    }

    std::string username;
    std::string password;
    while (file >> username >> password) {
        passwords[username] = password;
    }

    file.close();
    return passwords;
}

void writePasswordFile(const std::string& filename, const std::unordered_map<std::string, std::string>& passwords) {
    std::ofstream file(filename);
    if (!file.is_open()) {
        std::cerr << "Error opening file: " << filename << std::endl;
        return;
    }

    for (const auto& entry : passwords) {
        file << entry.first << " " << entry.second << std::endl;
    }

    file.close();
}

std::string computeHash(const std::string& password, const std::string& salt = "") {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, salt.c_str(), salt.length());
    SHA256_Update(&sha256, password.c_str(), password.length());
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
    std::string passwordFile = "passwords.txt";
    std::string saltFile = "salt.txt";

    // Creating a password file (a)
    std::unordered_map<std::string, std::string> passwords = {
        {"user1", "password1"},
        {"user2", "password2"},
        {"user3", "password3"},
        {"user4", "password4"},
        {"user5", "password5"},
        {"user6", "password6"},
        {"user7", "password7"},
        {"user8", "password8"},
        {"user9", "password9"},
        {"user10", "password10"}
    };
    writePasswordFile(passwordFile, passwords);
    std::cout << "Password file created." << std::endl;

    // Identification using passwords (a)
    std::string username, password;
    std::cout << "Enter username: ";
    std::cin >> username;
    std::cout << "Enter password: ";
    std::cin >> password;

    std::unordered_map<std::string, std::string> storedPasswords = readPasswordFile(passwordFile);
    if (storedPasswords.count(username) && storedPasswords[username] == password) {
        std::cout << "Authentication successful!" << std::endl;
    } else {
        std::cout << "Authentication failed!" << std::endl;
    }

    // Modifying to store hash values of passwords (b)
    std::unordered_map<std::string, std::string> hashedPasswords;
    for (const auto& entry : passwords) {
        std::string hashedPassword = computeHash(entry.second);
        hashedPasswords[entry.first] = hashedPassword;
    }
    writePasswordFile(passwordFile, hashedPasswords);
    std::cout << "Password file modified to store hash values." << std::endl;

    // Optional: Using salt (c)
    std::string salt;
    std::cout << "Enter salt: ";
    std::cin >> salt;

    std::unordered_map<std::string, std::string> saltedHashedPasswords;
    for (const auto& entry : passwords) {
        std::string hashedPassword = computeHash(entry.second, salt);
        saltedHashedPasswords[entry.first] = hashedPassword;
    }
    writePasswordFile(passwordFile, saltedHashedPasswords);
    std::cout << "Password file modified to store salted hash values." << std::endl;

    return 0;
}
