#include <iostream>
#include <cmath>

// Function to calculate the modular exponentiation (base^exponent mod modulus)
unsigned long long modularExponentiation(unsigned long long base, unsigned long long exponent, unsigned long long modulus) {
    unsigned long long result = 1;
    base = base % modulus;

    while (exponent > 0) {
        if (exponent % 2 == 1) {
            result = (result * base) % modulus;
        }

        base = (base * base) % modulus;
        exponent = exponent / 2;
    }

    return result;
}

// Function to calculate the secret key
unsigned long long calculateSecretKey(unsigned long long p, unsigned long long g, unsigned long long privateKey) {
    return modularExponentiation(g, privateKey, p);
}

int main() {
    unsigned long long p, g, privateKey1, privateKey2;

    std::cout << "Enter the value of p: ";
    std::cin >> p;
    std::cout << "Enter the value of the primitive root of p: ";
    std::cin >> g;
    std::cout << "Enter the private key of user 1: ";
    std::cin >> privateKey1;
    std::cout << "Enter the private key of user 2: ";
    std::cin >> privateKey2;

    // Calculating the secret keys
    unsigned long long secretKey1 = calculateSecretKey(p, g, privateKey1);
    unsigned long long secretKey2 = calculateSecretKey(p, g, privateKey2);

    std::cout << "Secret Key of User 1: " << secretKey1 << std::endl;
    std::cout << "Secret Key of User 2: " << secretKey2 << std::endl;

    return 0;
}
