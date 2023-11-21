#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/rand.h>
#include <conio.h>
#include <windows.h>

#define SECRET_KEY_SIZE 32
#define SLEEP(seconds) Sleep((seconds) * 1000)
#define INTERVAL 15

unsigned char SECRET_KEY[SECRET_KEY_SIZE];
// Function to generate a random secret key.
void generateRandomKey() {
    RAND_bytes(SECRET_KEY, sizeof(SECRET_KEY));
    // The random key should be encrypted after generation and decrypted before using.
}

//the preocess of encrypting random secret key
int aes_encrypt(const unsigned char *plaintext, int plaintext_len,
                const unsigned char *key, const unsigned char *iv, unsigned char *ciphertext) {
    
    int result_length = 0;  // 0 indicates error, 1 indicates success
    EVP_CIPHER_CTX *ctx;
    int len, ciphertext_len;
    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL)
        goto err;

    if (!EVP_EncryptInit_ex2(ctx, EVP_aes_256_cbc(), key, iv, NULL))
        goto err;
    
    if (!EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        goto err;
    
    ciphertext_len = len;
    if (!EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        goto err;
    
    ciphertext_len += len;
    result_length = ciphertext_len;

err:
    EVP_CIPHER_CTX_free(ctx);
    return result_length;
}
//the process of decrypting random secret key
int aes_decrypt(const unsigned char *ciphertext, int ciphertext_len,
                const unsigned char *key, const unsigned char *iv, unsigned char *plaintext) {
    
    int result_length = 0;  // 0 indicates error, 1 indicates success
    EVP_CIPHER_CTX *ctx;
    int len, plaintext_len;
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        goto err;
    
    if (!EVP_DecryptInit_ex2(ctx, EVP_aes_256_cbc(), key, iv, NULL))
        goto err;
    
    if (!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        goto err;

    plaintext_len = len;
    if (!EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
        goto err;
    
    plaintext_len += len;
    result_length = plaintext_len;

err:
    EVP_CIPHER_CTX_free(ctx);
    return result_length;
}


// Function that uses the secret key of HMAC to generate a hash.
unsigned char *generateHash(unsigned long time_block, unsigned int *hash_length) {
    static unsigned char output[EVP_MAX_MD_SIZE];
    HMAC(
        EVP_sha256(),
        SECRET_KEY,
        SECRET_KEY_SIZE,
        (unsigned char *)&time_block,
        sizeof(time_block),
        output,  // The result of the hash
        hash_length
    );
    return output;
}

// Function to use the hash to compute TOTP.
unsigned int computeTOTP(const unsigned char *hash, int hash_length) {
    int offset = hash[hash_length - 1] & 0x0F;
    unsigned int code = (hash[offset] & 0x7f) << 24
                        | (hash[offset + 1] & 0xff) << 16
                        | (hash[offset + 2] & 0xff) << 8
                        | (hash[offset + 3] & 0xff);
    while (code >= 1000000) {
        code -= 1000000;
    }
    return code;
}

// Function to get TOTP.
unsigned int getTOTP() {
    unsigned long time_block = time(NULL) / INTERVAL;
    unsigned int hash_length;
    unsigned char *hash = generateHash(time_block, &hash_length);
    return computeTOTP(hash, hash_length);
}

// Function to display the TOTP.
void displayTOTP(unsigned int totp) {
    printf("Current TOTP: %06u\n", totp);
}

// Function to get user input within a specified interval.
int getInputWithinInterval(int interval) {
    int elapsedTime = 0;
    while (elapsedTime < interval) {
        if (_kbhit()) {
            int userInput;
            scanf("%u", &userInput);
            return userInput;
        }
        SLEEP(1);  // Pause for 1 second
        elapsedTime++;
    }
    return -1;  // Indicates timeout
}

int main() {
    generateRandomKey();
    unsigned char iv[EVP_CIPHER_iv_length(EVP_aes_256_cbc())]; // Initialization vector
    RAND_bytes(iv, sizeof(iv));
    unsigned char encrypted[1024];
    unsigned char decrypted[1024];
    int encrypted_len = aes_encrypt(SECRET_KEY, SECRET_KEY_SIZE, SECRET_KEY, iv, encrypted);//encryt secret key into  encrypted_len
    int decrypted_len = aes_decrypt(encrypted, encrypted_len, SECRET_KEY, iv, decrypted);   //decrypt encrypt_len to store secret key into decrypted_len
    unsigned int currentPassword = getTOTP();
    time_t startTime = time(NULL);
    time_t currentTime;
    int remainingTime;

    while (1) {
        currentTime = time(NULL);
        remainingTime = INTERVAL - (currentTime - startTime);
        

        if (remainingTime <= 0) {
            printf("Timeout! TOTP has been updated.\n");
            currentPassword = getTOTP();
            startTime = currentTime;
            continue;
        }
        displayTOTP(currentPassword);

        printf("Time remaining for TOTP update: %ds\n", remainingTime);
        printf("Please enter the TOTP: ");
        

        int userInput = getInputWithinInterval(remainingTime);

        if (userInput == -1) {
            printf("Time out! TOTP is refreshed.\n");
            continue;
        }

        if (userInput == currentPassword) {
            printf("Verification successful!\n");
            break;
        } else {
            printf("Incorrect TOTP.\n");
        }
    }
    memset(SECRET_KEY, 0, sizeof(SECRET_KEY)); //remove key to ensure security

    return 0;
}
