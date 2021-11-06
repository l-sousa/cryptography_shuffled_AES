#include <stdint.h>
#include <string.h>
#include <wmmintrin.h>
#include <stdio.h>
#include <unistd.h>
#include "aesni.h"
#include <openssl/ripemd.h>

//return 0 if no error
//1 if encryption failed
//2 if decryption failed
//3 if both failed
int main(int argc, char *argv[])
{
    char *K;  // Standard encryption key
    char *SK; // Shuffling key
    char *M;  // Plaintext message

    for (int i = 0; i < argc; i++)
    {
        if (strcmp(argv[i], "-k") == 0)
        {
            K = argv[i + 1];
            i++;
        }

        if (strcmp(argv[i], "-sk") == 0)
        {
            SK = argv[i + 1];
            i++;
        }
    }

    char ch;
    while (read(STDIN_FILENO, &ch, 1) > 0)
    {
        printf("char: %s \n", ch);
    }

    int8_t plain[] = {0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34};

    int8_t enc_key[] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
    int8_t cipher[] = {0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb, 0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32};

    int8_t computed_cipher[16];
    int8_t computed_plain[16];

    aes128_load_key(enc_key);
    aes128_enc(plain, computed_cipher);
    aes128_dec(cipher, computed_plain);

    int out = 0;

    if (memcmp(cipher, computed_cipher, sizeof(cipher)))
        out = 1;
    if (memcmp(plain, computed_plain, sizeof(plain)))
        out |= 2;

    printf("Out: %d \n", out);

    return 0;
}
