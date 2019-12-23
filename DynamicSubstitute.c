// Usage (encryption): DynamicSubstitute -C/c plaintext.file ciphertext.file password
// Usage (decryption): DynamicSubstitute -P/p ciphertext.file plaintext.file password
// Compiled on MacOS, Linux and *BSD.
// Talk is SO EASY, show you my GOD.
// Simple is beautiful.

#include <fcntl.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

// Each value of 256 numbers of key table that you can set randomly,
// yet you can freely to change to key table of 65536 numbers that you can set the value randomly,
// you can also freely to change to key table of 4294967296 numbers that you can set the value randomly,
// even if to change to key table of 18446744073709551616 numberes is no problem, which is only limited by the memory of your machine. WOW!
unsigned char aucKeyTable[256] = {
    0xc5, 0xc4, 0x1E, 0x92, 0x5B, 0xa5, 0xbD, 0xb3, 0xb6, 0x75, 0x2A, 0x66, 0xbC, 0x80, 0x17, 0x07, 0x03, 0xc6, 0x44, 0x40, 0xf3, 0xd3, 0x28, 0x72, 0x1D, 0xfB, 0x57, 0x05, 0xd9, 0x32, 0x5C, 0x68,
    0x9E, 0x45, 0xb4, 0x58, 0x96, 0x48, 0x70, 0xe1, 0xf0, 0x4C, 0x2F, 0x76, 0x46, 0x11, 0x55, 0xc9, 0xbA, 0xdA, 0xb7, 0x71, 0x61, 0x3C, 0xf8, 0x3F, 0x6E, 0xdE, 0x24, 0xd2, 0x7C, 0xa9, 0xe7, 0xa4,
    0xaD, 0x99, 0xe8, 0x8A, 0x0B, 0xbF, 0x38, 0x78, 0x9B, 0xaF, 0xb0, 0xb5, 0x7A, 0xc3, 0x63, 0xd4, 0xc1, 0x73, 0xf1, 0x7D, 0x95, 0x67, 0x2B, 0x65, 0x15, 0x5A, 0x02, 0x43, 0x08, 0x54, 0xfE, 0x22,
    0x6C, 0xe6, 0x18, 0xaB, 0x26, 0x14, 0x8E, 0x0A, 0x39, 0x60, 0x84, 0x52, 0xc8, 0x53, 0x8F, 0x0D, 0x47, 0x90, 0x2D, 0xe0, 0xcA, 0x7F, 0x4F, 0x19, 0x9F, 0x13, 0x37, 0x85, 0x16, 0x3A, 0x82, 0x1C,
    0xeB, 0x9A, 0xe5, 0x6D, 0x23, 0x97, 0x50, 0x6B, 0xcC, 0xcF, 0x9D, 0xc2, 0xeE, 0x79, 0x29, 0x62, 0x69, 0xb9, 0xa6, 0x5D, 0xdC, 0xa7, 0xdF, 0xeA, 0x12, 0x09, 0x31, 0x83, 0x4D, 0x4A, 0x51, 0x33,
    0x59, 0xb1, 0xa8, 0xdB, 0x7B, 0x01, 0x1A, 0x81, 0xe4, 0xf9, 0x2E, 0xf6, 0x27, 0x7E, 0xeC, 0x3E, 0x10, 0xaA, 0xd0, 0x20, 0x64, 0xfD, 0xf4, 0x6A, 0xf5, 0x49, 0xb2, 0x30, 0x93, 0xd7, 0xa0, 0xe2,
    0x06, 0x89, 0xaC, 0x8C, 0xd5, 0xd6, 0x5F, 0x2C, 0xaE, 0x77, 0x5E, 0x74, 0xa2, 0x4E, 0xa1, 0x0E, 0x8B, 0xd8, 0x41, 0xbE, 0x8D, 0x21, 0x0F, 0xf2, 0x1F, 0x25, 0x91, 0x42, 0x98, 0x87, 0x6F, 0xfC,
    0x35, 0xfF, 0x04, 0x1B, 0xb8, 0x9C, 0xd1, 0xa3, 0x4B, 0xcB, 0xf7, 0xeF, 0xc7, 0x3B, 0xe3, 0x94, 0x34, 0x36, 0xfA, 0x56, 0xbB, 0x0C, 0xdD, 0xeD, 0x88, 0x86, 0xcD, 0x3D, 0xc0, 0xe9, 0xcE, 0x00};

// key table convert the 32 * 8 = 256 bytes of data at a time in order to generate the random number of "JunTai" distribution
void JunTai(unsigned char *pucPassword, unsigned long ulPasswordLength)
{
    for(unsigned long k = 0; k < 32; ++k)
    {
        unsigned long *pulKeySwap1 = (unsigned long*)aucKeyTable, *pulKeySwap2 = (unsigned long*)aucKeyTable, ulKeyTemp, ulKeyIndex;

        ulKeyIndex = pucPassword[k % ulPasswordLength] % 32;

        ulKeyTemp = pulKeySwap1[k];

        pulKeySwap1[k] = pulKeySwap2[ulKeyIndex];

        pulKeySwap2[ulKeyIndex] = ulKeyTemp;
    }
}

// use the key table's value to change the password
void changePassword(unsigned char *pucPassword, unsigned long ulPasswordLength)
{
    for(unsigned long l = 0; l < ulPasswordLength; ++l)
    {
        pucPassword[l] = aucKeyTable[pucPassword[l]];
    }
}

void Encrypt(char *argv[])
{
// any password length
    unsigned long ulPasswordLength = -1;

// get the password length
    while(argv[2][++ulPasswordLength]);

    struct stat statFileSize;

    stat(argv[0], &statFileSize);

// get the plaintext file size
    unsigned long ulFileSize = statFileSize.st_size;

// allocate the storage space
    unsigned char *pucPlaintext = (unsigned char*)malloc(ulFileSize), *pucCiphertext = (unsigned char*)malloc(ulFileSize);

// open the plaintext file descriptor
    int iPlaintextOrCiphertextFD = open(argv[0], O_RDONLY, S_IRUSR | S_IWUSR);

// read data from the plaintext file
    read(iPlaintextOrCiphertextFD, pucPlaintext, ulFileSize);

    close(iPlaintextOrCiphertextFD);

// process the plaintext data
    for(unsigned long i = 0; i < ulFileSize; i += 256)
    {
        JunTai((unsigned char*)argv[2], ulPasswordLength);

// dynamic substitute the 256 bytes of plaintext data at a time
        for(unsigned long j = 0; j < 256 && i + j < ulFileSize; ++j)
        {
               pucCiphertext[i + j] = aucKeyTable[pucPlaintext[i + j]];
        }

        changePassword((unsigned char*)argv[2], ulPasswordLength);
    }

// open the ciphertext file descriptor
    iPlaintextOrCiphertextFD = open(argv[1], O_CREAT | O_WRONLY, S_IREAD | S_IWRITE);

// write data to the ciphertext file
    write(iPlaintextOrCiphertextFD, pucCiphertext, ulFileSize);

    close(iPlaintextOrCiphertextFD);

    free(pucCiphertext);

    free(pucPlaintext);
}

void Decrypt(char *argv[])
{
// any password length
    unsigned long ulPasswordLength = -1;

// get the password length
    while(argv[2][++ulPasswordLength]);

    struct stat statFileSize;

    stat(argv[0], &statFileSize);

// get the ciphertext file size
    unsigned long ulFileSize = statFileSize.st_size;

// allocate the storage space
    unsigned char *pucCiphertext = (unsigned char*)malloc(ulFileSize), *pucPlaintext = (unsigned char*)malloc(ulFileSize);

// open the ciphertext file descriptor
    int iCiphertextOrPlaintextFD = open(argv[0], O_RDONLY, S_IRUSR | S_IWUSR);

// read data from the ciphertext file
    read(iCiphertextOrPlaintextFD, pucCiphertext, ulFileSize);

    close(iCiphertextOrPlaintextFD);

// process the ciphertext data
    for(unsigned long i = 0; i < ulFileSize; i += 256)
    {
        JunTai((unsigned char*)argv[2], ulPasswordLength);

        unsigned char aucSubstituteTable[256];

// generate substitute table in order to transform data quickly
        for(unsigned long n = 0; n < 256; ++n)
        {
            aucSubstituteTable[aucKeyTable[n]] = n;
        }

// dynamic substitute the 256 bytes of ciphertext data at a time
        for(unsigned long j = 0; j < 256 && i + j < ulFileSize; ++j)
        {
               pucPlaintext[i + j] = aucSubstituteTable[pucCiphertext[i + j]];
        }

        changePassword((unsigned char*)argv[2], ulPasswordLength);
    }

// open the plaintext file descriptor
    iCiphertextOrPlaintextFD = open(argv[1], O_CREAT | O_WRONLY, S_IREAD | S_IWRITE);

// write data to the plaintext file
    write(iCiphertextOrPlaintextFD, pucPlaintext, ulFileSize);

    close(iCiphertextOrPlaintextFD);

    free(pucPlaintext);

    free(pucCiphertext);
}

int main(int argc, char *argv[])
{
    if(argv[1][0] == '-')
    {
        if(argv[1][1] == 'C' || argv[1][1] == 'c')
        {
            Encrypt(argv + 2);
        }
        else if(argv[1][1] == 'P' || argv[1][1] == 'p')
        {
            Decrypt(argv + 2);
        }
    }

    return 0;
}
