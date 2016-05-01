/*********************************************************************
* Filename:   des.h
* Author:     Brad Conte (brad AT bradconte.com)
* Copyright:
* Disclaimer: This code is presented "as is" without any guarantees.
* Details:    Defines the API for the corresponding DES implementation.
              Note that encryption and decryption are defined by how
              the key setup is performed, the actual en/de-cryption is
              performed by the same function.
*********************************************************************/

#ifndef DES_H
#define DESH

/*************************** HEADER FILES ***************************/
#include <stddef.h>

/****************************** MACROS ******************************/
#define DES_BLOCK_SIZE 8                // DES operates on 8 bytes at a time

/**************************** DATA TYPES ****************************/
typedef unsigned char BYTE;             // 8-bit byte
typedef unsigned int  WORD;             // 32-bit word, change to "long" for 16-bit machines

typedef enum {
	DES_ENCRYPT,
	DES_DECRYPT
} DES_MODE;

/*********************** FUNCTION DECLARATIONS **********************/
void des_key_setup(const BYTE key[], BYTE schedule[][6], DES_MODE mode, const int rounds);
void des_crypt(const BYTE in[], BYTE out[], const BYTE key[][6], const int rounds);
void rand_plaintext(const BYTE curr_state[], BYTE next_state[], BYTE output_plaintext[]);
void algorithm1(const BYTE plain[][DES_BLOCK_SIZE],const BYTE key[][6], unsigned int* count_T0, unsigned int* count_T1, int number_of_plains,int rounds, const BYTE keyguess[]);
int algorithm2(const BYTE plain[][DES_BLOCK_SIZE], const BYTE keyschedule[][6], BYTE key8bits[], unsigned int count_T0[], unsigned int count_T1[], int number_of_plains, int keyguesses);

#endif   // DES_H
