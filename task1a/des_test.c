/*********************************************************************
* Filename:   des_test.c
* Author:     Brad Conte (brad AT bradconte.com)
* Copyright:
* Disclaimer: This code is presented "as is" without any guarantees.
* Details:    Performs known-answer tests on the corresponding DES
	          implementation. These tests do not encompass the full
	          range of available test vectors, however, if the tests
	          pass it is very, very likely that the code is correct
	          and was compiled properly. This code also serves as
	          example usage of the functions.
*********************************************************************/

/*************************** HEADER FILES ***************************/
#include <stdio.h>
#include <memory.h>
#include "des.h"

/*********************** FUNCTION DEFINITIONS ***********************/
int des_test(int rounds)
{
	BYTE pt1[DES_BLOCK_SIZE] = {0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xE7};
	BYTE pt2[DES_BLOCK_SIZE] = {0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF};

	BYTE key1[DES_BLOCK_SIZE] = {0x01,0x23,0x45,0xFF,0x89,0xAB,0xCD,0xEF};
	BYTE key2[DES_BLOCK_SIZE] = {0x13,0x34,0x57,0x79,0x9B,0xBC,0xDF,0xF1};

	BYTE ct1[DES_BLOCK_SIZE];
	BYTE ct2[DES_BLOCK_SIZE];
	BYTE decrypted_ct1[DES_BLOCK_SIZE];
	BYTE decrypted_ct2[DES_BLOCK_SIZE];

	BYTE schedule[16][6];
	int pass = 1;
    int i = 0;

    printf("Plaintext 1: \n     ");
    for(i = 0; i<DES_BLOCK_SIZE;i++)
    {
    	printf(" %02X",pt1[i]);
    }
    printf("\n");

	des_key_setup(key1, schedule, DES_ENCRYPT,rounds);
	des_crypt(pt1, ct1, schedule,rounds);

	printf("Ciphertext 1: \n     ");
	for(i = 0; i<DES_BLOCK_SIZE;i++)
	{
		printf(" %02X",ct1[i]);
	}
    printf("\n");

	des_key_setup(key1, schedule, DES_DECRYPT,rounds);
	des_crypt(ct1, decrypted_ct1, schedule,rounds);

	printf("Decrypted Text 1: \n     ");
	for(i = 0; i<DES_BLOCK_SIZE;i++)
	{
		printf(" %02X",decrypted_ct1[i]);
	}
	printf("\n");

	pass = pass && !memcmp(pt1, decrypted_ct1, DES_BLOCK_SIZE);

	printf("Plaintext 2: \n     ");
	for(i = 0; i<DES_BLOCK_SIZE;i++)
	{
	   	printf(" %02X",pt2[i]);
	}
	printf("\n");

	des_key_setup(key2, schedule, DES_ENCRYPT,rounds);
	des_crypt(pt2, ct2, schedule,rounds);

	printf("Ciphertext 2: \n     ");
	for(i = 0; i<DES_BLOCK_SIZE;i++)
	{
		printf(" %02X",ct2[i]);
	}
	printf("\n");

	des_key_setup(key2, schedule, DES_DECRYPT,rounds);
	des_crypt(ct2, decrypted_ct2, schedule,rounds);

	printf("Decrypted Text 2: \n     ");
	for(i = 0; i<DES_BLOCK_SIZE;i++)
	{
		printf(" %02X",decrypted_ct2[i]);
	}
	printf("\n");
	pass = pass && !memcmp(pt2, decrypted_ct2, DES_BLOCK_SIZE);

	return(pass);
}

int main()
{
	printf("DES test with 3 rounds: %s\n\n", des_test(3) ? "SUCCEEDED" : "FAILED");
	printf("DES test with 5 rounds: %s\n\n", des_test(5) ? "SUCCEEDED" : "FAILED");
	printf("DES test with 7 rounds: %s\n\n", des_test(7) ? "SUCCEEDED" : "FAILED");

	return(0);
}
