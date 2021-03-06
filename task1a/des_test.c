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

void print_plaintexts(int number_of_plains, const BYTE text_array[][DES_BLOCK_SIZE])
{
	int j, i;
	printf("The random plaintexts: \n");
	for(j=0;j<number_of_plains;j++)
	{
		printf("%d:\t", (j+1));
		for(i=0;i<DES_BLOCK_SIZE;i++)
		{
			printf(" %02X", text_array[j][i]);
		}
		printf("\n");
	}
}

void create_plaintexts(BYTE iv[], int number_of_plains, BYTE plaintexts[][DES_BLOCK_SIZE])
{
   BYTE key[DES_BLOCK_SIZE];
   BYTE state[DES_BLOCK_SIZE];
   BYTE random_plaintext[DES_BLOCK_SIZE];
   int i = 0;
   int j = 0;
   printf("Creating %d plaintexts...\n", number_of_plains);
   for(i = 0; i < DES_BLOCK_SIZE; i++)
   {
	   key[i] = iv[i];
   }

   for(j = 0; j < number_of_plains; j++)
   {
   	   rand_plaintext(key, state, random_plaintext);

   	   for(i = 0; i<DES_BLOCK_SIZE;i++)
	   {
   		   key[i] = state[i];
   		   plaintexts[j][i] = random_plaintext[i];
	   }
   }
}

int three_round_attack()
{
	printf("\nStarting 3 round attack...\n");
	float bias;
	int rounds = 3;
	unsigned int count_T0 = 0;
	unsigned int count_T1 = 0;
	int number_of_plaintexts = 30;
	BYTE plaintext_array[number_of_plaintexts][DES_BLOCK_SIZE];
	BYTE iv[DES_BLOCK_SIZE] = {0x03,0x53,0xE1,0x7D,0xA8,0x9B,0x00,0x22}; //for the random plaintext generation
	BYTE enc_key[DES_BLOCK_SIZE] = {0x00,0x87,0xC3,0x33,0x74,0xA1,0xD1,0x23}; //the encryption key
	BYTE key_schedule[rounds][6];

	//for verifying the result
	int i;
	BYTE subkey1[6];
    BYTE subkey3[6];

	create_plaintexts(iv, number_of_plaintexts, plaintext_array);
	//print_plaintexts(number_of_plaintexts, plaintext_array);

	des_key_setup(enc_key, key_schedule, DES_ENCRYPT,rounds);
	algorithm1(plaintext_array, key_schedule, &count_T0, &count_T1, number_of_plaintexts, rounds, key_schedule[0]);
	if((count_T0 == -1)&&(count_T1 == -1))
	{
		printf("ERROR: algorithm 1 only works with 3,5 or 7 rounds!\n");
		return 1;
	}
	if(count_T0 > count_T1)
	{
		bias = (float)count_T0 / (float)number_of_plaintexts;
		printf("RESULT: The right side (K1[22] XOR K3[22]) is %01X!\n \tBias: %f\n",0x00,bias);
	}
	else
	{
		bias = (float)count_T1 / (float)number_of_plaintexts;
		printf("RESULT: The right side (K1[22] XOR K3[22]) is %01X!\n \tBias: %f\n",0x01,bias);
	}
	printf("\tT0: %d - T1: %d\n", count_T0, count_T1);

	for(i = 0; i<6; i++)
	{
		subkey1[i] = key_schedule[0][i];
		subkey3[i] = key_schedule[2][i];
	}
	BYTE K1_22 = (subkey1[3] >> 6) & 0x01;
	BYTE K3_22 = (subkey3[3] >> 6) & 0x01;

	printf("\tActual result of the right side: %01X\n", K1_22^K3_22);

	return 0;

}

int five_round_attack()
{
	printf("\nStarting 5 round attack...\n");
	float bias;
	int rounds = 5;
	unsigned int count_T0 = 0;
	unsigned int count_T1 = 0;
	int number_of_plaintexts = 3000;
	BYTE plaintext_array[number_of_plaintexts][DES_BLOCK_SIZE];
	BYTE iv[DES_BLOCK_SIZE] = {0x43,0x85,0xE3,0xDD,0x3F,0x00,0xFF,0x63}; //for the random plaintext generation
	BYTE enc_key[DES_BLOCK_SIZE] = {0x5F,0xD1,0xDC,0x76,0x87,0xB4,0xBF,0x12}; //the encryption key
	BYTE key_schedule[rounds][6];

	//needed for verifying the result
	int i;
	BYTE subkey1[6];
	BYTE subkey2[6];
	BYTE subkey4[6];
	BYTE subkey5[6];

	create_plaintexts(iv, number_of_plaintexts, plaintext_array);
	//print_plaintexts(number_of_plaintexts, plaintext_array);

	des_key_setup(enc_key, key_schedule, DES_ENCRYPT,rounds);
	algorithm1(plaintext_array, key_schedule, &count_T0, &count_T1, number_of_plaintexts, rounds, key_schedule[0]);
	if((count_T0 == -1)&&(count_T1 == -1))
	{
		printf("ERROR: algorithm 1 only works with 3,5 or 7 rounds!\n");
		return 1;
	}
	if(count_T0 > count_T1)
	{
		bias = (float)count_T0 / (float)number_of_plaintexts;
		printf("RESULT: The right side (K1,5[42,43,45,46] XOR K2,4[22]) is %01X!\n \tBias: %f\n",0x00,bias);
	}
	else
	{
		bias = (float)count_T1 / (float)number_of_plaintexts;
		printf("RESULT: The right side (K1,5[42,43,45,46] XOR K2,4[22]) is %01X!\n \tBias: %f\n",0x01,bias);
	}
	printf("\tT0: %d - T1: %d\n", count_T0, count_T1);

	for(i = 0; i<6; i++)
	{
		subkey1[i] = key_schedule[0][i];
		subkey2[i] = key_schedule[1][i];
		subkey4[i] = key_schedule[3][i];
		subkey5[i] = key_schedule[4][i];
	}

	BYTE K1_42 = (subkey1[0] >> 2) & 0x01;
	BYTE K1_43 = (subkey1[0] >> 3) & 0x01;
	BYTE K1_45 = (subkey1[0] >> 5) & 0x01;
	BYTE K1_46 = (subkey1[0] >> 6) & 0x01;
	BYTE K5_42 = (subkey5[0] >> 2) & 0x01;
	BYTE K5_43 = (subkey5[0] >> 3) & 0x01;
	BYTE K5_45 = (subkey5[0] >> 5) & 0x01;
	BYTE K5_46 = (subkey5[0] >> 6) & 0x01;
	BYTE K2_22 = (subkey2[3] >> 6) & 0x01;
	BYTE K4_22 = (subkey4[3] >> 6) & 0x01;
	BYTE result = K1_42 ^ K1_43 ^ K1_45 ^ K1_46 ^ K5_42 ^ K5_43 ^ K5_45 ^ K5_46 ^ K2_22 ^ K4_22;
	printf("\tActual result of the right side: %01X\n", result);
	return 0;
}

int seven_round_attack()
{
	printf("\nStarting 7 round attack...\n");
	float bias;
	int rounds = 7;
	unsigned int count_T0 = 0;
	unsigned int count_T1 = 0;
	int number_of_plaintexts = 300000;
	BYTE plaintext_array[number_of_plaintexts][DES_BLOCK_SIZE];
	BYTE iv[DES_BLOCK_SIZE] = {0x07,0x22,0xEE,0xA2,0x7F,0x60,0x99,0x1A}; //for the random plaintext generation
	BYTE enc_key[DES_BLOCK_SIZE] = {0x40,0x31,0xEC,0xC4,0xA8,0xF6,0x92,0x88}; //the encryption key
	BYTE key_schedule[rounds][6];

	//just for checking the results
	int i;
	BYTE subkey1[6];
	BYTE subkey3[6];
	BYTE subkey4[6];
	BYTE subkey5[6];
	BYTE subkey7[6];

	create_plaintexts(iv, number_of_plaintexts, plaintext_array);
	//print_plaintexts(number_of_plaintexts, plaintext_array);

	des_key_setup(enc_key, key_schedule, DES_ENCRYPT,rounds);
	algorithm1(plaintext_array, key_schedule, &count_T0, &count_T1, number_of_plaintexts, rounds, key_schedule[0]);
	if((count_T0 == -1)&&(count_T1 == -1))
	{
		printf("ERROR: algorithm 1 only works with 3,5 or 7 rounds!\n");
		return 1;
	}
	if(count_T0 > count_T1)
	{
		bias = (float)count_T0 / (float)number_of_plaintexts;
		printf("RESULT: The right side (K1[19,23] XOR K3,5,7[22] XOR K4[44]) is %01X!\n \tBias: %f\n",0x00,bias);
	}
	else
	{
		bias = (float)count_T1 / (float)number_of_plaintexts;
		printf("RESULT: The right side (K1[19,23] XOR K3,5,7[22] XOR K4[44]) is %01X!\n \tBias: %f\n",0x01,bias);
	}
	printf("\tT0: %d - T1: %d\n", count_T0, count_T1);

	//verifying the result
	for(i = 0; i < 6; i++)
	{
		subkey1[i] = key_schedule[0][i];
		subkey3[i] = key_schedule[2][i];
		subkey4[i] = key_schedule[3][i];
		subkey5[i] = key_schedule[4][i];
		subkey7[i] = key_schedule[6][i];
	}
	BYTE K1_19 = (subkey1[3] >> 3) & 0x01;
	BYTE K1_23 = (subkey1[3] >> 7) & 0x01;
	BYTE K3_22 = (subkey3[3] >> 6) & 0x01;
	BYTE K5_22 = (subkey5[3] >> 6) & 0x01;
	BYTE K7_22 = (subkey7[3] >> 6) & 0x01;
	BYTE K4_44 = (subkey4[0] >> 4) & 0x01;
	BYTE result = K1_19 ^ K1_23 ^ K3_22 ^ K5_22 ^ K7_22 ^ K4_44;
	printf("\tActual result of the right side: %01X\n", result);

	return 0;
}

int eight_round_attack()
{
	printf("\nStarting 8 round attack...\n");
	float bias;
	int key_guesses = 64; //6 bit of the K8
	int number_of_plaintexts = 1040000; //~2^20
	unsigned int count_T0[key_guesses];
	unsigned int count_T1[key_guesses];
	int correct_guess;
	int i=0;
	BYTE guessedkey8bits[6];
	BYTE keyschedule[8][6];
	BYTE subkey8[6];
	BYTE plaintext_array[number_of_plaintexts][DES_BLOCK_SIZE];
	BYTE iv[DES_BLOCK_SIZE] = {0x08,0x55,0xA2,0x78,0x87,0xDD,0x2C,0xBC}; //for the random plaintext generation
	BYTE enc_key[DES_BLOCK_SIZE] = {0x96,0x4B,0xEA,0x19,0x50,0xF0,0x1F,0x36}; //the encryption key

	//just for checking the results
	BYTE subkey1[6];
	BYTE subkey3[6];
	BYTE subkey4[6];
	BYTE subkey5[6];
	BYTE subkey7[6];

	create_plaintexts(iv, number_of_plaintexts, plaintext_array);
	//print_plaintexts(number_of_plaintexts, plaintext_array);

	des_key_setup(enc_key, keyschedule, DES_ENCRYPT, 8);

	printf("Guessing the key...\n");
    correct_guess = algorithm2(plaintext_array, keyschedule, guessedkey8bits, count_T0, count_T1, number_of_plaintexts, key_guesses);

    printf("RESULT: Guessed bits 42-47 of the SubKey K8:\t%01X %01X %01X %01X %01X %01X\n", guessedkey8bits[0], guessedkey8bits[1], guessedkey8bits[2],
    		guessedkey8bits[3], guessedkey8bits[4], guessedkey8bits[5]);

    for(i = 0; i < 6; i++)
    {
    	subkey8[i] = keyschedule[7][i];
    }
    printf("\tActual bits 42-47 of the SubKey K8: \t");
    for(i = 0; i < 6; i++)
    {
    	guessedkey8bits[i] = (subkey8[0] >> (2+i)) & 0x01;
    	printf("%01X ",guessedkey8bits[i]);
    }
    printf("\n");

    if(count_T0[correct_guess] > count_T1[correct_guess])
    {
    	bias = (float)count_T0[correct_guess] / (float)number_of_plaintexts;
    	printf("RESULT: The right side (K1[19,23] XOR K3,5,7[22] XOR K4[44]) is %01X!\n \tBias: %f\n",0x00,bias);
    }
    else
    {
    	bias = (float)count_T1[correct_guess] / (float)number_of_plaintexts;
    	printf("RESULT: The right side (K1[19,23] XOR K3,5,7[22] XOR K4[44]) is %01X!\n \tBias: %f\n",0x01,bias);
    }
    printf("\tT0: %d - T1: %d\n", count_T0[correct_guess], count_T1[correct_guess]);

    //verifying the result
    	for(i = 0; i < 6; i++)
    	{
    		subkey1[i] = keyschedule[0][i];
    		subkey3[i] = keyschedule[2][i];
    		subkey4[i] = keyschedule[3][i];
    		subkey5[i] = keyschedule[4][i];
    		subkey7[i] = keyschedule[6][i];
    	}
    	BYTE K1_19 = (subkey1[3] >> 3) & 0x01;
    	BYTE K1_23 = (subkey1[3] >> 7) & 0x01;
    	BYTE K3_22 = (subkey3[3] >> 6) & 0x01;
    	BYTE K5_22 = (subkey5[3] >> 6) & 0x01;
    	BYTE K7_22 = (subkey7[3] >> 6) & 0x01;
    	BYTE K4_44 = (subkey4[0] >> 4) & 0x01;
    	BYTE result = K1_19 ^ K1_23 ^ K3_22 ^ K5_22 ^ K7_22 ^ K4_44;
    	printf("\tActual result of the right side: %01X\n", result);

	return 0;
}

int main()
{
	//for checking the correctness of the DES implementation
	//printf("DES test with 3 rounds: %s\n\n", des_test(3) ? "SUCCEEDED" : "FAILED");
	//printf("DES test with 5 rounds: %s\n\n", des_test(5) ? "SUCCEEDED" : "FAILED");
	//printf("DES test with 7 rounds: %s\n\n", des_test(7) ? "SUCCEEDED" : "FAILED");

    //3 ROUND ATTACK
    three_round_attack();
	//5 ROUND ATTACK
    five_round_attack();
    //7 ROUND ATTACK
    seven_round_attack();
    //8 ROUND ATTACK
    eight_round_attack();

	return(0);
}
