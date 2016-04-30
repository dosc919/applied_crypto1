/*********************************************************************
* Filename:   aes_test.c
* Author:     Brad Conte (brad AT bradconte.com)
* Copyright:
* Disclaimer: This code is presented "as is" without any guarantees.
* Details:    Performs known-answer tests on the corresponding AES
              implementation. These tests do not encompass the full
              range of available test vectors and are not sufficient
              for FIPS-140 certification. However, if the tests pass
              it is very, very likely that the code is correct and was
              compiled properly. This code also serves as
	          example usage of the functions.
*********************************************************************/

/*************************** HEADER FILES ***************************/
#include <stdio.h>
#include <memory.h>
#include "aes.h"

/*********************** FUNCTION DEFINITIONS ***********************/
#define KE_ROTWORD(x) (((x) << 8) | ((x) >> 24))

void print_hex(BYTE str[], int len)
{
	int idx;

	for(idx = 0; idx < len; idx++)
		printf("%02x", str[idx]);
}

void copyLambdaToState(BYTE lambda[16], BYTE state[4][4])
{
	int i;
	for(i = 0; i < 16; ++i)
		state[i % 4][i / 4] = lambda[i];
}

void cloneState(BYTE from_state[4][4], BYTE to_state[4][4])
{
	int i;
	int j;
	for(i = 0; i < 4; ++i)
		for(j = 0; j < 4; ++j)
			to_state[i][j] = from_state[i][j];
}

int do4RoundAttack()
{
	BYTE message1[16] = "\0breaking stuff!";
	BYTE message2[16] = "\0praise the sun!";
	BYTE lambda[2][256][16];
	BYTE lambda_enc[2][256][16];
	BYTE key[16] = {0x60,0x6d,0xeb,0x10,0x15,0xca,0x71,0xbe,0x2c,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81};
	BYTE guessed_round_key[16];
	WORD key_schedule[44];
	int i;
	int j;

	//initialize lambda sets
	for(i = 0; i < 256; ++i)
		for(j = 0; j < 16; ++j)
			if(j == 0)
			{
				lambda[0][i][j] = i;
				lambda[1][i][j] = i;
			}
			else
			{
				lambda[0][i][j] = message1[j];
				lambda[1][i][j] = message2[j];
			}

	aes_key_setup(key, key_schedule, 128);

	//get ciphertext for lambda sets
	for(i = 0; i < 256; ++i)
	{
		aes_encrypt(lambda[0][i], lambda_enc[0][i], key_schedule, 4);
		aes_encrypt(lambda[1][i], lambda_enc[1][i], key_schedule, 4);
	}

	BYTE sum = 0;
	int k;
	int l;
	BYTE tmp_state[4][4];
	for(i = 0; i < 16; ++i)
	{
		//try out all possible values for round-key-byte
		for(j = 0; j < 256; ++j)
		{
			//for all lambda sets
			for(l = 0; l < 2; ++l)
			{
				//check balance property
				for(k = 0; k < 256; ++k)
				{
					copyLambdaToState(lambda_enc[l][k], tmp_state);
					tmp_state[i % 4][i / 4] ^= j; //apply addRoundKey
					InvShiftRows(tmp_state);
					InvSubBytes(tmp_state);
					//consider in index that the guessed round-key-byte is shifted with InvShiftRows
					sum ^= tmp_state[i % 4][((i % 4) + i / 4) % 4];
				}
				if(sum != 0)
					break;
			}
			if(sum == 0)
				guessed_round_key[i] = j;
			else
				sum = 0;
		}
	}

	WORD guessed_key[4];
	WORD Rcon[]={0x01000000,0x02000000,0x04000000,0x08000000,0x10000000,
		         0x20000000,0x40000000,0x80000000,0x1b000000,0x36000000,
			     0x6c000000,0xd8000000,0xab000000,0x4d000000,0x9a000000};

	//calculate key from round-key
	for(i = 0; i < 4; ++i)
	{
		guessed_key[i] = guessed_round_key[4 * i] << 24;
		guessed_key[i] ^= guessed_round_key[4 * i + 1] << 16;
		guessed_key[i] ^= guessed_round_key[4 * i + 2] << 8;
		guessed_key[i] ^= guessed_round_key[4 * i + 3];
	}
	for(i = 4; i > 0; --i)
	{
		guessed_key[3] = guessed_key[2] ^ guessed_key[3];
		guessed_key[2] = guessed_key[1] ^ guessed_key[2];
		guessed_key[1] = guessed_key[0] ^ guessed_key[1];
		guessed_key[0] = guessed_key[0] ^ SubWord(KE_ROTWORD(guessed_key[3])) ^ Rcon[i - 1];
	}

	BYTE guessed_key_bytes[16];
	for(i = 0; i < 16; ++i)
		guessed_key_bytes[i] = guessed_key[i/4] >> (3 - i % 4) * 8;


	return !memcmp(key, guessed_key_bytes, 16);
}

int do5RoundAttack()
{
	BYTE message1[16] = "\0breaking stuff!";
	BYTE message2[16] = "\0praise the sun!";
	BYTE message3[16] = "\096,5% more woob";
	BYTE message4[16] = "\0may the fourth.";
	BYTE message5[16] = "\0good eye might.";
	BYTE lambda[5][256][16];
	BYTE lambda_enc[5][256][16];
	BYTE key[16] = {0x60,0x3d,0xeb,0x10,0x15,0xba,0x71,0xbe,0x2b,0x73,0xae,0xf9,0x85,0x7d,0x77,0x81};
	WORD key_schedule[44];
	int i;
	unsigned int j;

	//initialize lambda sets
	for(i = 0; i < 256; ++i)
		for(j = 0; j < 16; ++j)
			if(j == 0)
			{
				lambda[0][i][j] = i;
				lambda[1][i][j] = i;
				lambda[2][i][j] = i;
				lambda[3][i][j] = i;
				lambda[4][i][j] = i;
			}
			else
			{
				lambda[0][i][j] = message1[j];
				lambda[1][i][j] = message2[j];
				lambda[2][i][j] = message3[j];
				lambda[3][i][j] = message4[j];
				lambda[4][i][j] = message5[j];
			}

	aes_key_setup(key, key_schedule, 128);

	//get ciphertext for lambda sets
	for(i = 0; i < 256; ++i)
	{
		aes_encrypt(lambda[0][i], lambda_enc[0][i], key_schedule, 5);
		aes_encrypt(lambda[1][i], lambda_enc[1][i], key_schedule, 5);
		aes_encrypt(lambda[2][i], lambda_enc[2][i], key_schedule, 5);
		aes_encrypt(lambda[3][i], lambda_enc[3][i], key_schedule, 5);
		aes_encrypt(lambda[4][i], lambda_enc[4][i], key_schedule, 5);
	}

	int l;
	int k;
	int found;
	BYTE sum = 0;
	BYTE tmp_state_r4[4][4];
	BYTE guessed_round_key[16];
	BYTE round5_key_p1;
	BYTE round5_key_p2;
	int round4_key;
	BYTE lambda_r4[5][256][4][4];

	//fix half of the guessed key
	for(i = 8; i < 16; ++i)
		guessed_round_key[i] = key_schedule[20 + i / 4] >> (3 - i % 4) * 8;

	for(i = 0; i < 4; ++i)
	{
		found = 0;
		//try out all possible values for round-key-byte (2^16)
		for(j = 0; j <= 0xFFFF; ++j)
		{
			round5_key_p1 = j;
			round5_key_p2 = j >> 8;

			//for all lambda sets
			for(l = 0; l < 5; ++l)
			{
				//calculate state of round4
				for(k = 0; k < 256; ++k)
				{
					copyLambdaToState(lambda_enc[l][k], lambda_r4[l][k]);
					lambda_r4[l][k][i][0] ^= round5_key_p1;
					lambda_r4[l][k][(i + 3) % 4][1] ^= round5_key_p2;
					lambda_r4[l][k][(i + 2) % 4][2] ^= guessed_round_key[8 + (i + 2) % 4];
					lambda_r4[l][k][(i + 1) % 4][3] ^= guessed_round_key[12 + (i + 1) % 4];
					InvShiftRows(lambda_r4[l][k]);
					InvSubBytes(lambda_r4[l][k]);
				}
			}
			//check if a key for round 4 can be found
			for(round4_key = 0; round4_key < 256; ++round4_key)
			{
				//for all lambda sets
				for(l = 0; l < 5; ++l)
				{
					//check balance property
					for(k = 0; k < 256; ++k)
					{
						cloneState(lambda_r4[l][k], tmp_state_r4);
						tmp_state_r4[0][i] ^= round4_key;
						InvMixColumns(tmp_state_r4);
						InvShiftRows(tmp_state_r4);
						InvSubBytes(tmp_state_r4);
						//consider in index that the guessed round-key-byte is shifted with InvShiftRows
						sum ^= tmp_state_r4[0][i];
					}
					if(sum != 0)
						break;
				}
				if(sum == 0)
				{
					guessed_round_key[i] = round5_key_p1;
					guessed_round_key[4 + (i + 3) % 4] = round5_key_p2;
					found = 1;
					break;
				}
				else
					sum = 0;
			}
			if(found)
				break;
		}
	}


	WORD guessed_key[4];
	WORD Rcon[]={0x01000000,0x02000000,0x04000000,0x08000000,0x10000000,
		         0x20000000,0x40000000,0x80000000,0x1b000000,0x36000000,
			     0x6c000000,0xd8000000,0xab000000,0x4d000000,0x9a000000};

	//calculate key from round-key
	for(i = 0; i < 4; ++i)
	{
		guessed_key[i] = guessed_round_key[4 * i] << 24;
		guessed_key[i] ^= guessed_round_key[4 * i + 1] << 16;
		guessed_key[i] ^= guessed_round_key[4 * i + 2] << 8;
		guessed_key[i] ^= guessed_round_key[4 * i + 3];
	}
	for(i = 5; i > 0; --i)
	{
		guessed_key[3] = guessed_key[2] ^ guessed_key[3];
		guessed_key[2] = guessed_key[1] ^ guessed_key[2];
		guessed_key[1] = guessed_key[0] ^ guessed_key[1];
		guessed_key[0] = guessed_key[0] ^ SubWord(KE_ROTWORD(guessed_key[3])) ^ Rcon[i - 1];
	}

	BYTE guessed_key_bytes[16];
	for(i = 0; i < 16; ++i)
		guessed_key_bytes[i] = guessed_key[i/4] >> (3 - i % 4) * 8;

	return !memcmp(key, guessed_key_bytes, 16);
}


int main(int argc, char *argv[])
{
	if(argc == 2 && argv[1][0] == '4')
	{
		printf("4 Round Attack on AES: %s\n", do4RoundAttack() ? "SUCCEEDED" : "FAILED");
	}
	if(argc == 2 && argv[1][0] == '5')
	{
		printf("5 Round Attack on AES: %s\n", do5RoundAttack() ? "SUCCEEDED" : "FAILED");
	}
	if(argc == 1)
	{
		printf("4 Round Attack on AES: %s\n", do4RoundAttack() ? "SUCCEEDED" : "FAILED");
		printf("5 Round Attack on AES: %s\n", do5RoundAttack() ? "SUCCEEDED" : "FAILED");
	}
	return(0);
}
