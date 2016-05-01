/*********************************************************************
* Filename:   des.c
* Author:     Brad Conte (brad AT radconte.com)
* Copyright:
* Disclaimer: This code is presented "as is" without any guarantees.
* Details:    Implementation of the DES encryption algorithm.
              Modes of operation (such as CBC) are not included.
              The formal NIST algorithm specification can be found here:
               * http://csrc.nist.gov/publications/fips/fips46-3/fips46-3.pdf
*********************************************************************/

/*************************** HEADER FILES ***************************/
#include <stdlib.h>
#include <memory.h>
#include "des.h"

/****************************** MACROS ******************************/
// Obtain bit "b" from the left and shift it "c" places from the right
#define BITNUM(a,b,c) (((a[(b)/8] >> (7 - (b%8))) & 0x01) << (c))
#define BITNUMINTR(a,b,c) ((((a) >> (31 - (b))) & 0x00000001) << (c))
#define BITNUMINTL(a,b,c) ((((a) << (b)) & 0x80000000) >> (c))

// This macro converts a 6 bit block with the S-Box row defined as the first and last
// bits to a 6 bit block with the row defined by the first two bits.
#define SBOXBIT(a) (((a) & 0x20) | (((a) & 0x1f) >> 1) | (((a) & 0x01) << 4))

/**************************** VARIABLES *****************************/
static const BYTE sbox1[64] = {
	14,  4,  13,  1,   2, 15,  11,  8,   3, 10,   6, 12,   5,  9,   0,  7,
	 0, 15,   7,  4,  14,  2,  13,  1,  10,  6,  12, 11,   9,  5,   3,  8,
	 4,  1,  14,  8,  13,  6,   2, 11,  15, 12,   9,  7,   3, 10,   5,  0,
	15, 12,   8,  2,   4,  9,   1,  7,   5, 11,   3, 14,  10,  0,   6, 13
};
static const BYTE sbox2[64] = {
	15,  1,   8, 14,   6, 11,   3,  4,   9,  7,   2, 13,  12,  0,   5, 10,
	 3, 13,   4,  7,  15,  2,   8, 14,  12,  0,   1, 10,   6,  9,  11,  5,
	 0, 14,   7, 11,  10,  4,  13,  1,   5,  8,  12,  6,   9,  3,   2, 15,
	13,  8,  10,  1,   3, 15,   4,  2,  11,  6,   7, 12,   0,  5,  14,  9
};
static const BYTE sbox3[64] = {
	10,  0,   9, 14,   6,  3,  15,  5,   1, 13,  12,  7,  11,  4,   2,  8,
	13,  7,   0,  9,   3,  4,   6, 10,   2,  8,   5, 14,  12, 11,  15,  1,
	13,  6,   4,  9,   8, 15,   3,  0,  11,  1,   2, 12,   5, 10,  14,  7,
	 1, 10,  13,  0,   6,  9,   8,  7,   4, 15,  14,  3,  11,  5,   2, 12
};
static const BYTE sbox4[64] = {
	 7, 13,  14,  3,   0,  6,   9, 10,   1,  2,   8,  5,  11, 12,   4, 15,
	13,  8,  11,  5,   6, 15,   0,  3,   4,  7,   2, 12,   1, 10,  14,  9,
	10,  6,   9,  0,  12, 11,   7, 13,  15,  1,   3, 14,   5,  2,   8,  4,
	 3, 15,   0,  6,  10,  1,  13,  8,   9,  4,   5, 11,  12,  7,   2, 14
};
static const BYTE sbox5[64] = {
	 2, 12,   4,  1,   7, 10,  11,  6,   8,  5,   3, 15,  13,  0,  14,  9,
	14, 11,   2, 12,   4,  7,  13,  1,   5,  0,  15, 10,   3,  9,   8,  6,
	 4,  2,   1, 11,  10, 13,   7,  8,  15,  9,  12,  5,   6,  3,   0, 14,
	11,  8,  12,  7,   1, 14,   2, 13,   6, 15,   0,  9,  10,  4,   5,  3
};
static const BYTE sbox6[64] = {
	12,  1,  10, 15,   9,  2,   6,  8,   0, 13,   3,  4,  14,  7,   5, 11,
	10, 15,   4,  2,   7, 12,   9,  5,   6,  1,  13, 14,   0, 11,   3,  8,
	 9, 14,  15,  5,   2,  8,  12,  3,   7,  0,   4, 10,   1, 13,  11,  6,
	 4,  3,   2, 12,   9,  5,  15, 10,  11, 14,   1,  7,   6,  0,   8, 13
};
static const BYTE sbox7[64] = {
	 4, 11,   2, 14,  15,  0,   8, 13,   3, 12,   9,  7,   5, 10,   6,  1,
	13,  0,  11,  7,   4,  9,   1, 10,  14,  3,   5, 12,   2, 15,   8,  6,
	 1,  4,  11, 13,  12,  3,   7, 14,  10, 15,   6,  8,   0,  5,   9,  2,
	 6, 11,  13,  8,   1,  4,  10,  7,   9,  5,   0, 15,  14,  2,   3, 12
};
static const BYTE sbox8[64] = {
	13,  2,   8,  4,   6, 15,  11,  1,  10,  9,   3, 14,   5,  0,  12,  7,
	 1, 15,  13,  8,  10,  3,   7,  4,  12,  5,   6, 11,   0, 14,   9,  2,
	 7, 11,   4,  1,   9, 12,  14,  2,   0,  6,  10, 13,  15,  3,   5,  8,
	 2,  1,  14,  7,   4, 10,   8, 13,  15, 12,   9,  0,   3,  5,   6, 11
};

/*********************** FUNCTION DEFINITIONS ***********************/
void Initial_Breakup(WORD state[], const BYTE in[])
{
	state[0] = 0;
	state[1] = 0;
	int i = 0;
	for(i = 0; i<4; i++)
	{
		state[0] += in[i] << (8*(3-i));
		state[1] += in[4+i] << (8*(3-i));
	}
}

void Final_Assembling(WORD state[], BYTE out[])
{
	int i = 0;
    for(i = 0; i<4; i++)
    {
        out[i] = (state[0] >> (8*(3-i))) & 0xFF;
        out[4+i] = (state[1] >> (8*(3-i))) & 0xFF;
    }
}


WORD f(WORD state, const BYTE key[])
{
	BYTE lrgstate[6]; //,i;
	WORD t1,t2;

	// Expantion Permutation
	t1 = BITNUMINTL(state,31,0) | ((state & 0xf0000000) >> 1) | BITNUMINTL(state,4,5) |
		  BITNUMINTL(state,3,6) | ((state & 0x0f000000) >> 3) | BITNUMINTL(state,8,11) |
		  BITNUMINTL(state,7,12) | ((state & 0x00f00000) >> 5) | BITNUMINTL(state,12,17) |
		  BITNUMINTL(state,11,18) | ((state & 0x000f0000) >> 7) | BITNUMINTL(state,16,23);

	t2 = BITNUMINTL(state,15,0) | ((state & 0x0000f000) << 15) | BITNUMINTL(state,20,5) |
		  BITNUMINTL(state,19,6) | ((state & 0x00000f00) << 13) | BITNUMINTL(state,24,11) |
		  BITNUMINTL(state,23,12) | ((state & 0x000000f0) << 11) | BITNUMINTL(state,28,17) |
		  BITNUMINTL(state,27,18) | ((state & 0x0000000f) << 9) | BITNUMINTL(state,0,23);

	lrgstate[0] = (t1 >> 24) & 0x000000ff;
	lrgstate[1] = (t1 >> 16) & 0x000000ff;
	lrgstate[2] = (t1 >> 8) & 0x000000ff;
	lrgstate[3] = (t2 >> 24) & 0x000000ff;
	lrgstate[4] = (t2 >> 16) & 0x000000ff;
	lrgstate[5] = (t2 >> 8) & 0x000000ff;

	// Key XOR
	lrgstate[0] ^= key[0];
	lrgstate[1] ^= key[1];
	lrgstate[2] ^= key[2];
	lrgstate[3] ^= key[3];
	lrgstate[4] ^= key[4];
	lrgstate[5] ^= key[5];

	// S-Box Permutation
	state = (sbox1[SBOXBIT(lrgstate[0] >> 2)] << 28) |
			  (sbox2[SBOXBIT(((lrgstate[0] & 0x03) << 4) | (lrgstate[1] >> 4))] << 24) |
			  (sbox3[SBOXBIT(((lrgstate[1] & 0x0f) << 2) | (lrgstate[2] >> 6))] << 20) |
			  (sbox4[SBOXBIT(lrgstate[2] & 0x3f)] << 16) |
			  (sbox5[SBOXBIT(lrgstate[3] >> 2)] << 12) |
			  (sbox6[SBOXBIT(((lrgstate[3] & 0x03) << 4) | (lrgstate[4] >> 4))] << 8) |
			  (sbox7[SBOXBIT(((lrgstate[4] & 0x0f) << 2) | (lrgstate[5] >> 6))] << 4) |
				sbox8[SBOXBIT(lrgstate[5] & 0x3f)];

	// P-Box Permutation
	state = BITNUMINTL(state,15,0) | BITNUMINTL(state,6,1) | BITNUMINTL(state,19,2) |
			  BITNUMINTL(state,20,3) | BITNUMINTL(state,28,4) | BITNUMINTL(state,11,5) |
			  BITNUMINTL(state,27,6) | BITNUMINTL(state,16,7) | BITNUMINTL(state,0,8) |
			  BITNUMINTL(state,14,9) | BITNUMINTL(state,22,10) | BITNUMINTL(state,25,11) |
			  BITNUMINTL(state,4,12) | BITNUMINTL(state,17,13) | BITNUMINTL(state,30,14) |
			  BITNUMINTL(state,9,15) | BITNUMINTL(state,1,16) | BITNUMINTL(state,7,17) |
			  BITNUMINTL(state,23,18) | BITNUMINTL(state,13,19) | BITNUMINTL(state,31,20) |
			  BITNUMINTL(state,26,21) | BITNUMINTL(state,2,22) | BITNUMINTL(state,8,23) |
			  BITNUMINTL(state,18,24) | BITNUMINTL(state,12,25) | BITNUMINTL(state,29,26) |
			  BITNUMINTL(state,5,27) | BITNUMINTL(state,21,28) | BITNUMINTL(state,10,29) |
			  BITNUMINTL(state,3,30) | BITNUMINTL(state,24,31);

	// Return the final state value
	return(state);
}

void des_key_setup(const BYTE key[], BYTE schedule[][6], DES_MODE mode, const int rounds)
{
	WORD i, j, to_gen, C, D;
	const WORD key_rnd_shift[16] = {1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1};
	const WORD key_perm_c[28] = {56,48,40,32,24,16,8,0,57,49,41,33,25,17,
	                             9,1,58,50,42,34,26,18,10,2,59,51,43,35};
	const WORD key_perm_d[28] = {62,54,46,38,30,22,14,6,61,53,45,37,29,21,
	                             13,5,60,52,44,36,28,20,12,4,27,19,11,3};
	const WORD key_compression[48] = {13,16,10,23,0,4,2,27,14,5,20,9,
	                                  22,18,11,3,25,7,15,6,26,19,12,1,
	                                  40,51,30,36,46,54,29,39,50,44,32,47,
	                                  43,48,38,55,33,52,45,41,49,35,28,31};

	// Permutated Choice #1 (copy the key in, ignoring parity bits).
	for (i = 0, j = 31, C = 0; i < 28; ++i, --j)
		C |= BITNUM(key,key_perm_c[i],j);
	for (i = 0, j = 31, D = 0; i < 28; ++i, --j)
		D |= BITNUM(key,key_perm_d[i],j);

	// Generate the round subkeys.
	for (i = 0; i < rounds; ++i) {
		C = ((C << key_rnd_shift[i]) | (C >> (28-key_rnd_shift[i]))) & 0xfffffff0;
		D = ((D << key_rnd_shift[i]) | (D >> (28-key_rnd_shift[i]))) & 0xfffffff0;

		// Decryption subkeys are reverse order of encryption subkeys so
		// generate them in reverse if the key schedule is for decryption useage.
		if (mode == DES_DECRYPT)
			to_gen = (rounds-1) - i;
		else /*(if mode == DES_ENCRYPT)*/
			to_gen = i;
		// Initialize the array
		for (j = 0; j < 6; ++j)
			schedule[to_gen][j] = 0;
		for (j = 0; j < 24; ++j)
			schedule[to_gen][j/8] |= BITNUMINTR(C,key_compression[j],7 - (j%8));
		for ( ; j < 48; ++j)
			schedule[to_gen][j/8] |= BITNUMINTR(D,key_compression[j] - 28,7 - (j%8));
	}
}

void des_crypt(const BYTE in[], BYTE out[], const BYTE key[][6], const int rounds)
{
	WORD state[2],idx,t;

	//no permutation
    Initial_Breakup(state,in);

	for (idx=0; idx < (rounds-1); ++idx) {
		t = state[1];
		state[1] = f(state[1],key[idx]) ^ state[0];
		state[0] = t;
	}
	// Perform the final loop manually as it doesn't switch sides
	state[0] = f(state[1],key[rounds-1]) ^ state[0];

	Final_Assembling(state,out);
}

void rand_plaintext(const BYTE curr_state[], BYTE next_state[], BYTE output_plaintext[])
{
	BYTE in0[DES_BLOCK_SIZE] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
	BYTE in1[DES_BLOCK_SIZE] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01};
	BYTE schedule[8][6];
	des_key_setup(curr_state,schedule,DES_ENCRYPT,8);
	des_crypt(in0, next_state, schedule, 8);
	des_crypt(in1, output_plaintext, schedule, 8);
}

BYTE compute_left_side(const BYTE plaintext[], const BYTE ciphertext[], int rounds, const WORD f)
{
	if((rounds != 3)&&(rounds != 5)&&(rounds !=7)&&(rounds != 8))
	{
		return 0xFF;
	}
	if(rounds == 3)
	{
		//gather the needed bits for 3 rounds
		//using R0[15] ^ L3[15] ^ L0[7,18,24,29] ^ R3[7,18,24,29]
		BYTE Pr15,Cl15,Pl7,Pl18,Pl24,Pl29,Cr7,Cr18,Cr24,Cr29;
		Pr15 = (plaintext[6] >> 7) & 0x01;
		Cl15 = (ciphertext[2] >> 7) & 0x01;
		Pl7 = (plaintext[3] >> 7) & 0x01;
		Pl18 = (plaintext[1] >> 2) & 0x01;
		Pl24 = plaintext[0] & 0x01;
		Pl29 = (plaintext[0] >> 5) & 0x01;
		Cr7 = (ciphertext[7] >> 7) & 0x01;
		Cr18 = (ciphertext[5] >> 2) & 0x01;
		Cr24 = ciphertext[4] & 0x01;
		Cr29 = (ciphertext[4] >> 5) & 0x01;
		return (Pr15 ^ Cl15 ^ Pl7 ^ Pl18 ^ Pl24 ^ Pl29 ^ Cr7 ^ Cr18 ^ Cr24 ^ Cr29);
	}
	else if(rounds == 5)
	{
		//gather the bits for 5 rounds
		//using L0[15] ^ R0[7,18,24,27,28,29,30,31] ^ R5[15] ^ L5[7,18,24,27,28,29,30,31]
		BYTE Pl15,Pr7,Pr18,Pr24,Pr27,Pr28,Pr29,Pr30,Pr31;
		BYTE Cr15,Cl7,Cl18,Cl24,Cl27,Cl28,Cl29,Cl30,Cl31;
		Pl15 = (plaintext[2] >> 7) & 0x01;
		Pr7 = (plaintext[7] >> 7) & 0x01;
		Pr18 = (plaintext[5] >> 2) & 0x01;
		Pr24 = plaintext[4] & 0x01;
		Pr27 = (plaintext[4] >> 3) & 0x01;
		Pr28 = (plaintext[4] >> 4) & 0x01;
		Pr29 = (plaintext[4] >> 5) & 0x01;
		Pr30 = (plaintext[4] >> 6) & 0x01;
		Pr31 = (plaintext[4] >> 7) & 0x01;
		Cr15 = (ciphertext[6] >> 7) & 0x01;
		Cl7 = (ciphertext[3] >> 7) & 0x01;
		Cl18 = (ciphertext[1] >> 2) & 0x01;
		Cl24 = ciphertext[0] & 0x01;
		Cl27 = (ciphertext[0] >> 3) & 0x01;
		Cl28 = (ciphertext[0] >> 4) & 0x01;
		Cl29 = (ciphertext[0] >> 5) & 0x01;
		Cl30 = (ciphertext[0] >> 6) & 0x01;
		Cl31 = (ciphertext[0] >> 7) & 0x01;
		return (Pl15 ^ Pr7 ^ Pr18 ^ Pr24 ^ Pr27 ^ Pr28 ^ Pr29 ^ Pr30 ^ Pr31 ^ Cr15 ^ Cl7 ^ Cl18 ^ Cl24 ^ Cl27 ^ Cl28 ^ Cl29 ^ Cl30 ^ Cl31);
	}
	else if(rounds == 7)
	{
		//using L0[7,18,24] ^ R0[12,16] ^ R7[15] ^ L7[7,18,24,29]   because R7 = L8 and L7 = R8 if F(R8,K8) is 0 (there is no K8 in 7 rounds)
		BYTE Pl7, Pl18, Pl24, Pr12, Pr16;
		BYTE Cl7, Cl18, Cl24, Cl29, Cr15;
		Pl7 = (plaintext[3] >> 7) & 0x01;
		Pl18 = (plaintext[1] >> 2) & 0x01;
		Pl24 = (plaintext[0]) & 0x01;
		Pr12 = (plaintext[6] >> 4) & 0x01;
		Pr16 = (plaintext[5]) & 0x01;
		Cl7 = (ciphertext[3] >> 7) & 0x01;
		Cl18 = (ciphertext[1] >> 2) & 0x01;
		Cl24 = ciphertext[0] & 0x01;
		Cl29 = (ciphertext[0] >> 5) & 0x01;
		Cr15 = (ciphertext[6] >> 7) & 0x01;

		/* L0[7,18,24] ^ R0[12,16] ^ L7[15] ^ R7[7,18,24,29]   other interpretation of the 7 round approximation
		BYTE Cl15, Cr7, Cr18, Cr24, Cr29;
		Cl15 = (ciphertext[3] >> 7) & 0x01;
		Cr7 = (ciphertext[7] >> 7) & 0x01;
		Cr18 = (ciphertext[5] >> 2) & 0x01;
		Cr24 = (ciphertext[4]) & 0x01;
		Cr29 = (ciphertext[4] >> 5) & 0x01;
		return (Pl7 ^ Pl18 ^ Pl24 ^ Pr12 ^ Pr16 ^ Cl15 ^ Cr7 ^ Cr18 ^ Cr24 ^ Cr29);*/

		return (Pl7 ^ Pl18 ^ Pl24 ^ Pr12 ^ Pr16 ^ Cl7 ^ Cl18 ^ Cl24 ^ Cl29 ^ Cr15);
	}
	else
	{
		//using L0[7,18,24] ^ R0[12,16] ^ L7[15] ^ R7[7,18,24,29] ^ F(R8,K8)[15]
		BYTE Pl7, Pl18, Pl24, Pr12, Pr16;
		BYTE Cl15, Cr7, Cr18, Cr24, Cr29, F8;
		Pl7 = (plaintext[3] >> 7) & 0x01;
		Pl18 = (plaintext[1] >> 2) & 0x01;
		Pl24 = (plaintext[0]) & 0x01;
		Pr12 = (plaintext[6] >> 4) & 0x01;
		Pr16 = (plaintext[5]) & 0x01;
		Cr7 = (ciphertext[7] >> 7) & 0x01;
		Cr18 = (ciphertext[5] >> 2) & 0x01;
		Cr24 = ciphertext[4] & 0x01;
		Cr29 = (ciphertext[4] >> 5) & 0x01;
		Cl15 = (ciphertext[2] >> 7) & 0x01;
		F8 = (f >> 15) & 0x01; //F[R8,K8][15] here
		return (Pl7 ^ Pl18 ^ Pl24 ^ Pr12 ^ Pr16 ^ Cr7 ^ Cr18 ^ Cr24 ^ Cr29 ^ Cl15 ^ F8);
	}

	return 0xFF;
}

void algorithm1(const BYTE plain[][DES_BLOCK_SIZE], const BYTE key[][6], unsigned int* count_T0, unsigned int* count_T1, int number_of_plains, int rounds, const BYTE keyguess[])
{
	BYTE ciphertext[DES_BLOCK_SIZE];
	int i = 0;
	BYTE solution = 0x00;
    WORD f8 = 0;
    WORD c8[2];

	for(i = 0; i < number_of_plains; i++)
	{
		des_crypt(plain[i], ciphertext, key, rounds);

		if(rounds == 8)
		{
			//computing F(R8,K8') for the 8 round attack
            Initial_Breakup(c8,ciphertext);
            f8 = f(c8[1], keyguess);
		}

		solution = compute_left_side(plain[i], ciphertext, rounds, f8);
		if(solution == 0xFF)
		{
			*count_T0 = -1;
			*count_T1 = -1;
			return;
		}
        if(solution == 0x00)
        {
        	*count_T0 += 1;
        }
        else if(solution == 0x01)
        {
        	*count_T1 += 1;
        }
	}
}

int algorithm2(const BYTE plain[][DES_BLOCK_SIZE], const BYTE keyschedule[][6], BYTE key8bits[], unsigned int count_T0[], unsigned int count_T1[], int number_of_plains, int keyguesses)
{
	BYTE keyguess[6];
	int i = 0;
	int correct_keyguess = 0;
	unsigned int diff[keyguesses];
	//only bits 42-47 of K8 are relevant, setting other bits to 0
	keyguess[1] = 0x00;
	keyguess[2] = 0x00;
	keyguess[3] = 0x00;
	keyguess[4] = 0x00;
	keyguess[5] = 0x00;

	for(i = 0; i<keyguesses; i++)
	{
		//initialize counters
		count_T0[i] = 0;
		count_T1[i] = 0;
		//guess key, only 6 bits are effective (???? ??00)
        keyguess[0] = (i << 2) & 0xFC;

		algorithm1(plain, keyschedule, &count_T0[i], &count_T1[i], number_of_plains, 8, keyguess);
		if(count_T0[i] > count_T1[i])
		{
			diff[i] = count_T0[i] - count_T1[i];
		}
		else
		{
			diff[i] = count_T1[i] - count_T0[i];
		}
	}

	//search the highest difference between T0 and T1
	unsigned int max = diff[0];
	for(i = 1; i<keyguesses;i++)
	{
		if(max < diff[i])
		{
			max = diff[i];
			correct_keyguess = i;
		}
	}
	keyguess[0] = (correct_keyguess << 2) & 0xFC;

	//storing the guessed key bits K8[42] - K8[47]
	for(i = 0; i < 6; i++)
	{
		key8bits[i] = (keyguess[0] >> (2+i)) & 0x01;
	}
	return correct_keyguess;
}

