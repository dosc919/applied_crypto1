/*
Implementation by the Keccak, Keyak and Ketje Teams, namely, Guido Bertoni,
Joan Daemen, Michaël Peeters, Gilles Van Assche and Ronny Van Keer, hereby
denoted as "the implementer".

For more information, feedback or questions, please refer to our websites:
http://keccak.noekeon.org/
http://keyak.noekeon.org/
http://ketje.noekeon.org/

To the extent possible under law, the implementer has waived all copyright
and related or neighboring rights to the source code in this file.
http://creativecommons.org/publicdomain/zero/1.0/
*/

/*
================================================================
The purpose of this source file is to demonstrate a readable and compact
implementation of all the Keccak instances approved in the FIPS 202 standard,
including the hash functions and the extendable-output functions (XOFs).

We focused on clarity and on source-code compactness,
rather than on the performance.

The advantages of this implementation are:
    + The source code is compact, after removing the comments, that is. :-)
    + There are no tables with arbitrary constants.
    + For clarity, the comments link the operations to the specifications using
        the same notation as much as possible.
    + There is no restriction in cryptographic features. In particular,
        the SHAKE128 and SHAKE256 XOFs can produce any output length.
    + The code does not use much RAM, as all operations are done in place.

The drawbacks of this implementation are:
    - There is no message queue. The whole message must be ready in a buffer.
    - It is not optimized for peformance.

The implementation is even simpler on a little endian platform. Just define the
LITTLE_ENDIAN symbol in that case.

For a more complete set of implementations, please refer to
the Keccak Code Package at https://github.com/gvanas/KeccakCodePackage

For more information, please refer to:
    * [Keccak Reference] http://keccak.noekeon.org/Keccak-reference-3.0.pdf
    * [Keccak Specifications Summary] http://keccak.noekeon.org/specs_summary.html

This file uses UTF-8 encoding, as some comments use Greek letters.
================================================================
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

typedef unsigned char BYTE;

/**
  * Function to compute the Keccak[r, c] sponge function over a given input.
  * @param  rate            The value of the rate r.
  * @param  capacity        The value of the capacity c.
  * @param  input           Pointer to the input message.
  * @param  inputByteLen    The number of input bytes provided in the input message.
  * @param  output          Pointer to the buffer where to store the output.
  * @param  outputByteLen   The number of output bytes desired.
  * @param  rounds			The number of rounds performed by the f1600 function.
  * @pre    One must have r+c=1600 and the rate a multiple of 8 bits in this implementation.
  */
void Keccak(unsigned int rate, unsigned int capacity, const unsigned char *input, unsigned long long int inputByteLen, unsigned char *output, unsigned long long int outputByteLen, int rounds);


//Function of the cube attack
void Keccak_MAC_128(const unsigned char* input, unsigned int inputByteLen, unsigned char* output, int rounds)
{
	Keccak(1024, 576, input, inputByteLen, output, 16, rounds);
}

/*
================================================================
Technicalities
================================================================
*/

typedef unsigned char UINT8;
typedef unsigned long long int UINT64;
typedef UINT64 tKeccakLane;

#ifndef LITTLE_ENDIAN
/** Function to load a 64-bit value using the little-endian (LE) convention.
  * On a LE platform, this could be greatly simplified using a cast.
  */
static UINT64 load64(const UINT8 *x)
{
    int i;
    UINT64 u=0;

    for(i=7; i>=0; --i) {
        u <<= 8;
        u |= x[i];
    }
    return u;
}

/** Function to store a 64-bit value using the little-endian (LE) convention.
  * On a LE platform, this could be greatly simplified using a cast.
  */
static void store64(UINT8 *x, UINT64 u)
{
    unsigned int i;

    for(i=0; i<8; ++i) {
        x[i] = u;
        u >>= 8;
    }
}

/** Function to XOR into a 64-bit value using the little-endian (LE) convention.
  * On a LE platform, this could be greatly simplified using a cast.
  */
static void xor64(UINT8 *x, UINT64 u)
{
    unsigned int i;

    for(i=0; i<8; ++i) {
        x[i] ^= u;
        u >>= 8;
    }
}
#endif

/*
================================================================
A readable and compact implementation of the Keccak-f[1600] permutation.
================================================================
*/

#define ROL64(a, offset) ((((UINT64)a) << offset) ^ (((UINT64)a) >> (64-offset)))
#define i(x, y) ((x)+5*(y))

#ifdef LITTLE_ENDIAN
    #define readLane(x, y)          (((tKeccakLane*)state)[i(x, y)])
    #define writeLane(x, y, lane)   (((tKeccakLane*)state)[i(x, y)]) = (lane)
    #define XORLane(x, y, lane)     (((tKeccakLane*)state)[i(x, y)]) ^= (lane)
#else
    #define readLane(x, y)          load64((UINT8*)state+sizeof(tKeccakLane)*i(x, y))
    #define writeLane(x, y, lane)   store64((UINT8*)state+sizeof(tKeccakLane)*i(x, y), lane)
    #define XORLane(x, y, lane)     xor64((UINT8*)state+sizeof(tKeccakLane)*i(x, y), lane)
#endif

/**
  * Function that computes the linear feedback shift register (LFSR) used to
  * define the round constants (see [Keccak Reference, Section 1.2]).
  */
int LFSR86540(UINT8 *LFSR)
{
    int result = ((*LFSR) & 0x01) != 0;
    if (((*LFSR) & 0x80) != 0)
        // Primitive polynomial over GF(2): x^8+x^6+x^5+x^4+1
        (*LFSR) = ((*LFSR) << 1) ^ 0x71;
    else
        (*LFSR) <<= 1;
    return result;
}

/**
 * Function that computes the Keccak-f[1600] permutation on the given state.
 */
void KeccakF1600_StatePermute(void *state, int rounds)
{
    unsigned int round, x, y, j, t;
    UINT8 LFSRstate = 0x01;

    for(round=0; round<rounds; round++) {
        {   // === θ step (see [Keccak Reference, Section 2.3.2]) ===
            tKeccakLane C[5], D;

            // Compute the parity of the columns
            for(x=0; x<5; x++)
                C[x] = readLane(x, 0) ^ readLane(x, 1) ^ readLane(x, 2) ^ readLane(x, 3) ^ readLane(x, 4);
            for(x=0; x<5; x++) {
                // Compute the θ effect for a given column
                D = C[(x+4)%5] ^ ROL64(C[(x+1)%5], 1);
                // Add the θ effect to the whole column
                for (y=0; y<5; y++)
                    XORLane(x, y, D);
            }
        }

        {   // === ρ and π steps (see [Keccak Reference, Sections 2.3.3 and 2.3.4]) ===
            tKeccakLane current, temp;
            // Start at coordinates (1 0)
            x = 1; y = 0;
            current = readLane(x, y);
            // Iterate over ((0 1)(2 3))^t * (1 0) for 0 ≤ t ≤ 23
            for(t=0; t<24; t++) {
                // Compute the rotation constant r = (t+1)(t+2)/2
                unsigned int r = ((t+1)*(t+2)/2)%64;
                // Compute ((0 1)(2 3)) * (x y)
                unsigned int Y = (2*x+3*y)%5; x = y; y = Y;
                // Swap current and state(x,y), and rotate
                temp = readLane(x, y);
                writeLane(x, y, ROL64(current, r));
                current = temp;
            }
        }

        {   // === χ step (see [Keccak Reference, Section 2.3.1]) ===
            tKeccakLane temp[5];
            for(y=0; y<5; y++) {
                // Take a copy of the plane
                for(x=0; x<5; x++)
                    temp[x] = readLane(x, y);
                // Compute χ on the plane
                for(x=0; x<5; x++)
                    writeLane(x, y, temp[x] ^((~temp[(x+1)%5]) & temp[(x+2)%5]));
            }
        }

        {   // === ι step (see [Keccak Reference, Section 2.3.5]) ===
            for(j=0; j<7; j++) {
                unsigned int bitPosition = (1<<j)-1; //2^j-1
                if (LFSR86540(&LFSRstate))
                    XORLane(0, 0, (tKeccakLane)1<<bitPosition);
            }
        }
    }
}

/*
================================================================
A readable and compact implementation of the Keccak sponge functions
that use the Keccak-f[1600] permutation.
================================================================
*/

#define MIN(a, b) ((a) < (b) ? (a) : (b))

void Keccak(unsigned int rate, unsigned int capacity, const unsigned char *input, unsigned long long int inputByteLen, unsigned char *output, unsigned long long int outputByteLen, int rounds)
{
    UINT8 state[200];
    unsigned int rateInBytes = rate/8;
    unsigned int blockSize = 0;
    unsigned int i;

    if (((rate + capacity) != 1600) || ((rate % 8) != 0))
        return;

    // === Initialize the state ===
    memset(state, 0, sizeof(state));

    // === Absorb all the input blocks ===
    while(inputByteLen > 0) {
        blockSize = MIN(inputByteLen, rateInBytes);
        for(i=0; i<blockSize; i++)
            state[i] ^= input[i];
        input += blockSize;
        inputByteLen -= blockSize;

        if (blockSize == rateInBytes) {
            KeccakF1600_StatePermute(state, rounds);
            blockSize = 0;
        }
    }

    // === Do the switch to the squeezing phase ===
    KeccakF1600_StatePermute(state, rounds);

    // === Squeeze out all the output blocks ===
    while(outputByteLen > 0) {
        blockSize = MIN(outputByteLen, rateInBytes);
        memcpy(output, state, blockSize);
        output += blockSize;
        outputByteLen -= blockSize;

        if (outputByteLen > 0)
            KeccakF1600_StatePermute(state, rounds);
    }
}

void test_keccak_mac(int rounds)
{
	//896 bit message
	unsigned char message[112] = {0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
				0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
				0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
				0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01};
	//128 bit key
	unsigned char key[16] = {0xA3, 0xBB, 0x45, 0x70, 0x91, 0x96, 0xC4, 0x1A, 0x5F, 0xFF, 0x66, 0xD3, 0xBC, 0xF8, 0x90, 0x73};
	unsigned char input[128];
	BYTE output[16];
	int i;
	//forging input (K||M)
	for(i = 0; i < 128; i++)
	{
		if(i < 16)
			input[i] = key[i];
		else
			input[i] = message[i-16];
	}

	Keccak_MAC_128(input, 128, output, rounds);
	printf("Create Tag for some message with a random key\n");
	printf("Tag: ");
	for(i = 0; i < 16; i++)
	{
	   	printf("%02X ", output[i]);
	}
	printf("\n");

}

void compute_sum(int bytes, int cube[], int cube_vars, unsigned char key[16], unsigned char final_sum[16], int rounds)
{
	//todo: our sum has 128bit output, the paper only shows 1bit output, so maybe the equations are wrong...
	BYTE output[16];
	BYTE input[128];
	BYTE message[bytes];
	int i,j;
	BYTE cube_var_value;
	int bits_for_cubevars = 0; //used to iterate over all possible combinations of the cube variables. bits 0 - k are the values for the variables
	int equations = 2 << (cube_vars - 1);
	//initialize the output_sum with 0
	for(i = 0; i < 16; i++)
	{
		final_sum[i] = 0x00;
	}
	//set all message bits to 0
	for(i = 0; i < bytes; i++)
	{
		message[i] = 0x00;
	}
	for(i = 0; i < equations; i++)
	{
		//iterate the cube variables
		for(j = 0; j < cube_vars; j++)
		{
			cube_var_value = (bits_for_cubevars >> (cube_vars - j - 1)) & 0x0001;
			message[(cube[j] / 8)] |= (cube_var_value << (cube[j] % 8));
		}
		//forge the input
		for(j = 0; j < 128; j++)
		{
			if(j < 16)
				input[j] = key[j];
			else
				input[j] = message[j-16];
		}
		Keccak_MAC_128(input, 128, output, rounds);
		//XORing all partial outputs together to get the final output
		for(j = 0; j < 16; j++)
		{
			final_sum[j] ^= output[j];
		}
		bits_for_cubevars += 1;
	}
}

int compare_sums(const unsigned char sum1[], const unsigned char sum2[])
{
	int i;
	int equal = 1;
	for(i = 0; i<16; i++)
	{
		if(sum1[i] != sum2[i])
			equal = 0;
	}
	return equal;
}

int compute_coefficients(unsigned char comp_value[], int bytes, int cube[], int cube_variables, unsigned char coefficients[], int rounds)
{
	int number_of_coefficients = 128;
	unsigned char key[16] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
	unsigned char key_temp[16];
	unsigned char sum_for_coefficient[16];
	int i,j,equal;
	int found_some_coeffs = 0;
	for(i = 0; i < number_of_coefficients; i++)
	{
		for(j = 0; j < 16; j++)
		{
			key_temp[j] = 0x00;
		}
		//set only one bit to 1 to get the value for this coefficient
		key_temp[i/8] = key[i/8] | (1 << (i%8));
		compute_sum(bytes,cube, cube_variables, key_temp, sum_for_coefficient, rounds);
		equal = compare_sums(sum_for_coefficient, comp_value);
		//if the sum for a coefficient differs from the sum of the constant coefficient c0, then it is present
		if(equal==0)
		{
			//printf("Coefficient %d is present\n", i);
			coefficients[i] = 0x01;
		}
	}
	for(i = 0; i<number_of_coefficients; i++)
	{
		//if only one coefficient is present, the superpoly is not constant
		if(sum_for_coefficient[i] != 0x00)
		{
			found_some_coeffs = 1;
			break;
		}
	}

	return found_some_coeffs;
}

int check_if_nonlinear()
{
	//todo: implement the non-linearity check
	return 1;
}

/**
 * Returns 1 if the cube leads to a linear superpoly.
 * Returns 0 if the superpoly is constant.
 * Returns -1 if the superpoly is non-linear.
 */
int superpoly_for_cube(int bits, int cube[], int cube_vars, BYTE coefficients[], int rounds)
{
	BYTE key[16] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
	BYTE sum_with_0key[16];
	int i;

	int is_constant = 0;
	int is_nonlinear = 0;
	int bytes = bits/8;
	compute_sum(bytes, cube, cube_vars, key, sum_with_0key, rounds);
	is_constant = compute_coefficients(sum_with_0key, bytes, cube, cube_vars, coefficients,rounds);
	if(is_constant == 0)
		return 0;
	is_nonlinear = check_if_nonlinear();
	if(is_nonlinear == 0)
		return -1;
	return 1;
}

void search_maxterms_superpolys(int initial_degree_guess, int wanted_number_of_superpolys, int rounds)
{
	int k = initial_degree_guess - 1;
	int public_vars = 896;
	int found_linear_superpolys = 0;
	int i,j;
	int unique = 0;
	srand(210);

	//find ~120 linear independent superpolys
	while(found_linear_superpolys <= wanted_number_of_superpolys)
	{
		//choose a subset I of k public variables
		int cube[k];
		BYTE poly_coefficients[128] = {0};
		//create I - Set
		//printf("I-Set: ");
		for(i = 0; i < k; i++)
		{
			cube[i] = rand() % public_vars;
			//be sure that no indizes are double in the I - Set
			while(unique == 0)
			{
				unique = 1;
				for(j = i - 1; j >= 0; j--)
				{
					if(cube[i] == cube[j])
						unique = 0;
				}
				if(unique == 0)
				{
					cube[i] = rand() % public_vars;
				}
			}
			unique = 0;
			//printf(" %d",I[i]);
		}
		//printf("\n");
		//compute pI
		int result = superpoly_for_cube(public_vars, cube, k, poly_coefficients, rounds);
		if(result == 0)
		{
			printf("superpoly is constant! Remove a variable from the cube!\n");
			//superpoly was constant
			//todo: remove a cube variable and try again
		}
		if(result == -1)
		{
			printf("superpoly is non-linear! add a variable to the cube!\n");
			//superpoly was non-linear
		}
		//if the superpoly is linear and the coefficients are computed, result is 1
		if(result == 1)
			found_linear_superpolys++;
	}
}

int main()
{
	int rounds = 1; //TODO 4 rounds
	int wanted_number_of_superpolys = 140;
    //test_keccak_mac(rounds);
    printf("Starting %d round attack on keccak...\n",rounds);
    //offline phase
    /*
     * define cubes - send them through the simulation of f (with known key)
     * compute superpolys and test them on linearity and constant
     * gather ~120 linear independend superpolys
     */
    int degree_guess = 2 << (rounds-1);
    search_maxterms_superpolys(degree_guess, wanted_number_of_superpolys, rounds);

    //online phase
    /* send cubes through the oracle with the unknown key
     * find the values to the superpolys (the sums over the cube variables)
     * solve the linear equation system
     * bruteforce the remaining unknown key bits
     */
	return(0);
}

