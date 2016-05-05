###########################################
#  References of algorithm source codes
###########################################

DES:
https://github.com/B-Con/crypto-algorithms

AES:
https://github.com/B-Con/crypto-algorithms

KECCAK:
https://github.com/gvanas/KeccakCodePackage


###########################################
#  Execute attacks
###########################################
Compiler: gcc

DES:
make run
  execute all attacks (3,5,7,8 rounds)

AES:
make run4
  execute 4 round attack

make run5
  execute 5 round attack

make run
  execute both attacks

KECCACK:
make run
  execute 4 round attack (only offline)

###########################################
#  Additional notes
###########################################

DES:

AES:
  both attacks print successfull if the key was recovered
  5 round attack takes appr. 1h

KECCACK:
  contradictions in the superpoly equations