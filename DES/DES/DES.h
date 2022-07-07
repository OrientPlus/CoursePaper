#pragma once


#include <fstream>
#include <iostream>
#include <string>
#include <bitset>
#include <vector>
#include <windows.h>
#include <cmath>


using namespace std;

class DES
{
public:
	void encrypt();
	void decrypt();
	
	int64_t sizeEncFile = 0, sizeDecFile = 0, sizeSourceFile = 0;
private:
	int64_t fileSize = 0;
	bitset<64> data;
	bitset<64> key = 0b0000000001010011010011000101010000100101000001001010111101100001;
	bitset<48> RoundKey[16];
	bitset<32> leftBlock, rightBlock;
	string path, Enc_filename;


	void IP_first();
	void IP_second();
	bitset<48> EP(bitset<32>& block);
	void key_extension();
	int conv_to_dec(int tmp);
	void init_file();
	void round(int j, bool flag);
	void apply_Sbox(bitset<6>* Sblock6, bitset<4>* Sblock4);
	bitset<32> block_convertion(bitset<32> BLOCK, bitset<48> R_key);
	int64_t getSizeFile(string path_);
};