#pragma once


#include <fstream>
#include <iostream>
#include <string>
#include <bitset>
#include <vector>
#include <windows.h>
#include <chrono>


using namespace std;

class DES
{
public:
	void encrypt();
	void decrypt();
	
	chrono::milliseconds exec_time_dec, exec_time_enc;
	int64_t sizeEncFile = 0, sizeDecFile = 0, sizeSourceFile = 0;
private:
	int64_t fileSize = 0;
	bitset<64> data;
	bitset<64> key;
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

	string convert_string(string& hex);
	const char* hex_char_to_bin(char ch);
	bool key_flag = false;
};