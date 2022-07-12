#pragma once

#include <iostream>
#include <fstream>
#include <bitset>
#include <string>
#include <stdint.h>
#include <chrono>


#define BLOCK_256 bitset<256>
#define BLOCK_128 bitset<128>
#define BLOCK_96 bitset<96>
#define BLOCK_64 bitset<64>
#define BLOCK_32 bitset<32>
#define BLOCK_8 bitset<8>

#define ENCR true
#define DECR false

typedef int64_t QWORD;
typedef int16_t WORD;

using namespace std;

class LOKI 
{
public:
	void encrypt();
	void decrypt();
	chrono::milliseconds exec_time_dec, exec_time_enc;

	int64_t sizeEncFile = 0, sizeDecFile = 0, sizeSourceFile = 0;
private:
	BLOCK_128 data;
	BLOCK_256 key;
	BLOCK_64 RoundKey[48], 
		leftBlock, rightBlock;
	
	string path, Enc_filename;
	
	void init_file();
	void round(int j, bool flag);
	void key_extension();
	void check_key();
	BLOCK_64 KP(BLOCK_64 block, BLOCK_32 key);
	BLOCK_64 F(BLOCK_64 block1, BLOCK_64 block2);
	BLOCK_96 E(BLOCK_64);
	BLOCK_64 apply_Sboxes_layer1(BLOCK_96 ep_block);
	BLOCK_64 apply_Sboxes_layer2(BLOCK_64 block, BLOCK_32 key);
	BLOCK_8 apply_S1(WORD word);
	BLOCK_8 apply_S2(WORD word);
	BLOCK_64 P(BLOCK_64 block);

	WORD my_pow(WORD word, int n);
	int64_t getSizeFile(string path);
	string convert_string(string &hex);
	const char* hex_char_to_bin(char ch);

	bool key_flag = false;
};