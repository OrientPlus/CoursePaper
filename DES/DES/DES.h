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

	void initial_file();
	void encrypt();
	void decrypt();
	int64_t getSizeFile();
	void initial_permutation();
	void finaly_permutation();
	bitset<48> expanding_permutation(bitset<32> &block);
	void key_extension();
	int conv_to_dec(int tmp);
	int64_t sizeEncrFile();
	
private:
	ifstream in;
	ofstream out;
	int64_t fileSize = 0;
	bitset<64> data;
	bitset<64> key = 0x1122334455667788;
	bitset<48> RoundKey[16];
	bitset<32> leftBlock, rightBlock;
	string path;
	bool bigSize=false;
	int receivedBlocks = 0;
};