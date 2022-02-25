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
	DES();

	void encrypt();

	void get_data();

	int64_t getSizeFile();

	void initial_permutation(int it);
	void finaly_permutation(int it);

	bitset<48> expanding_permutation(bitset<32> &block);

	void key_extension();

	int get_dec(int tmp);

	void print_data();

	char *convert_bin_to_hex(int _i);

	int64_t sizeEncrFile();
	
private:
	ifstream in;
	ofstream out;
	int64_t fileSize = 0;
	bitset<64> data[10];
	bitset<64> key = 1498011;
	bitset<48> RoundKey[16];
	bitset<32> leftBlock, rightBlock;
	string path;
	bool bigSize=false;
	int receivedBlocks = 0;
};