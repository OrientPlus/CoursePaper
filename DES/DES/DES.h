#pragma once


#include <fstream>
#include <iostream>
#include <string>
#include <bitset>
#include <vector>
#include <windows.h>


using namespace std;

class DES
{
public:
	void encrypt();

	void get_data();

	int64_t getSizeFile(ifstream& in);

	void initial_permutation(int it);
	void finaly_permutation(int it);

	bitset<48> expanding_permutation(bitset<32> &block);

	void key_extension();

	int get_dec(int tmp);
	
private:
	int64_t fileSize = 0;
	bitset<64> data[10];
	bitset<64> key = ( 0,1,1,0,1,0,1,0,0,0,1,0,1,0,1,0,1,0,1,0,0,1,0,1,0,1,1,1,1,1,1,0,0,1,1,1,1,0,0,1,0,1,0,1,0,1,1,0,1,0,1,0,1,1,1,0,1,1,1,1,1,1,0,0 );
	bitset<48> RoundKey[16];
	bitset<32> leftBlock, rightBlock;
	string path;
	bool bigSize=false;
};