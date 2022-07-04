#include <iostream>
#include <bitset>
#include <vector>
#include <cstddef>
#include <time.h>
#include <fstream>

#define ENCRYPTION true
#define DECRYPTION false

std::ofstream debug("C://Users/gutro/Desktop/GIT 2.0/Курсовая/Project1/Project1/debug/2EP.txt", std::ios::app);
std::ofstream debug2("C://Users/gutro/Desktop/GIT 2.0/Курсовая/Project1/Project1/debug/1gettedDATA.txt", std::ios::app);
std::ofstream debug3("C://Users/gutro/Desktop/GIT 2.0/Курсовая/Project1/Project1/debug/3XOR_KEY.txt", std::ios::app);
std::ofstream debug4("C://Users/gutro/Desktop/GIT 2.0/Курсовая/Project1/Project1/debug/4SBOX.txt", std::ios::app);
std::ofstream debug5("C://Users/gutro/Desktop/GIT 2.0/Курсовая/Project1/Project1/debug/5LAST_PERM.txt", std::ios::app);
std::ofstream debug6("C://Users/gutro/Desktop/GIT 2.0/Курсовая/Project1/Project1/debug/6AFTER_XOR.txt", std::ios::app);
std::ofstream debug7("C://Users/gutro/Desktop/GIT 2.0/Курсовая/Project1/Project1/debug/7ROUND_KEY.txt", std::ios::app);
std::ofstream debug8("C://Users/gutro/Desktop/GIT 2.0/Курсовая/Project1/Project1/debug/8KEY.txt", std::ios::app);
std::string strr;
static int count = 0;

using Block = std::bitset<64>;
using HalfBlock = std::bitset<32>;
using uint = unsigned int;
using byte = unsigned char;

class DES {
private:
	std::vector<Block> Blocks;
	std::bitset<56> CDKeyBitset = 0;
	int size;

	void LineToBloks(byte[], int);
	Block StrToBitset(std::string);

	std::bitset<48> GenerateKeyI(int, bool);

	void PrintBlockBitsetInReverseOrder(Block);
	void PrintBlockBitset(Block);
	void FlipBitsetBlocks();
	void FirstIPSwap();
	void LastIPSwap();
	void KeyToCDKeyBitset(unsigned long long);
	Block FanoRound(Block, std::bitset<48>, bool Flag);
	HalfBlock F(HalfBlock, std::bitset<48>);
	void KeyShiftToLeft(int);
	void KeyShiftToRight(int);

public:
	void print_some_block(std::string str);

	void encryption(byte[], unsigned long long);
	void decryption(byte[], unsigned long long);
	void fileEncryption(std::string, std::string, unsigned long long);
	void fileDecryption(std::string, std::string, unsigned long long);
};

unsigned long long G[56] =
{ 57,49,41,33,25,17,9,1,58,50,42,34,26,18,10,2,59,51,43,35,27,19,11,3,60,52,44,36,
63,55,47,39,31,23,15,7,62,54,46,38,30,22,14,6,61,53,45,37,29,21,13,5,28,20,12,4 };

namespace _DES {

	//Remove check bits from key + swap
	const __int8 perm1[56] = {
			56, 48, 40, 32, 24, 16,  8,
			 0, 57, 49, 41, 33, 25, 17,
			 9,  1, 58, 50, 42, 34, 26,
			18, 10,  2, 59, 51, 43, 35,
			62, 54, 46, 38, 30, 22, 14,
			 6, 61, 53, 45, 37, 29, 21,
			13,  5, 60, 52, 44, 36, 28,
			20, 12,  4, 27, 19, 11,  3
	};

	//Permutation of key compression
	const __int8 perm2[48] = {
			13, 16, 10, 23, 0, 4, 2, 27, 14, 5, 20, 9,
		22, 18, 11, 3, 25, 7, 15, 6, 26, 19, 12, 1,
		40, 51, 30, 37, 46, 54, 29, 39, 50, 44, 32, 47,
		43, 48, 38, 55, 33, 52, 45, 41, 49, 35, 28, 31
	};

	//IP first
	const __int8 perm3[64] = {
			57, 49, 41, 33, 25, 17,  9,  1,
			59, 51, 43, 35, 27, 19, 11,  3,
			61, 53, 45, 37, 29, 21, 13,  5,
			63, 55, 47, 39, 31, 23, 15,  7,
			56, 48, 40, 32, 24, 16,  8,  0,
			58, 50, 42, 34, 26, 18, 10,  2,
			60, 52, 44, 36, 28, 20, 12,  4,
			62, 54, 46, 38, 30, 22, 14,  6
	};

	//P box
	const __int8 perm4[48] = {
			31, 0, 1, 2, 3, 4,
		3, 4, 5, 6, 7, 8,
		7, 8, 9, 10, 11, 12,
		11, 12, 13, 14, 15, 16,
		15, 16, 17, 18, 19, 20,
		19, 20, 21, 22, 23, 24,
		23, 24, 25, 26, 27, 28,
		27, 28, 29, 30, 31, 0
	};
	//P box in i-round
	const __int8 perm5[32] = {
			15,  6, 19, 20,
			28, 11, 27, 16,
			 0, 14, 22, 25,
			 4, 17, 30,  9,
			 1,  7, 23, 13,
			31, 26,  2,  8,
			18, 12, 29,  5,
			21, 10,  3, 24
	};

	//IP last
	const __int8 perm6[64] = {
			39,  7, 47, 15, 55, 23, 63, 31,
			38,  6, 46, 14, 54, 22, 62, 30,
			37,  5, 45, 13, 53, 21, 61, 29,
			36,  4, 44, 12, 52, 20, 60, 28,
			35,  3, 43, 11, 51, 19, 59, 27,
			34,  2, 42, 10, 50, 18, 58, 26,
			33,  1, 41,  9, 49, 17, 57, 25,
			32,  0, 40,  8, 48, 16, 56, 24
	};

	//shift
	const __int8 sc[16] = { 1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1 };

	//sbox
	const __int8 sbox[8][4][16] = {
		{{14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7},
		{0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8},
		 {4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0},
		 {15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13}},

		{{15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10},
		 {3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5},
		 {0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15},
		 {13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9}},

		{{10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8},
		 {13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1},
		 {13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7},
		 {1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12}},

		{{7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15},
		 {13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9},
		 {10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4},
		 {3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14}},

		{{2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9},
		 {14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6},
		 {4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14},
		 {11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3}},

		{{12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11},
		 {10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8},
		 {9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6},
		 {4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13}},

		{{4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1},
		 {13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6},
		 {1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2},
		 {6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12}},

		{{13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7},
		 {1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2},
		 {7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8},
		 {2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11}} };
}

int main()
{
	byte Line[] = { 0x12,0x34,0x56,0xAB,0xCD,0x13,0x25,0x36,0x12,0x34,0x56,0xAB,0xCD,0x13,0x25,0x36 };
	unsigned long long Key = 0x1122334455667788;
	byte Line2[] = { 0x2F, 0xaf, 0x17, 0x00, 0x82, 0x9a, 0x64, 0xaA };
	DES Des;
	DES Des2;
	clock_t t0 = clock();
	Des.fileEncryption("data.txt", "2.txt", Key);
	clock_t t1 = clock();
	std::cout << "time: " << (double)(t1 - t0) / CLOCKS_PER_SEC << std::endl;

	t0 = clock();
	Des2.fileDecryption("2.txt", "dec.txt", Key);
	t1 = clock();
	std::cout << "time: " << (double)(t1 - t0) / CLOCKS_PER_SEC << std::endl;
	system("pause");
}

//+
Block DES::StrToBitset(std::string _Block)
{
	std::string convert;

	for (auto i : _Block)
	{
		std::bitset<8> tmp(i);
		for (auto j : tmp.to_string())
			convert.push_back(j);
	}
	Block result(convert);

	return result;
}
//+?
std::bitset<48> DES::GenerateKeyI(int NumberRound, bool Flag)
{
	if (Flag == ENCRYPTION)
		KeyShiftToLeft(NumberRound);
	if (Flag == DECRYPTION)
		KeyShiftToRight(NumberRound);
	std::bitset<48> Result;
	for (int i = 0; i < 48; i++)
	{
		Result[i] = CDKeyBitset[_DES::perm2[i]];
	}
	//-------------------------------------------------------
	strr = Result.to_string();
	debug8 << strr << std::endl;
	//----------------------------------------------------------

	return Result;
}


void DES::FirstIPSwap()
{
	for (uint i = 0; i < Blocks.size(); i++)
	{
		Block tmp = Blocks[i];
		for (uint j = 0; j < 64; j++)
		{
			Blocks[i][j] = tmp[_DES::perm3[j]];
		}
	}
}

void DES::LastIPSwap()
{
	for (uint i = 0; i < Blocks.size(); i++)
	{
		Block tmp = Blocks[i];
		for (uint j = 0; j < 64; j++)
		{
			Blocks[i][j] = tmp[_DES::perm6[j]];
		}
	}
}

void DES::KeyToCDKeyBitset(unsigned long long _Key)
{
	std::bitset<56>Tmp = _Key;
	Block KeyBitset;

	for (int i = 0; i < 8; i++)
	{
		int Counter = 0;
		for (int j = 0; j < 7; j++)
		{
			if (Tmp[j + i * 7] == 1)Counter++;
			KeyBitset[j + i * 8] = Tmp[j + i * 7];
		}

		if (Counter % 2 == 0)
			KeyBitset[(i + 1) * 8 - 1] = 1;
		else
			KeyBitset[(i + 1) * 8 - 1] = 0;
	}



	std::bitset<4> CharBitset;

	unsigned long long Res = 0;
	unsigned long long Sh;
	unsigned long long Base = 1;
	for (unsigned int i = 0; i < 56; i++) {
		Sh = Base << (64 - G[i]);
		Res |= ((KeyBitset.to_ullong() & Sh) >> (64 - G[i])) << (56 - i - 1);
	}
	CDKeyBitset = Res;
	//-------------------------------------------
	//strr = CDKeyBitset.to_string();
	//debug8 << strr <<  std::endl;
	//-------------------------------------------

	for (int i = 0; i < 14; i++)
	{
		for (int j = 0; j < 4; j++)
			CharBitset[j] = CDKeyBitset[j + i * 4];
		int tmp = CharBitset.to_ullong();
	}

}

Block DES::FanoRound(Block _Block, std::bitset<48> _KeyI, bool Flag)
{
	HalfBlock RightBlock;
	HalfBlock LeftBlock;
	for (int i = 0; i < 32; i++)
	{
		RightBlock[i] = _Block[32 + i];
		LeftBlock[i] = _Block[i];
	}
	Block Result;
	HalfBlock temp;
	if (Flag == ENCRYPTION)
	{
		//---------------------------------------------------------------
		strr = LeftBlock.to_string();
		debug6 << "\nBefore xor:" << strr << " //LEFT" << std::endl;
		//---------------------------------------------------------------
		temp = F(RightBlock, _KeyI);
		//---------------------------------------------------------------
		strr = temp.to_string();
		debug6 << "AFTER func:" << strr << " //RIGHT" << std::endl;
		//---------------------------------------------------------------
		LeftBlock ^= temp;
		//---------------------------------------------------------------
		strr = LeftBlock.to_string();
		debug6 << "After  xor:" << strr << std::endl;
		//---------------------------------------------------------------
		for (int i = 0; i < 32; i++)
		{
			Result[i] = RightBlock[i];
			Result[i + 32] = LeftBlock[i];
		}
	}
	if (Flag == DECRYPTION)
	{
		RightBlock ^= F(LeftBlock, _KeyI);
		for (int i = 0; i < 32; i++)
		{
			Result[i] = RightBlock[i];
			Result[i + 32] = LeftBlock[i];
		}
	}



	return Result;
}

HalfBlock DES::F(HalfBlock _RightBlock, std::bitset<48> _KeyI)
{
	HalfBlock Result;

	std::bitset<48> RightHalfBlockWithPBox;
	for (uint i = 0; i < 48; i++)
		RightHalfBlockWithPBox[i] = _RightBlock[_DES::perm4[i]];
	//----------------------------------------------------------------------------
	strr = RightHalfBlockWithPBox.to_string();
	debug << "::"  << strr << std::endl;
	//----------------------------------------------------------------------------

	RightHalfBlockWithPBox ^= _KeyI;
	//----------------------------------------------------------------------------
	strr = RightHalfBlockWithPBox.to_string();
	debug3 << "::" << strr << std::endl;

	strr = _KeyI.to_string();
	debug7 << strr << std::endl;
	//----------------------------------------------------------------------------
	std::vector<std::bitset<6>> Bbox;

	for (uint i = 0; i < 8; i++)
	{
		std::bitset<6> Tmp;
		Bbox.push_back(Tmp);
	}

	for (int i = 0; i < 48; i++)
		Bbox[i / 6][i % 6] = RightHalfBlockWithPBox[i];

	for (int i = 0; i < Bbox.size(); i++)
	{

		std::bitset<2> ColumnBitSet;
		ColumnBitSet[0] = Bbox[i][0];
		ColumnBitSet[1] = Bbox[i][5];

		std::bitset<4> LineBitSet;
		for (int j = 1; j < 5; j++)
			LineBitSet[j - 1] = Bbox[i][j];
		//int Column;
		//if (ColumnBitSet[0] == 0 && ColumnBitSet[1] == 0)  Column = 0; //номер строки
		//else if (ColumnBitSet[0] == 0 && ColumnBitSet[1] == 1)  Column = 1; //номер строки
		//else if (ColumnBitSet[0] == 1 && ColumnBitSet[1] == 0)  Column = 2; //номер строки
		//else if (ColumnBitSet[0] == 1 && ColumnBitSet[1] == 1)  Column = 3; //номер строки
		byte Column = ColumnBitSet.to_ullong();
		byte Line = LineBitSet.to_ullong();

		std::bitset<4> SBoxBitSet = _DES::sbox[i][Column][Line];
		strr = SBoxBitSet.to_string();
		debug4 << strr << std::endl;

		for (int j = 0; j < 4; j++)
		{
			Result[j + i * 4] = SBoxBitSet[j];
		}
	}

	HalfBlock Tmp = Result;

	for (int i = 0; i < 32; i++)
	{
		Result[i] = Tmp[_DES::perm5[i]];
	}
	strr = Result.to_string();
	debug5 << strr << std::endl;
	return Result;
}

void DES::KeyShiftToLeft(int ShiftRound)
{
	int ShiftValue = _DES::sc[ShiftRound];
	std::bitset<28> tmpK1, tmpK2;

	for (int i = 0; i < 28; i++) //Получение промежуточного 56-битового ключа в виде двух ключей по 28 бит
	{
		tmpK1[i] = CDKeyBitset[i];
		tmpK2[i] = CDKeyBitset[i+28];
	}
	if (ShiftRound == 0| ShiftRound == 1| ShiftRound == 8| ShiftRound == 15)
	{
		tmpK1 <<= 1;
		tmpK2 <<= 1;
	}
	else
	{
		tmpK1 <<= 2;
		tmpK2 <<= 2;
	}

	for (int i = 0; i < 28; i++)
	{
		CDKeyBitset[i] = tmpK1[i];
		CDKeyBitset[i + 28] = tmpK2[i];
	}
}

void DES::KeyShiftToRight(int ShiftRound)
{
	int ShiftValue = _DES::sc[ShiftRound];
	std::bitset<28> tmpK1, tmpK2;

	for (int i = 0; i < 28; i++) //Получение промежуточного 56-битового ключа в виде двух ключей по 28 бит
	{
		tmpK1[i] = CDKeyBitset[i];
		tmpK2[i] = CDKeyBitset[i + 28];
	}
	if (ShiftRound == 0 | ShiftRound == 1 | ShiftRound == 8 | ShiftRound == 15)
	{
		tmpK1 >>= 1;
		tmpK2 >>= 1;
	}
	else
	{
		tmpK1 >>= 2;
		tmpK2 >>= 2;
	}

	for (int i = 0; i < 28; i++)
	{
		CDKeyBitset[i] = tmpK1[i];
		CDKeyBitset[i + 28] = tmpK2[i];
	}
}

void DES::LineToBloks(byte _Line[], int _Size)
{
	for (uint i = 0; i < _Size / 8; i++)
	{
		std::string tmp = "";
		for (uint j = 0; j < 8; j++)
		{
			char x = _Line[j + i * 8];
			tmp += x;
		}
		Block _Block = StrToBitset(tmp);
		Blocks.push_back(_Block);
	}
}


void DES::fileEncryption(std::string _FileIn, std::string _FileOut, unsigned long long _Key)
{
	std::ifstream Input(_FileIn, std::ios::binary);
	std::ofstream Output(_FileOut, std::ios::binary);

	KeyToCDKeyBitset(_Key);

	std::bitset<48> RoundKeys[16];

	for (int i = 0; i < 16; i++)
	{
		RoundKeys[i] = GenerateKeyI(i, ENCRYPTION);
	}
	/*debug2 << "ПОЛУЧЕННЫЕ ДАННЫЕ:\n";
	debug2 << RoundKeys[0].to_string() << std::endl;*/
	while (!Input.eof())
	{
		std::bitset<64> Line;
		Input.read((char*)&Line, sizeof(std::bitset<64>));
		
		strr = Line.to_string();
		debug2 << strr << std::endl;
		
		for (int i = 0; i < 16; i++)
		{
			Line = FanoRound(Line, RoundKeys[i], ENCRYPTION);
		}
		
		Output.write((char*)&Line, sizeof(std::bitset<64>));
		Line = 0;
	}
	Input.close();
	Output.close();
}

void DES::fileDecryption(std::string _FileIn, std::string _FileOut, unsigned long long _Key)
{
	std::ifstream Input(_FileIn, std::ios::binary);
	std::ofstream Output(_FileOut, std::ios::binary);

	KeyToCDKeyBitset(_Key);

	std::bitset<48> RoundKeys[16];

	for (int i = 0; i < 16; i++)
	{
		RoundKeys[i] = GenerateKeyI(i, DECRYPTION);
	}

	while (!Input.eof())
	{
		std::bitset<64> Line;
		Input.read((char*)&Line, sizeof(std::bitset<64>));
		for (int i = 0; i < 16; i++)
		{
			Line = FanoRound(Line, RoundKeys[i], DECRYPTION);
		}
		Output.write((char*)&Line, sizeof(std::bitset<64>));
		Line = 0;
	}
	Input.close();
	Output.close();
}

