#include "LOKI.h"

void LOKI::init_file()
{
	ifstream in;
	path = "data.pdf";
	int choise = 1;
	//открытие файла для чтения иходного текста и файла для записи шифротекста
	cout << "1 - Use default path (C://Users/gutro/Desktop/GIT 2.0/Курсовая/DES/DES/data.txt) \n2 - Enter path\n=>";

	//cin >> choise;
	if (choise == 1)
		in.open(path, std::ios::binary);
	else {
		cout << "\nEnter path data: ";
		cin >> path;
		in.open(path, std::ios::binary);
	}
	if (!in.is_open())
	{
		cout << "\nFile cannot open!" << endl;
		system("pause");
		exit(-10);
	}
	in.close();

	sizeSourceFile = getSizeFile(path);
}

void LOKI::encrypt()
{
	init_file();
	Enc_filename = path;
	Enc_filename.insert(0, "ENC_");
	ifstream in(path, std::ios::binary);
	ofstream output(Enc_filename, std::ios::binary);

	key_extension();

	//получать и шифровать блоки пока не закончится исходный файл
	while (!in.eof())
	{
		in.read((char*)&data, sizeof(BLOCK_128));

		for (int i = 0; i < 16; i++)
			round(i, ENCR);

		output.write((char*)&data, sizeof(BLOCK_128));
	}
	sizeEncFile = getSizeFile(Enc_filename);
}

void LOKI::decrypt()
{
	path.insert(0, "DEC_");
	ifstream in(Enc_filename, std::ios::binary);
	ofstream output(path, std::ios::binary);

	//получать и шифровать блоки пока не закончится исходный файл
	while (!in.eof())
	{
		in.read((char*)&data, sizeof(BLOCK_128));
		for (int i = 0; i < 16; i++)
			round(i, DECR);

		output.write((char*)&data, sizeof(BLOCK_128));
	}
	sizeDecFile = getSizeFile(path);
}

void LOKI::round(int j, bool flag)
{
	//разделение блока на правый и левый подблок
	for (int i = 0; i < 64; i++)
	{
		leftBlock[i] = data[i];
		rightBlock[i] = data[i + 64];
	}

	if (flag == ENCR)
	{
		rightBlock ^= RoundKey[j * 3];
		leftBlock ^= F(rightBlock, RoundKey[(j * 3) + 1]);
		rightBlock ^= RoundKey[(j * 3) + 2];
	}
	if (flag == DECR)
	{
		leftBlock ^= RoundKey[47 - (j * 3)];
		rightBlock ^= F(leftBlock, RoundKey[47 - ((j * 3) + 1)]);
		leftBlock ^= RoundKey[47 - ((j * 3) + 2)];
	}

	//объединение правого и левого блока в один блок
	for (int i = 0; i < 64; i++)
	{
		data[i] = rightBlock[i];
		data[i + 64] = leftBlock[i];
	}
}

void LOKI::key_extension()
{
	BLOCK_64 key_subBlock[4], temp;

	//разделяем ключ на 4 блока по 64 бит
	for (int i = 0; i < 64; i++)
	{
		key_subBlock[0][i] = key[i];
		key_subBlock[1][i] = key[i + 64];
		key_subBlock[2][i] = key[i + 128];
		key_subBlock[3][i] = key[i + 192];
	}

	for (int i = 0; i < 48; i++)
	{
		temp = 0x9E3779B97F4A7C15 * i;
		temp ^= key_subBlock[1] ^ key_subBlock[2];
		key_subBlock[0] ^= F(temp, key_subBlock[3]);
		if (i != 47)
		{
			temp = key_subBlock[0];
			key_subBlock[0] = key_subBlock[1];
			key_subBlock[1] = key_subBlock[2];
			key_subBlock[2] = key_subBlock[3];
			key_subBlock[3] = temp;
		}

		RoundKey[i] = key_subBlock[0];
	}
}

BLOCK_64 LOKI::F(BLOCK_64 block1, BLOCK_64 block2)
{
	BLOCK_96 ep_block;
	BLOCK_32 subKey1, subKey2;
	for (int i = 0; i < 32; i++)
	{
		subKey1[i] = block2[i];
		subKey2[i] = block2[i + 32];
	}
	block1 = KP(block1, subKey2);
	ep_block = E(block1);

	block1 = apply_Sboxes_layer1(ep_block);
	
	block1 = P(block1);

	block1 = apply_Sboxes_layer2(block1, subKey1);

	return block1;
}

//key permutation перестановка в функции F
BLOCK_64 LOKI::KP(BLOCK_64 block, BLOCK_32 key)
{
	BLOCK_32 subBlock1, subBlock2;
	int temp;

	for (int i = 0; i < 32; i++)
	{
		subBlock1[i] = block[i];
		subBlock2[i] = block[i + 32];
	}

	//если бит ключа == 1, свапаем бит в этой позиции в подблоках данных 
	for (int i = 0; i < 32; i++)
	{
		if (key.test(i) == true)
		{
			temp = subBlock1[i];
			subBlock1[i] = subBlock2[i];
			subBlock2[i] = temp;
		}
	}

	for (int i = 0; i < 32; i++)
	{
		block[i] = subBlock1[i];
		block[i + 32] = subBlock2[i];
	}
	return block;
}

//expanding перестановка в F функции 
BLOCK_96 LOKI::E(BLOCK_64 block)
{
	BLOCK_96 result;
	int it = 0;

	for (int i = 0; i < 9; i++)
	{
		switch (i)
		{
		case 0:
			for (int j = 4; j >= 0; j--)
			{
				result[it] = block[i];
				it++;
			}
			continue;
		case 1:
			for (int j = 63; j >= 56; j--)
			{
				result[it] = block[i];
				it++;
			}
			continue;
		case 2:
			for (int j = 58; j >= 48; j--)
			{
				result[it] = block[i];
				it++;
			}
			continue;
		case 3:
			for (int j = 52; j >= 40; j--)
			{
				result[it] = block[i];
				it++;
			}
			continue;
		case 4:
			for (int j = 42; j >= 32; j--)
			{
				result[it] = block[i];
				it++;
			}
			continue;
		case 5:
			for (int j = 34; j >= 24; j--)
			{
				result[it] = block[i];
				it++;
			}
			continue;
		case 6:
			for (int j = 28; j >= 16; j--)
			{
				result[it] = block[i];
				it++;
			}
			continue;
		case 7:
			for (int j = 18; j >= 8; j--)
			{
				result[it] = block[i];
				it++;
			}
			continue;
		case 8:
			for (int j = 12; j >= 0; j--)
			{
				result[it] = block[i];
				it++;
			}
			continue;
		default:
			exit(-100);
		}
	}
	return result;
}

//рименение S-боксов 1 слоя
BLOCK_64 LOKI::apply_Sboxes_layer1(BLOCK_96 ep_block)
{
	BLOCK_64 result;
	bitset<13> S13;
	bitset<11> S11;
	bitset<8> S8[8];
	WORD word;
	int it = 0;

	//разбиение и применение S-боксов
	for (int i = 0; i < 8; i++)
	{
		switch (i)
		{
		case 0:
			for (int i = 0; i < 13; i++)
				S13[i] = ep_block[i];
			word = S13.to_ulong();
	
			S8[0] = apply_S1(word);
			continue;
		case 1:
			it = 0;
			for (int i = 13; i < 24; i++)
			{
				S11[it] = ep_block[i];
				it++;
			}
			word = S11.to_ulong();
			
			S8[1] = apply_S2(word);
			continue;
		case 2:
			it = 0;
			for (int i = 24; i < 37; i++)
			{
				S13[it] = ep_block[i];
				it++;
			}
			word = S13.to_ulong();

			S8[2] = apply_S1(word);
			continue;
		case 3:
			it = 0;
			for (int i = 37; i < 48; i++)
			{
				S11[it] = ep_block[i];
				it++;
			}
			word = S11.to_ulong();

			S8[1] = apply_S2(word);
			continue;
		case 4:
			it = 0;
			for (int i = 48; i < 59; i++)
			{
				S11[it] = ep_block[i];
				it++;
			}
			word = S11.to_ulong();

			S8[1] = apply_S2(word);
			continue;
		case 5:
			it = 0;
			for (int i = 59; i < 72; i++)
			{
				S13[it] = ep_block[i];
				it++;
			}
			word = S13.to_ulong();

			S8[5] = apply_S1(word);
			continue;
		case 6:
			it = 0;
			for (int i = 72; i < 83; i++)
			{
				S11[it] = ep_block[i];
				it++;
			}
			word = S11.to_ulong();

			S8[1] = apply_S2(word);
			continue;
		case 7:
			it = 0;
			for (int i = 83; i < 96; i++)
			{
				S13[it] = ep_block[i];
				it++;
			}
			word = S13.to_ulong();

			S8[7] = apply_S1(word);
			continue;
		}
	}

	//объединение 8-битных S-box в один блок 64 бита
	for (int i = 0; i < 8; i++)
	{
		result[i] = S8[0][i];
		result[i+8] = S8[1][i];
		result[i+16] = S8[2][i];
		result[i+24] = S8[3][i];
		result[i+32] = S8[4][i];
		result[i+40] = S8[5][i];
		result[i+48] = S8[6][i];
		result[i+56] = S8[7][i];
	}
	return result;
}

WORD LOKI::my_pow(WORD word, int n)
{
	for (int i = 0; i < n; i++)
	{
		word = word * word;
	}
	return word;
}

//перестановка после первого слоя S-боксов
BLOCK_64 LOKI::P(BLOCK_64 block)
{
	int Perm[] = { 56, 48, 40, 32, 24, 16, 8, 0, 57, 49, 41, 33, 25, 17, 9, 1,
					58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3,
					60, 52, 44, 36, 28, 20, 12, 4, 61, 53, 45, 37, 29, 21, 13, 5,
					62, 54, 46, 38, 30, 22, 14, 6, 63, 55, 47, 39, 31, 23, 15, 7 };
	BLOCK_64 temp = block;

	for (int i = 0; i < 64; i++)
		block[i] = temp[Perm[i]];

	return block;
}

//рименение S-боксов 2 слоя
BLOCK_64 LOKI::apply_Sboxes_layer2(BLOCK_64 block, BLOCK_32 key)
{
	BLOCK_64 result;
	bitset<3> S3[4];
	bitset<5> S5[4];
	bitset<13> S13;
	bitset<11> S11;
	bitset<8> S8[8];
	WORD word;
	int it = 0;

	//разделяем блок на 8 восьмибитных подблоков
	for (int i = 0; i < 8; i++)
	{
		S8[0][i] = block[i];
		S8[1][i] = block[i + 8];
		S8[2][i] = block[i + 16];
		S8[3][i] = block[i + 24];
		S8[4][i] = block[i + 32];
		S8[5][i] = block[i + 40];
		S8[6][i] = block[i + 48];
		S8[7][i] = block[i + 56];
	}

	for (int i = 0; i < 8; i++)
	{
		switch (i)
		{
			case 0:
				it = 0;
				for (int j = 0; j < 3; j++)
				{
					S11[it] = key[j];
					it++;
				}
				for (int i = 0; i < 8; i++)
				{
					S11[it] = S8[0][i];
					it++;
				}
				word = S11.to_ulong();
				S8[0] = apply_S1(word);
				continue;
			case 1:
				it = 0;
				for (int j = 3; j < 6; j++)
				{
					S11[it] = key[j];
					it++;
				}
				for (int i = 0; i < 8; i++)
				{
					S11[it] = S8[1][i];
					it++;
				}
				word = S11.to_ulong();
				S8[1] = apply_S1(word);
				continue;
			case 2:
				it = 0;
				for (int j = 6; j < 11; j++)
				{
					S13[it] = key[j];
					it++;
				}
				for (int i = 0; i < 8; i++)
				{
					S13[it] = S8[2][i];
					it++;
				}
				word = S13.to_ulong();
				S8[2] = apply_S2(word);
				continue;
			case 3:
				it = 0;
				for (int j = 11; j < 16; j++)
				{
					S13[it] = key[j];
					it++;
				}
				for (int i = 0; i < 8; i++)
				{
					S13[it] = S8[3][i];
					it++;
				}
				word = S13.to_ulong();
				S8[3] = apply_S2(word);
				continue;
			case 4:
				it = 0;
				for (int j = 16; j < 19; j++)
				{
					S11[it] = key[j];
					it++;
				}
				for (int i = 0; i < 8; i++)
				{
					S11[it] = S8[4][i];
					it++;
				}
				word = S11.to_ulong();
				S8[4] = apply_S1(word);
				continue;
			case 5:
				it = 0;
				for (int j = 19; j < 22; j++)
				{
					S11[it] = key[j];
					it++;
				}
				for (int i = 0; i < 8; i++)
				{
					S11[it] = S8[5][i];
					it++;
				}
				word = S11.to_ulong();
				S8[5] = apply_S1(word);
				continue;
			case 6:
				it = 0;
				for (int j = 22; j < 27; j++)
				{
					S13[it] = key[j];
					it++;
				}
				for (int i = 0; i < 8; i++)
				{
					S13[it] = S8[6][i];
					it++;
				}
				word = S13.to_ulong();
				S8[6] = apply_S2(word);
				continue;
			case 7:
				it = 0;
				for (int j = 27; j < 32; j++)
				{
					S13[it] = key[j];
					it++;
				}
				for (int i = 0; i < 8; i++)
				{
					S13[it] = S8[7][i];
					it++;
				}
				word = S13.to_ulong();
				S8[7] = apply_S2(word);
				continue;
		}
	}

	//объединение 8-битных S-box в один блок 64 бита
	for (int i = 0; i < 8; i++)
	{
		result[i] = S8[0][i];
		result[i + 8] = S8[1][i];
		result[i + 16] = S8[2][i];
		result[i + 24] = S8[3][i];
		result[i + 32] = S8[4][i];
		result[i + 40] = S8[5][i];
		result[i + 48] = S8[6][i];
		result[i + 56] = S8[7][i];
	}
	return result;
}

BLOCK_8 LOKI::apply_S1(WORD word)
{
	BLOCK_8 result;

	word ^= 0x1FFF;
	word = my_pow(word, 3);
	result = word % 0x2911;
	result &= 0xFF;

	return result;
}

BLOCK_8 LOKI::apply_S2(WORD word)
{
	BLOCK_8 result;

	word ^= 0x7FF;
	word = my_pow(word, 3);
	result = word % 0xAA7;
	result &= 0xFF;

	return result;
}

int64_t LOKI::getSizeFile(string path_)
{
	fstream file(path_);
	file.seekg(0, file.end);
	streamsize size = file.tellg();
	file.seekg(0, std::ios::beg);
	file.close();
	return size/1024 + 1;
}