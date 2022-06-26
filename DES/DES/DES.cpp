#include "DES.h"
#include "chrono"


void DES::initial_file()
{
	path = "data.txt";
	int choise = 1;
	//открытие файла для чтения иходного текста и файла для записи шифротекста
	cout << "1 - Use default path (C://Users/gutro/Desktop/GIT 2.0/Курсовая/DES/DES/data.txt) \n2 - Enter path\n==>";

	cin >> choise;
	if (choise == 1) 
		ifstream in(path, std::ios::binary);
	else {
		cout << "\nEnter path data: ";
		cin >> path;
		ifstream in(path, std::ios::binary);
	}
	in.open(path);
	if (!in.is_open())	
		cout << "\nFile cannot open!" << endl;
	
	fileSize = getSizeFile();
	if (fileSize > 640)
		bigSize = true;
	in.close();
}

int64_t DES::getSizeFile()
{
	ifstream in(path, std::ios::binary);
	in.seekg(0, in.end);
	std::streamsize size = in.tellg();
	in.seekg(0, std::ios::beg);
	//cout << "\nFILE SIZE = " << size << endl;
	in.close();
	return size;
}

void DES::initial_permutation()
{
	bitset<64> tmp = data;
	int IP[64] =
	{
		57, 49, 41, 33, 25, 17,  9,  1,
		59, 51, 43, 35, 27, 19, 11,  3,
		61, 53, 45, 37, 29, 21, 13,  5,
		63, 55, 47, 39, 31, 23, 15,  7,
		56, 48, 40, 32, 24, 16,  8,  0,
		58, 50, 42, 34, 26, 18, 10,  2,
		60, 52, 44, 36, 28, 20, 12,  4,
		62, 54, 46, 38, 30, 22, 14,  6
	};
	for (int i = 0; i < 64; i++)
	{
		data.set(i, tmp.test(IP[i]));
	}
}

void DES::finaly_permutation()
{
	bitset<64> tmp = data;
	int FP[64] =
	{
		39,  7, 47, 15, 55, 23, 63, 31,
		38,  6, 46, 14, 54, 22, 62, 30,
		37,  5, 45, 13, 53, 21, 61, 29,
		36,  4, 44, 12, 52, 20, 60, 28,
		35,  3, 43, 11, 51, 19, 59, 27,
		34,  2, 42, 10, 50, 18, 58, 26,
		33,  1, 41,  9, 49, 17, 57, 25,
		32,  0, 40,  8, 48, 16, 56, 24
	};
	for (int i = 0; i < 64; i++)
	{
		data.set(i, tmp.test(FP[i]));
	}
}

void DES::encrypt()
{
	initial_file();
	ifstream in(path, std::ios::binary);
	ofstream output("ENCRYPT.txt", std::ios::binary);
	bitset<48> TMPblock48;
	bitset<32> TMPblock32[2];
	bitset<6> Sblock6[8];
	bitset<4>Sblock4[8];
	int S_BOX[8][4][16] = {
		{
			{ 14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7 },
	{ 0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8 },
	{ 4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0 },
	{ 15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13 }
		},
	{
		{ 15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10 },
	{ 3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5 },
	{ 0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15 },
	{ 13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9 }
	},
	{
		{ 10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8 },
	{ 13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1 },
	{ 13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7 },
	{ 1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12 }
	},
	{
		{ 7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15 },
	{ 13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9 },
	{ 10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4 },
	{ 3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14 }
	},
	{
		{ 2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9 },
	{ 14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6 },
	{ 4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14 },
	{ 11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3 }
	},
	{
		{ 12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11 },
	{ 10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8 },
	{ 9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6 },
	{ 4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13 }
	},
	{
		{ 4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1 },
	{ 13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6 },
	{ 1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2 },
	{ 6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12 }
	},
	{
		{ 13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7 },
	{ 1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2 },
	{ 7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8 },
	{ 2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11 }
	}
	},
		P[32] = {
		15,  6, 19, 20,
		28, 11, 27, 16,
		 0, 14, 22, 25,
		 4, 17, 30,  9,
		1,  7, 23, 13,
		31, 26,  2,  8,
		18, 12, 29,  5,
		21, 10,  3, 24
	};
	int position[2] = {0,0}, tmp=0;

	string temp;
	key_extension();

	while (!in.eof()) //получать и шифровать блоки пока не закончится исходный файл
	{
		in.read((char*)&data, sizeof(bitset<64>));
		temp = data.to_string();
		cout << "DATA: \n";
		cout << temp << endl;

		initial_permutation();
		for (int j = 0; j < 32; j++)//разделить блок на два подблока по 32 бита
		{
			leftBlock.set(j, data.test(j));
			rightBlock.set(j, data.test(j + 32));
		}
		//16 раундов шифрования
		for (int j = 0; j < 16; j++)
		{
			TMPblock48 = expanding_permutation(rightBlock);

			TMPblock48 ^= RoundKey[j]; // XOR операция над раундовым ключом и подблоком

			for (int it = 0; it < 48; it++) //разбиение 48-битного блока на 8 S-блоков по 6 бит
			{
				if (it < 6) Sblock6[0].set(it, TMPblock48.test(it));
				if (it >= 6 && it < 12) Sblock6[1].set(it - 6, TMPblock48.test(it));
				if (it >= 12 && it < 18) Sblock6[2].set(it - 12, TMPblock48.test(it));
				if (it >= 18 && it < 24) Sblock6[3].set(it - 18, TMPblock48.test(it));
				if (it >= 24 && it < 30) Sblock6[4].set(it - 24, TMPblock48.test(it));
				if (it >= 30 && it < 36) Sblock6[5].set(it - 30, TMPblock48.test(it));
				if (it >= 36 && it < 42) Sblock6[6].set(it - 36, TMPblock48.test(it));
				if (it >= 42 && it < 48) Sblock6[7].set(it - 42, TMPblock48.test(it));
			}
			//получение перестановкой 4-битовых S-блоков
			for (int it = 0; it < 8; it++) 
			{
				// определить число из таблицы
				if (Sblock6[it][0] == 0 && Sblock6[it][5] == 0)  position[0] = 0; //номер строки
				if (Sblock6[it][0] == 0 && Sblock6[it][5] == 1)  position[0] = 1; //номер строки
				if (Sblock6[it][0] == 1 && Sblock6[it][5] == 0)  position[0] = 2; //номер строки
				if (Sblock6[it][0] == 1 && Sblock6[it][5] == 1)  position[0] = 3; //номер строки

				tmp = 0;
				for (int _it = 1; _it < 5; _it++) //номер столбца в двоичной СС
				{
					tmp = tmp * 10 + Sblock6[it].test(_it);
				}
				position[1] = conv_to_dec(tmp); //номер столбца в 10 СС

				Sblock4[it] = S_BOX[it][position[0]][position[1]]; //задаем значение 4-битового битсета /не факт что так сработает констр. присваивания битсета/
				int swap;
				for (int i = 0; i < 2; i++)
				{
					swap = Sblock4[it].test(i);
					Sblock4[it].set(i, Sblock4[it].test(3 - i));
					Sblock4[it].set(3 - i, swap);
				}
			}

			//объединение восьми 4-битовых блоков в 32-битный блок
			int tmpB_it = 0;
			for (int it = 0; it < 8; it++)
			{
				for (int _it = 0; _it < 4; _it++)
				{
					TMPblock32[0].set(tmpB_it, Sblock6[it].test(_it));
					tmpB_it++;
				}
			}

			TMPblock32[1] = TMPblock32[0];    //перестановка после S-блоков
			for (int it = 0; it < 32; it++) 
			{
				TMPblock32[0].set(it, TMPblock32[1].test(P[it]));
			}

			leftBlock ^= TMPblock32[0]; //XOR операция левого и правого блока(после преобразований правого)
			//если это не последний раунд, то меняем местами левый и правый блок
			if (j != 15) {
				TMPblock32[0] = leftBlock;
				leftBlock = rightBlock;
				rightBlock = TMPblock32[0];
			}
		}
		//объединение блоков после шифрования
		for (int i = 0; i < 64; i++)
		{
			if (i < 32)
				data.set(i, leftBlock.test(i));
			else
				data.set(i, rightBlock.test(i-32));
		}
		finaly_permutation();
		
		temp = data.to_string();
		cout << "ecr data:\n";
		cout << temp << endl;
		output.write((char*)&data, sizeof(bitset<64>));
	}
	
}

void DES::decrypt()
{
	ofstream output("DECRYPT.txt", std::ios::binary);
	ifstream in("ENCRYPT.txt", std::ios::binary);
	bitset<48> TMPblock48;
	bitset<32> TMPblock32[2];
	bitset<6> Sblock6[8];
	bitset<4>Sblock4[8];
	int S_BOX[8][4][16] = {
		{
			{ 14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7 },
	{ 0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8 },
	{ 4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0 },
	{ 15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13 }
		},
	{
		{ 15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10 },
	{ 3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5 },
	{ 0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15 },
	{ 13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9 }
	},
	{
		{ 10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8 },
	{ 13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1 },
	{ 13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7 },
	{ 1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12 }
	},
	{
		{ 7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15 },
	{ 13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9 },
	{ 10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4 },
	{ 3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14 }
	},
	{
		{ 2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9 },
	{ 14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6 },
	{ 4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14 },
	{ 11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3 }
	},
	{
		{ 12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11 },
	{ 10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8 },
	{ 9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6 },
	{ 4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13 }
	},
	{
		{ 4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1 },
	{ 13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6 },
	{ 1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2 },
	{ 6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12 }
	},
	{
		{ 13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7 },
	{ 1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2 },
	{ 7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8 },
	{ 2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11 }
	}
	},
		P[32] = {
		15,  6, 19, 20,
		28, 11, 27, 16,
		 0, 14, 22, 25,
		 4, 17, 30,  9,
		1,  7, 23, 13,
		31, 26,  2,  8,
		18, 12, 29,  5,
		21, 10,  3, 24
	};
	int position[2] = { 0,0 }, tmp = 0;

	//string temp;
	//key_extension();

	while (!in.eof()) //получать и шифровать блоки пока не закончится исходный файл
	{
		in.read((char*)&data, sizeof(bitset<64>));
		/*temp = data.to_string();
		cout << "DATA: \n";
		cout << temp << endl;*/

		initial_permutation();
		for (int j = 0; j < 32; j++)//разделить блок на два подблока по 32 бита
		{
			leftBlock.set(j, data.test(j));
			rightBlock.set(j, data.test(j + 32));
		}
		//16 раундов шифрования
		for (int j = 0; j < 16; j++)
		{
			TMPblock48 = expanding_permutation(leftBlock);

			TMPblock48 ^= RoundKey[15-j]; // XOR операция над раундовым ключом и подблоком

			for (int it = 0; it < 48; it++) //разбиение 48-битного блока на 8 S-блоков по 6 бит
			{
				if (it < 6) Sblock6[0].set(it, TMPblock48.test(it));
				if (it >= 6 && it < 12) Sblock6[1].set(it - 6, TMPblock48.test(it));
				if (it >= 12 && it < 18) Sblock6[2].set(it - 12, TMPblock48.test(it));
				if (it >= 18 && it < 24) Sblock6[3].set(it - 18, TMPblock48.test(it));
				if (it >= 24 && it < 30) Sblock6[4].set(it - 24, TMPblock48.test(it));
				if (it >= 30 && it < 36) Sblock6[5].set(it - 30, TMPblock48.test(it));
				if (it >= 36 && it < 42) Sblock6[6].set(it - 36, TMPblock48.test(it));
				if (it >= 42 && it < 48) Sblock6[7].set(it - 42, TMPblock48.test(it));
			}
			//получение перестановкой 4-битовых S-блоков
			for (int it = 0; it < 8; it++)
			{
				// определить число из таблицы
				if (Sblock6[it][0] == 0 && Sblock6[it][5] == 0)  position[0] = 0; //номер строки
				if (Sblock6[it][0] == 0 && Sblock6[it][5] == 1)  position[0] = 1; //номер строки
				if (Sblock6[it][0] == 1 && Sblock6[it][5] == 0)  position[0] = 2; //номер строки
				if (Sblock6[it][0] == 1 && Sblock6[it][5] == 1)  position[0] = 3; //номер строки

				tmp = 0;
				for (int _it = 1; _it < 5; _it++) //номер столбца в двоичной СС
				{
					tmp = tmp * 10 + Sblock6[it].test(_it);
				}
				position[1] = conv_to_dec(tmp); //номер столбца в 10 СС

				Sblock4[it] = S_BOX[it][position[0]][position[1]]; //задаем значение 4-битового битсета
				int swap;
				for (int i = 0; i < 2; i++)
				{
					swap = Sblock4[it].test(i);
					Sblock4[it].set(i, Sblock4[it].test(3 - i));
					Sblock4[it].set(3 - i, swap);
				}
			}

			//объединение восьми 4-битовых блоков в 32-битный блок
			int tmpB_it = 0;
			for (int it = 0; it < 8; it++)
			{
				for (int _it = 0; _it < 4; _it++)
				{
					TMPblock32[0].set(tmpB_it, Sblock6[it].test(_it));
					tmpB_it++;
				}
			}

			TMPblock32[1] = TMPblock32[0];    //перестановка после S-блоков
			for (int it = 0; it < 32; it++)
			{
				TMPblock32[0].set(it, TMPblock32[1].test(P[it]));
			}

			rightBlock ^= TMPblock32[0]; //XOR операция левого и правого блока(после преобразований правого)
			//если это не последний раунд, то меняем местами левый и правый блок
			if (j != 15) {
				TMPblock32[0] = rightBlock;
				rightBlock = leftBlock;
				leftBlock = TMPblock32[0];
			}
		}
		//объединение блоков после шифрования
		for (int i = 0; i < 64; i++)
		{
			if (i < 32)
				data.set(i, leftBlock.test(i));
			else
				data.set(i, rightBlock.test(i - 32));
		}
		finaly_permutation();

		/*temp = data.to_string();
		cout << "ecr data:\n";
		cout << temp << endl;*/
		output.write((char*)&data, sizeof(bitset<64>));
	}
}

bitset<48> DES::expanding_permutation(bitset<32> &block)
{
	int Pbox[] = {
		31, 0, 1, 2, 3, 4,
		3, 4, 5, 6, 7, 8,
		7, 8, 9, 10, 11, 12,
		11, 12, 13, 14, 15, 16,
		15, 16, 17, 18, 19, 20,
		19, 20, 21, 22, 23, 24,
		23, 24, 25, 26, 27, 28,
		27, 28, 29, 30, 31, 0
	};
	bitset<48> EPblock;
	for (int i = 0; i < 48; i++)
	{
		EPblock.set(i, block.test(Pbox[i]));
	}
	return EPblock;
}

void DES::key_extension()
{
	bitset<28> tmpKey1, tmpKey2;
	bitset<56> tmpKEY56;
	int P1[] = {
		57, 49, 41, 33, 25, 17, 9,
		1, 58, 50, 42, 34, 26, 18,
		10, 2, 59, 51, 43,  35, 27,
		19, 11, 3, 60, 52, 44, 36
	},
		P2[] = {
		63, 55, 47, 39, 31, 23, 15,
		7, 62, 54, 46, 38, 30, 22,
		14, 6, 61, 53, 45, 37, 29,
		21, 13, 5, 28, 20, 12, 4
	},
		RP[] = {
		13, 16, 10, 23, 0, 4, 2, 27, 14, 5, 20, 9, 
		22, 18, 11, 3, 25, 7, 15, 6, 26, 19, 12, 1, 
		40, 51, 30, 37, 46, 54, 29, 39, 50, 44, 32, 47,
		43, 48, 38, 55, 33, 52, 45, 41, 49, 35, 28, 31
	};

	//invert key
	bool tmp;
	for (int i = 0; i < 32; i++)
	{
		tmp = key.test(i);
		key.set(i, key.test(63-i));
		key.set(63 - i, tmp);
	}
	for (int i = 0; i < 28; i++) //Получение промежуточного 56-битового ключа в виде двух ключей по 28 бит
	{
		tmpKey1.set(i,  key.test(P1[i] - 1) );
		tmpKey2.set(i,  key.test(P2[i] - 1) );
	}

	for (int i = 0; i < 16; i++) //Получение 16 ключей раундов
	{
		if (i == 0 | 1 | 8 | 15) //сдвиг каждого подключа
		{
			tmpKey1 <<= 1;
			tmpKey2 <<= 1;
		}
		else {
			tmpKey1 <<= 2;
			tmpKey2 <<= 2;
		}
		for (int j = 0; j < 56; j++) //объединение двух подключей в один 56-битный ключ
		{
			if (j < 28)
			{
				tmpKEY56.set(j, tmpKey1.test(j));
				continue;
			}
			tmpKEY56.set(j, tmpKey2.test(j - 28));
		}
		for (int j = 0; j < 48; j++) //конечная перестановка для получения раундового ключа
		{
			RoundKey[i].set(j, tmpKEY56.test(RP[j]));
		}
	}
	
}

int DES::conv_to_dec(int count)
{
	switch (count)
	{
	case 0:
		return 0;
	case 1:
		return 1;
	case 10:
		return 2;
	case 11:
		return 3;
	case 100:
		return 4;
	case 101:
		return 5;
	case 110:
		return 6;
	case 111:
		return 7;
	case 1000:
		return 8;
	case 1001:
		return 9;
	case 1010:
		return 10;
	case 1011:
		return 11;
	case 1100:
		return 12;
	case 1101:
		return 13;
	case 1110:
		return 14;
	case 1111:
		return 15;
	default:
		cout << "\n\t ERROR IN CONV_TO_DEC FUNCTION!\n";
		system("pause");
		exit(100);
	}
}

int64_t DES::sizeEncrFile()
{
	ifstream out("OUTPUT.txt");
	out.seekg(0, in.end);
	std::streamsize size = out.tellg();
	out.seekg(0, std::ios::beg);
	out.close();
	return size;
}