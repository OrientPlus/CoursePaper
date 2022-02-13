#include "DES.h"

void DES::get_data()
{
	char ch;
	int j = 0, pos = 0;
	path = "C://Users/gutro/Desktop/GIT 2.0/Курсовая/DES/DES/dataPng.hg";

	//открытие файла для чтения иходного текста и файла для записи шифротекста
	cout << "Enter path data: ";
	ifstream in(path, std::ios::binary);
	ofstream out("outputBin.bin", ios::binary);
	if (!in.is_open())
	{
		cout << "\nFile cannot open!" << endl;
	}

	fileSize = getSizeFile(in);
	if (fileSize > 640)
	{
		bigSize = true;
	}

	//запись исходного текста в 10 битсетов
	while (in.get(ch) && pos<10)
	{
		if (j >= 64) {
			pos++; j = 0;
		}
		for (int i = 0; i <= 7; i++)
		{
			unsigned int bit = (((int)ch & (int)pow(2, i)) > 0 ? 1 : 0);
			data[pos].set(j, bit);
			j++;
		}
	}

	out << "BITSIZE " << pos << " = " << data[pos].size() << endl;
	for (int i = 0; i <= pos; i++) //промежуточнная запись битсетов в файл
	{
		out << data[pos];
	}
	in.close();
	out.close();
}

int64_t DES::getSizeFile(ifstream& in)
{
	in.seekg(0, in.end);
	std::streamsize size = in.tellg();
	in.seekg(0, std::ios::beg);
	cout << "\nFILE SIZE = " << size << endl;
	return size;
}

void DES::initial_permutation(int it)
{
	bitset<64> tmp = data[it];
	int IP[64] =
	{
		57, 49, 41, 33, 25, 17, 9, 1,
		59, 51, 43, 35, 27, 19, 11, 3,
		61, 53, 45, 37, 29, 21, 13, 5,
		63, 55, 47, 39, 31, 23, 15, 7,
		56, 48, 40, 32, 24, 16, 8, 0,
		58, 50, 42, 34, 26, 18, 10, 2,
		60, 52, 44, 36, 28, 20, 12, 4,
		62, 54, 46, 38, 30, 22, 14, 6
	};
	for (int i = 0; i < 64; i++)
	{
		data[it].set(i, tmp.test(IP[i]));
	}
}

void DES::finaly_permutation(int it)
{
	bitset<64> tmp = data[it];
	int FP[64] =
	{
		40, 8, 48, 16, 56, 24, 64, 32,
		39, 7, 47, 15, 55, 23, 63, 31,
		38, 6, 46, 14, 54, 22, 62, 30,
		37, 5, 45, 13, 53, 21, 61, 29,
		36, 4, 44, 12, 52, 20, 60, 28,
		35, 3, 43, 11, 51, 19, 59, 27,
		34, 2, 42, 10, 50, 18, 58, 26,
		33, 1, 41,  9, 49, 17, 57, 25
	};
	for (int i = 0; i < 64; i++)
	{
		data[it].set(i, tmp.test(FP[i]));
	}
}

void DES::encrypt()
{
	bitset<48> TMPblock48;
	bitset<32> TMPblock32[2];
	bitset<6> Sblock6[8];
	bitset<4>Sblock4[8];
	int S1[4][16] = {
			{ 14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7 },
			{ 0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8 },
			{ 4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0 },
			{ 15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13 }
	},
		S2[4][16] = {
			{ 15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10 },
			{ 3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5 },
			{ 0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15 },
			{ 13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9 }
	},
		S3[4][16] = {
			{ 10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8 },
			{ 13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1 },
			{ 13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7 },
			{ 1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12 }
	},
		S4[4][16] = {
			{ 7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15 },
			{ 13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9 },
			{ 10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4 },
			{ 3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14 }
	},
		S5[4][16] = {
			{ 2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9 },
			{ 14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6 },
			{ 4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14 },
			{ 11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3 }
	},
		S6[4][16] = {
			{ 12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11 },
			{ 10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8 },
			{ 9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6 },
			{ 4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13 }
	},
		S7[4][16] = {
			{ 4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1 },
			{ 13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6 },
			{ 1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2 },
			{ 6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12 }
	},
		S8[4][16] = {
			{ 13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7 },
			{ 1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2 },
			{ 7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8 },
			{ 2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11 }
	},
		P[32] = {
		16,  7, 20, 21,
		29, 12, 28, 17,
		1, 15, 23, 26,
		5, 18, 31, 10,
		2,  8, 24, 14,
		32, 27,  3,  9,
		19, 13, 30,  6,
		22, 11,  4, 25
	};
	int position[2] = {0,0}, tmp=0;
	get_data();
	key_extension();
	if (bigSize)
	{
		for (int i = 0; i < 10; i++) //шифрование 10 блоков исходного текста
		{
			initial_permutation(i);

			for (int j = 0; j < 32; j++)//разделить блок на два подблока по 32 бита
			{
				leftBlock.set(j, data[i].test(j));
				rightBlock.set(j, data[i].test(j + 32));
			}
			for (int j = 0; j < 16; j++)//16 раундов шифрования
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
					if (it >= 36 && it < 40) Sblock6[6].set(it - 36, TMPblock48.test(it));
					if (it >= 40 && it < 48) Sblock6[7].set(it - 40, TMPblock48.test(it));
				}

				for (int it = 0; it < 8; it++) //получение перестановкой 4-битовых S-блоков
				{
					// определить число из таблицы
					if (Sblock6[it][0] == 0 && Sblock6[it][5] == 0)  position[0] = 0; //номер строки
					if (Sblock6[it][0] == 0 && Sblock6[it][5] == 1)  position[0] = 1; //номер строки
					if (Sblock6[it][0] == 1 && Sblock6[it][5] == 0)  position[0] = 2; //номер строки
					if (Sblock6[it][0] == 1 && Sblock6[it][5] == 1)  position[0] = 3; //номер строки


					for (int _it = 1; _it < 5; _it++) //номер столбца в двоичной СС
					{
						tmp = tmp * 10 + Sblock6[it].test(_it);
					}
					position[1] = get_dec(tmp); //номер столбца в 10 СС
					
					Sblock4[it] = S1[position[0]][position[1]]; //задаем значение 4-битового битсета /не факт что так сработает конс. присваивания битсета/
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
					TMPblock32[0].set(it, TMPblock32[1].test(P[it] - 1));
				}


				leftBlock ^= TMPblock32[0]; //XOR операция левого и правого блока(после преобразований правого)

				if (j == 15) break; //если это не последний раунд, то меняем местами левый и правый блок
				else {
					for (int it = 0; it < 32; it++)
					{
						TMPblock32[0] = leftBlock;
						leftBlock = rightBlock;
						rightBlock = TMPblock32[0];
					}
				}
			}

			finaly_permutation(i);
		}
	}
}

bitset<48> DES::expanding_permutation(bitset<32> &block)
{
	int Pbox[] = {
		32, 1, 2, 3, 4, 5,
		4, 5, 6, 7, 8, 9,
		8, 9, 10, 11, 12, 13,
		12, 13, 14, 15, 16, 17,
		16, 17, 18, 19, 20, 21,
		20, 21, 22, 23, 24, 25,
		24, 25, 26, 27, 28, 29,
		28, 29, 30, 31, 32, 1
	};
	bitset<48> EPblock;
	for (int i = 0; i < 48; i++)
	{
		EPblock.set(i, (block.test(Pbox[i])-1));
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
		14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 
		23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2, 
		41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
		44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32
	};

	for (int i = 0; i < 28; i++) //Получение промежуточного 56-битового ключа в виде двух ключей по 28 бит
	{
		tmpKey1.set(i, ( key.test(P1[i]) - 1) );
		tmpKey2.set(i, ( key.test(P2[i]) - 1) );
	}

	for (int i = 0; i < 16; i++) //Получение 16 ключей раундов
	{
		if (i == 1 | 2 | 9 | 16) //сдвиг каждого подключа
		{
			tmpKey1 << 1;
			tmpKey2 << 1;
		}
		else {
			tmpKey1 << 2;
			tmpKey2 << 2;
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
			RoundKey[i].set(j, ( tmpKEY56.test(RP[j]) - 1) ); //некорректное обращение к битсету tmpKEY56, out of range на +-30 итерации
		}
	}
	
}

int DES::get_dec(int count)
{
	int res = 0, tmp=0;
	for (int i = 0; i < 4; i++)
	{
		tmp = count / 10;
		count = count % 10;
		res = res + res * pow(2, i);
	}
	return res;
}