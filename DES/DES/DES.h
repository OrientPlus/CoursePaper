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
	void get_data()
	{
		cout << "Enter path data: ";
		path = "C://Users/gutro/Desktop/GIT 2.0/Курсовая/DES/DES/data.txt";
		ifstream in(path, std::ios::binary);
		//ofstream out("outputBin.txt", ios::binary);
		if (!in.is_open())
		{
			cout << "\nFile cannot open!" << endl;
		}
		fileSize = getSizeFile(&path, in);

		//считать массив из допустим 1024 битиков во временное хранилище
		//переместить в массив битсетов 
		char ch;
		int j = 0, pos=0;
	while (in.get(ch))
		{
		if (j >= 64) { pos++; j = 0; }
			for (int i = 7; i >= 0; i--)
			{
				unsigned int bit = (((int)ch & (int)pow(2, i)) > 0 ? 1 : 0);
				data[pos].set(j, bit);
				j++;
			}
		}
	in.close();
	}

	void printBinary()
	{
		ifstream f("data.txt", ios::binary);
		ofstream o("OutputBinary.txt", ios::binary);
		char ch;
		if (!f)
		{
			cout << "Error opening file!" << endl;
			system("pause");
		}
		while (f.get(ch))
		{
			for (int i = 7; i >= 0; i--)
			{
				o.write((((int)ch & (int)pow(2, i)) > 0 ? "1" : "0"), 1);
			}
		}
		f.close();
		o.close();
	}

	int64_t getSizeFile(string* t_path, ifstream &in)
	{
		in.seekg(0, in.end);
		std::streamsize size = in.tellg();
		in.seekg(0, std::ios::beg);
		cout << "\nFILE SIZE = " << size << endl;
		return size;
	}
private:
	int64_t fileSize = 0;
	bitset<64> data[25];
	string path;
	
};