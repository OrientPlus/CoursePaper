#include <iostream>
#include "chrono"

#include "DES.h"

int main()
{
	auto start_time = std::chrono::steady_clock::now();
	DES des;
	des.encrypt();
	des.decrypt();
	auto end_time = std::chrono::steady_clock::now();
	auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
	std::cout << "\nExecution time: " << elapsed.count() / 1000 << " sec\n";
	
	int64_t sizeFile = des.sizeEncrFile();
	std::cout << "Size of file: " << sizeFile/1024 << " Kbytes\n";
	system("pause");
	return 0;
}