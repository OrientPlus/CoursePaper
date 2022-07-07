#include <iostream>
#include "chrono"

#include "DES.h"

int main()
{
	DES des;

	auto start_time = chrono::steady_clock::now();
	des.encrypt();
	auto end_time = chrono::steady_clock::now();
	auto elapsed_enc = chrono::duration_cast<chrono::milliseconds>(end_time - start_time);

	start_time = chrono::steady_clock::now();
	des.decrypt();
	end_time = chrono::steady_clock::now();
	auto elapsed_dec = chrono::duration_cast<chrono::milliseconds>(end_time - start_time);

	cout << "\nEncryption time: " << elapsed_enc.count() << " millisec  | File size: " << des.sizeEncFile << " KByte\n";
	cout << "\nDecryption time: " << elapsed_dec.count() << " millisec  | File size: " << des.sizeDecFile << " KByte\n";

	system("pause");
	return 0;
}