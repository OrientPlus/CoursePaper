#include <iostream>
#include <chrono>

#include "LOKI.h"

int main()
{
	LOKI loki;

	auto start_time = chrono::steady_clock::now();
	loki.encrypt();
	auto end_time = chrono::steady_clock::now();
	auto elapsed_enc = chrono::duration_cast<chrono::milliseconds>(end_time - start_time);

	start_time = chrono::steady_clock::now();
	loki.decrypt();
	end_time = chrono::steady_clock::now();
	auto elapsed_dec = chrono::duration_cast<chrono::milliseconds>(end_time - start_time);

	cout << "\nEncryption time: " << elapsed_enc.count() << " millisec  | File size: " << loki.sizeEncFile << " KByte\n";
	cout << "\nDecryption time: " << elapsed_dec.count() << " millisec  | File size: " << loki.sizeDecFile << " KByte\n";

	system("pause");
	return 0;
}