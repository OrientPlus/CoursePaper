#include <iostream>

#include "LOKI.h"

int main()
{
	LOKI loki;

	loki.encrypt();
	loki.decrypt();

	cout << "\nEncryption time: " << loki.exec_time_enc.count() << " millisec  | File size: " << loki.sizeEncFile << " KByte\n";
	cout << "\nDecryption time: " << loki.exec_time_dec.count() << " millisec  | File size: " << loki.sizeDecFile << " KByte\n";

	system("pause");
	return 0;
}