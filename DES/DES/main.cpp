#include <iostream>
#include "chrono"

#include "DES.h"

int main()
{
	DES des;

	des.encrypt();
	des.decrypt();
	
	cout << "\nEncryption time: " << des.exec_time_enc.count() << " millisec  | File size: " << des.sizeEncFile << " KByte\n";
	cout << "\nDecryption time: " << des.exec_time_dec.count() << " millisec  | File size: " << des.sizeDecFile << " KByte\n";

	system("pause");
	return 0;
}