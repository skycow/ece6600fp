// testing octet - string conversion
#include <iostream>
#include <string.h>
#include <string>

using namespace std;

typedef unsigned char octet;

int main()
{
	cout << "Hello World!" << endl;
	octet foo = '6';
	cout << "foo " << foo << endl;

	octet foo_array[5];
	cout << "Enter a 5 letter word: ";
	cin >> foo_array;
	cout << foo_array << endl;

	string foo_string;
	// foo_string = *(foo_array + 1);
	memcpy(&foo_string, &foo_array, sizeof(foo_array));
	cout << "Here is the word as a string: " << foo_string << endl;
}