#include <fstream>
#include <vector>
#include "CLR.hpp"

#define DEBUG

#ifdef DEBUG
#define debug_print(fmt, ...) fprintf(stderr, fmt, __VA_ARGS__)
#else
#define debug_print(fmt, ...)
#endif

std::vector<char> get_file_data(std::string path)
{
	std::vector<char> buffer;
	try {
		//open file
		std::ifstream infile(path);

		//get length of file
		infile.seekg(0, infile.end);
		size_t length = infile.tellg();
		infile.seekg(0, infile.beg);

		//read file
		if (length > 0)
		{
			buffer.resize(length);
			infile.read(&buffer[0], length);
		}
		std::vector<unsigned char> v;
		v.assign(buffer.begin(), buffer.end());
	}
	catch (std::exception& e)
	{
		
	}
	return buffer;
}

int main()
{

	std::vector<char> c = get_file_data("..\\..\\InMemoryNET\\Debug\\InMemoryNET.exe");

	std::vector<unsigned char> netv(c.begin(), c.end());

	std::string b64net = base64::to_base64_vector(netv);
	std::string b64arg = base64::to_base64("this is an arg");
	
	CLRManager::CLR clr = CLRManager::CLR();
	clr.execute_assembly(b64net, b64arg);

	return 0;
}