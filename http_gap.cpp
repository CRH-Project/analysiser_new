#include <iostream>
#ifdef OUTPUT
#include "roll.h"
#include "HttpData.h"
#else
#include "src/roll.h"
#include "src/HttpData.h"
#endif
using namespace std;

int main(int argc, char * argv[])
{
	if(argc!=2)
	{
		cerr<<"Usage : ./http <filename>"<<endl;
	}
	
	string prefix("respond_anal/");
	prefix += argv[1];
	initRespondTimeGetter(prefix.c_str());
	roll(argv[1],httpgap_roller);
	endRespondTimeGetter();

	return 0;
}
