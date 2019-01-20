#include <iostream>
#ifdef OUTPUT
#include "roll.h"
#include "judgeStart.h"
#else
#include "src/roll.h"
#include "src/judgeStart.h"
#endif
using namespace std;

int main(int argc, char * argv[])
{
	if(argc!=2)
	{
		cerr<<"Usage : ./judge <filename>"<<endl;
	}
	
	init_filename(argv[1]);
	roll(argv[1],judge_roller);

	return 0;
}

