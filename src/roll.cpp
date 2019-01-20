#include "roll.h"
int roll(const char * fileName, pcap_handler ph)
{
	FILE * f=fopen(fileName,"r");
	if(!f)
	{
		fprintf(stderr,"INVALID FILE TO ANALYSIS!\n");
		return -1;
	}	
	pcap_t *pcap =pcap_fopen_offline(f,NULL);
	u_char err[100];
	int errcode = pcap_loop(pcap,0,ph,err);
	fclose(f);
	if(errcode)
		fprintf(stderr,"ERROR OCCURED: %s\n",err);
	return errcode;
}

#include <cstdio>
#include <cstdlib>

void roll_error()
{
	fprintf(stderr,"%s\n",err);
	exit(-1);
}
