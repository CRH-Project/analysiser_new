#include "utils.h"
#include <string.h>
#include <stdlib.h>

const char * itoa(int cnt)
{
	const int BUFFER_SIZE=11;
	char * buffer=(char *)malloc(sizeof(char)*BUFFER_SIZE);
	memset(buffer,0,sizeof(char)*BUFFER_SIZE);
	if(cnt==0) 
	{
		buffer[0]='0';
		return buffer;
	}
	int pos=BUFFER_SIZE-1;
	while(cnt!=0)
	{
		buffer[--pos]=(char)('0'+(cnt%10));
		cnt/=10;
	}
	const char * ret=buffer+pos;
	return ret;
}

int getField(char *dst, const char *src, char *sign) {
	if(!dst || !src || !sign) return -1;

	int i = 0;
	char tmp;
	const char *start = strstr(src, sign);
	if(!start) return -1;

	start += strlen(sign); // "Content-Type: XXX"

	while(1) {
		tmp = *start;
		if(tmp == '\r' || tmp == ';' || tmp == ',' || tmp == '\0')
			break;
		dst[i++] = tmp;
		start++;
	}
	dst[i] = '\0';
	return 0;
}
