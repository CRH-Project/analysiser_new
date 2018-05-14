#include "utils.h"
#include "utils.c"
#include <stdexcept>



/**
 * HELPER FUNCTIONS operator +-* of timeval
 */
bool operator<(const struct timeval & l,const struct timeval & r)
{
	if(l.tv_sec == r.tv_sec)
		return l.tv_usec<r.tv_usec;
	return l.tv_sec<r.tv_sec;
}
struct timeval operator-(const struct timeval & l,const struct timeval & r)
{
	struct timeval ans;
	__suseconds_t pp=0;
	if (l<r){
		fprintf(stderr,"cannot get negative time l=(%ld,%ld) r=(%ld,%ld)\n",l.tv_sec,l.tv_usec,r.tv_sec,r.tv_usec);
		return {-1l,-1l};
	}
	ans.tv_sec=l.tv_sec-r.tv_sec;	
	if(l.tv_usec<r.tv_usec){
		pp=1000000;ans.tv_sec-=1;
	}
	ans.tv_usec=pp+l.tv_usec-r.tv_usec;
	return ans;
}
struct timeval operator+(const struct timeval & l, const struct timeval & r)
{
	struct timeval ans;
	ans.tv_usec = (l.tv_usec + r.tv_usec) % 1000000;
	ans.tv_sec = l.tv_sec + r.tv_sec +
					(l.tv_usec + r.tv_usec) / 1000000;
	return ans;
}
struct timeval operator*(const struct timeval & l, const int r)
{
	struct timeval ans = {0l,0l};
	for(int i=0;i<r;i++)
	{
		ans = ans+l;
	}
	return ans;
}


