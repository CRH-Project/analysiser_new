#include <iostream>
#include <signal.h>
#include <setjmp.h>
#include <map>
#include <fstream>
#ifdef OUTPUT
#include "roll.h"
#include "HttpData.h"
#else
#include "src/roll.h"
#include "src/HttpData.h"
#endif
using namespace std;



void printHeader(ostream & o)
{
	o<<"Version,Duration,D-Payload Size,D-Throughput,D-Packet Count"<<
		"U-PaylodSize,U-Throughput,U-Packet Count"<<endl;
}

jmp_buf env;
void sighandler(int signum)
{
	longjmp(env,1);
}

void printSession(ostream & o,Session & s)
{
	/* Format
	 * version,dura,downloadInfo,uploadinfo
	 *	[down/up]info format:
	 *		payloadsize,throughput,pktcnt
	 */
	static char deli = ',';
	string version;
	auto v = s.getVersion();
	switch(v)
	{
		case Session::HTTP_10:
			version = "HTTP/1.0";
			break;
		case Session::HTTP_11:
			version = "HTTP/1.1";
			break;
		case Session::UNKNOWN_V:
			version = "UNKNOWN";
			break;
		case Session::HTTP_HYB:
			version = "Hybrid";
			break;
		default:
			version = "error";
			cerr<<"version error? "<<v<<endl;
	}
	Flow * up = s.getFlow(Session::UPLOAD);
	Flow * dn = s.getFlow(Session::DOWNLOAD);
	auto dura = s.caculateDuration();

	o<<version<<deli<<
		dura<<deli<<
		dn->getPayloadSize()<<deli<<
		dn->getPayloadSize()/dura<<deli<<
		dn->getPacketNumber()<<deli<<
		up->getPayloadSize()<<deli<<
		up->getPayloadSize()/dura<<deli<<
		up->getPacketNumber()<<deli<<endl;	
}



int main(int argc, char * argv[])
{
	if(argc!=2)
	{
		cerr<<"Usage : ./http <filename>"<<endl;
		exit(-1);
	}

#if VERSION == HTTP
	signal(SIGINT,sighandler);
	std::map<char,int> version2ind = {
		{Session::HTTP_11,0},
		{Session::HTTP_10,1},
		{Session::UNKNOWN_V,2},
		{Session::HTTP_HYB,3}
	};
	string suffix[4] = {"-1.1.csv","-1.0.csv","-unknown.csv","-hybrid.csv"};
	ofstream fouts[4];
	for(int i=0;i<4;i++)
	{
		fouts[i] = ofstream(argv[1]+suffix[i]);
		printHeader(fouts[i]);
	}


	if(setjmp(env) == 1)
		goto LABEL1;
	roll(argv[1],http_roller);
	tempPrint();

LABEL1:;
	vector<Session> finished;
	getFinishedSessions(finished);
	for(auto &s : finished)
	{
		auto ver = s.getVersion();
		auto ind = version2ind[ver];
		printSession(fouts[ind],s);
		if(s.getFlow(Session::UPLOAD)->getTotalSize() == 0)
		{
			cout<<"Session : "<<s.printID()<<" -- NO_UPLOAD! "<<std::endl;
		}
		if(s.getFlow(Session::DOWNLOAD)->getTotalSize() == 0)
		{
			cout<<"Session : "<<s.printID()<<" -- NO DOWNLOAD! "<<std::endl;
		}
		auto rt = s.getRetransmissionTimes();
		if(rt.first > 0 || rt.second > 0)
		cerr<<"Session "<<s.printID()<<"'s retrans_times : UPLOAD "<<
			rt.first<<", DOWNLOAD "<<rt.second<<endl;
	}
	for(int i=0;i<4;i++)
		fouts[i].close();
#elif VERSION == HTTPS
	string suffix("-https.csv");
	ofstream fout(argv[1]+suffix);
	if(!fout)
	{
		fprintf(stderr,"Cannot open output file!\n");
		return -1;
	}
	printHeader(fout);

	roll(argv[1],http_roller);

	vector<Session> finished;
	getFinishedSessions(finished);
	size_t sum = finished.size(),
		   successful = 0;
	for(auto & s: finished)
	{
		if(s.getPayloadSize() > 5)
		{
			printSession(fout,s);
			++successful;
		}
	}

	cerr<<argv[1]<<","<<((double)successful)/((double)(sum))<<endl;
	

#else
	fprintf(stderr,"No version definition found in HttpData.h!\n");
#endif 

	return 0;
}
