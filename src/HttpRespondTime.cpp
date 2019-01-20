#include <iostream>
#include <map>
#include <string>
#include <stdio.h>
#include <stdlib.h>
#include <algorithm>
#include <set>
#include <unordered_map>
#include "utils.h"
#include "HttpData.h"
#include <vector>

std::vector<std::string> succCode{"200 OK","201 Created",
                "206 Partial Content"};
std::map<std::string,int> acceptType{{1,"text"},{2,"application"},{3,"image"}};
class _Session : public Session
{
	public:
		const static int OK = 0;
		const static int REQUESTED = 1;
		typedef void (*_SESS_CALL_BACK_T)(_Session *,void *);
	private:
		int object_count = 0;
		int obj_status = OK;
		struct timeval obj_start = {0,0};
		struct timeval obj_end = {0,0};
		
	private:
		void _init()
		{
			object_count = 0;
			obj_status = OK;
			obj_start = {0,0};
			obj_end = {0,0};
		}


	public:
		_Session()
		{
			Session();
			_init();
		}

		_Session(Pair & s, Pair & d):Session(s,d)
		{
			_init();
		}

		void getRequest(struct timeval t)
		{
			if(obj_status == OK)
			{
				obj_start = t;
				obj_status = REQUESTED;
			}
			else
			{
				/* IGNORE */
			}
		}

		void getResponse(struct timeval t,
				_SESS_CALL_BACK_T cbak,void * arg)
		{
			if(obj_status == REQUESTED)
			{
				obj_end = t;
				obj_status = OK;
				object_count += 1;
			}
			else
			{
				/* IGNORE */
			}
			/*for debug*/
		}

		void getCorrectResponse(struct timeval t,
				_SESS_CALL_BACK_T cbak, void * arg)
		{
			getResponse(t,cbak,arg);
			cbak(this,arg);
		}

		double getTimeGap()
		{
			if(this->obj_status != OK) return 0;
			if(this->obj_end < this->obj_start) return 0;
			struct timeval tt = this->obj_end - this->obj_start; 
			return tt.tv_sec + tt.tv_usec/1000000.0;
		}
		 
		size_t getObjCount()
		{
			return this->object_count;
		}
		
};

typedef std::map<DoublePair,_Session> HashMap;
typedef std::multimap<DoublePair,_Session> HashMultiMap;

static FILE *fout;
static size_t total;
static HashMap unfinished;
static HashMultiMap finished;



void printToFile(_Session * session, void * arg)
{
	int tt = (int)arg;
	FILE * file = fout;
	if(!file || !session)
		return;
	if(session->getTimeGap() > 0) 
		fprintf(file,"%lf,%s\n",session->getTimeGap(),acceptType[tt].c_str());
}

bool isRequest(const std::string & s, Packet *p)
{
	if(ISUSR(p->src.ip) && s.find("HTTP/")!=std::string::npos
			&& s.find("GET")!=std::string::npos)
		return true;
	return false;
}

bool isRespond(const std::string & s, Packet * p)
{
	if(ISUSR(p->dst.ip))
		return true;
	return false;
}	

int isCorrectRespond(const std::string &s, Packet *p)
{
    char buf[100];
    int retVal = 0;
    if(getField(buf,s.c_str(),"Content-Type: ")>=0)
    {
        std::string type{buf};
        to_lower(type);
        if(type.find("audio")!=std::string::npos 
                || type.find("video")!=std::string::npos)
        {
            return false;
        }
	for(auto &ent : acceptType)
	{
	    if(type.find(ent.second)!=std::string::npos) retVal = ent.first;
	}
    }
    for(auto ss : succCode)
    {
    	if(s.find(ss)!=std::string::npos)
        {
	    	return retVal;
        }
    }
    return false;
}

void httpgap_roller(u_char *user, const struct pcap_pkthdr * h, const u_char * pkt)
{
	total++;
	if(total % 100000 == 0) printf("%ldk packets done..\n",total/1000);
	const struct Ethernet *link = (struct Ethernet *)pkt;
	const struct Ipv4 *net = (struct Ipv4 *)(pkt + sizeof(struct Ethernet));
	const struct Tcp *trans = (struct Tcp *)((u_char *)net + 4 * net->ihl);
	const char *app = (char *)((u_char *)trans + 4 * trans->doff);

	if(net->protocol != 6) return;

	uint32_t srcip = ntohl(net->srcip), 
			 dstip = ntohl(net->dstip);
	uint16_t srcport = ntohs(trans->srcport),
			 dstport = ntohs(trans->dstport);
	Pair src{srcip,srcport},dst{dstip,dstport};

	uint32_t seq = ntohl(trans->seq), tot_len = ntohs(net->tot_len);
	uint32_t payload_len = tot_len - net->ihl*4 - trans->doff*4;	
	
	if(!ISHTTP(srcport) && !ISHTTP(dstport))
		return;

	//TODO: initialize packet
	Packet p;
	{
		p.src = src;
		p.dst = dst;
		p.seq = trans->seq;
		p.header_len = tot_len - payload_len;
		p.payload_len = payload_len;
		p.timestp = h->ts;
	}

	if(ISUSR(dstip)) std::swap(src,dst);
	DoublePair dp{src,dst};
	if(trans->syn)
	{
		if(unfinished.count(dp)==0)
		{
			_Session a(src,dst);
			unfinished.insert(std::make_pair(dp,a));
		}
		auto & session = unfinished[dp];
		session.syn(session.getDirection(&p), &p);
		goto LVERSION_CNT;
	}

	if(trans->fin || trans->rst)
	{
		if(unfinished.count(dp))
		{
			auto & session = unfinished[dp];
			if(trans->rst) session.fin(3,&p);
			else session.fin(session.getDirection(&p),&p);
			if(session.getTcpState() == Session::CLOSED)
			{
				finished.insert(std::make_pair(dp,session));
				unfinished.erase(unfinished.find(dp));
			}
		}
		goto LVERSION_CNT;
	}
	
	if(unfinished.count(dp))
	{
		auto & session = unfinished[dp];
		session.addPacket(session.getDirection(&p),&p);
		std::string s;
		for(int i=0;i<h->caplen;i++)
		{
			if(pkt[i] == 0) s+=(char)1;
			else s+=pkt[i];
		}
		/*if(s.find("HTTP/1.1")!=std::string::npos)
		{
			session.setVersion(Session::HTTP_11);
		}
		else if(s.find("HTTP/1.0")!=std::string::npos)
		{
			session.setVersion(Session::HTTP_10);
		}*/
		if(isRequest(s,&p))
			session.getRequest(p.timestp);
		else if (isRespond(s,&p))
		{
			FILE * file = fout;
			session.getResponse(p.timestp,printToFile,(void *)file);
			int tt;
			if((tt=isCorrectRespond(s,&p)))
			{
				if(session.getTimeGap()<1e-3 && session.getTimeGap()>0)
				{
					fprintf(stderr,"Session : %s, object %zu\n",
							session.printID().c_str(),
							session.getObjCount());
				}
				session.getCorrectResponse(p.timestp,printToFile,(void*)tt);
			}
		}
	}

LVERSION_CNT:;

}

int initRespondTimeGetter(const char * prefix)
{
/*	std::string s1(prefix),s2(prefix);
	s1 += "-http1.0.txt";
	s2 += "-http1.1.txt";
	http10 = fopen(s1.c_str(),"w");
	http11 = fopen(s2.c_str(),"w");*/

    std::string s(prefix);
    s+="-resTime.txt";
    fout = fopen(s.c_str(),"w");
    if(!fout)
	{
		fprintf(stderr,"error opening file:\n");
		fprintf(stderr,"\t%s\n",strerror(errno));
		return -1;
	}
}

void endRespondTimeGetter()
{
    if(fout)
        fclose(fout);
}
