#include <stdio.h>
#include <iostream>
#include <unordered_set>
#include <unordered_map>
#include <set>
#include <map>
#include "HttpData.h"
#include "utils.h"


#define TEST


typedef std::map<DoublePair,Session> HashMap;
typedef std::multimap<DoublePair,Session> HashMultiMap;


static size_t total,totalVERSION_CNT,total11,total10;
static HashMap unfinished;
static HashMultiMap finished;
static std::map<std::string, size_t> size_map;
static std::set<DoublePair> st,notfoundst;
void http_roller(u_char *user, const struct pcap_pkthdr * h, const u_char * pkt)
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
	
#if VERSION == HTTP
	if(!ISHTTP(srcport) && !ISHTTP(dstport))
		return;
#elif VERSION == HTTPS
	if(srcport!=443 && dstport!=443)
		return;
#endif

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
		st.insert(dp);
		if(unfinished.count(dp)==0)
		{
			Session a(src,dst);
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
	
	if(st.count(dp) == 0)
	{
		notfoundst.insert(dp);
	}

	if(unfinished.count(dp))
	{
		auto & session = unfinished[dp];
		session.addPacket(session.getDirection(&p),&p);

#ifdef CALC_TYPE_SIZE
        std::string type { std::move(session.getType()) };
        size_map[type] += p.payload_len;
#endif

#if VERSION == HTTP
		std::string s;
		for(int i=0;i<h->caplen;i++)
		{
			if(pkt[i] == 0) s+=(char)1;
			else s+=pkt[i];
		}
		if(s.find("HTTP/1.1")!=std::string::npos)
		{
			session.setVersion(Session::HTTP_11);
			total11++;
		}
		else if(s.find("HTTP/1.0")!=std::string::npos)
		{
			session.setVersion(Session::HTTP_10);
			total10++;
        }

#ifdef CALC_TYPE_SIZE
        char type_buf[100];
        if(getField(type_buf, s.c_str(), "Content-Type: ")>=0)
        {
            std::string temp_type(type_buf);
            int temp_pos = temp_type.find("/");
            if(temp_pos!=std::string::npos)
                session.setType(temp_type.substr(0, temp_pos));
            //fprintf(stderr,"got type %s\n",session.getType().c_str());
        }
#endif

#endif
    }
    //TODO: NORMAL PACKETS
LVERSION_CNT:;

}

static const int VERSION_CNT = 4;
double thp[VERSION_CNT],dura[VERSION_CNT],payld[VERSION_CNT];
size_t cnt[VERSION_CNT],pknum[VERSION_CNT],unfincnt[VERSION_CNT];
size_t flush()
{
    size_t total3=0;
    //	for(auto & ent : unfinished)
    //	{
    //		if(ent.second.isHalfClosed())
    //		{
    //			finished.insert(ent);
    //			total3++;
    //		}
    //	}

    for(auto & ent : unfinished)
    {
        auto & s = ent.second;
        int ind = (s.getVersion()>>2);
        ++unfincnt[ind];
    }
    for(auto & ent : finished)
    {
        auto & s = ent.second;	
        int ind = (s.getVersion()>>2);
        ++cnt[ind];
        thp[ind]+=s.caculateThp(Session::DOWNLOAD);
        dura[ind]+=s.caculateDuration();
        payld[ind]+=s.getFlow(Session::DOWNLOAD)->getPayloadSize();
        pknum[ind]+=s.getFlow(Session::DOWNLOAD)->getPacketNumber();
    }
    for(int ind = 0;ind<VERSION_CNT;ind++)
    {
        thp[ind]/=cnt[ind];dura[ind]/=cnt[ind];payld[ind]/=cnt[ind];
    }
    return total3;
}

void tempPrint()
{
    printf("flushing...\n");
    auto v = flush();
    char version[VERSION_CNT][8] = {"UNKN","1.1","1.0","HYBiD"};
    for(int i=0;i<VERSION_CNT;i++)
    {
        printf("for HTTP%s\n\tsession num = %zu+%zu\n\tthp = %lf\n\tdura=%lf\n\tpayld=%lf\n\tpktcnt=%ld\n",
                version[i],cnt[i],unfincnt[i],thp[i],dura[i],payld[i],pknum[i]);
    }
    printf("not found size = %ld, found size = %ld\n",
            notfoundst.size(),st.size());
    printf("finished size = %ld, unfinished size = %ld, half-closed = %ld\n",
            finished.size(),unfinished.size(),v);
    printf("total11 = %ld, total10 = %ld\n",total11,total10);
}

void getFinishedSessions(std::vector<Session> & v)
{
    v.clear();
    v.reserve(finished.size());
    for(auto & ent : finished)
        v.push_back(ent.second);
}

size_t getSizeOfGivenType(const std::string &type)
{
    return size_map[type];
}

