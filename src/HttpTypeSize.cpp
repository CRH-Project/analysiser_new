#include <vector>
#include <map>
#include "HttpData.h"
#include "HttpTypeSize.h"
#include "utils.h"

class _Session : public Session
{
    public:
        size_t currTypeSize;
        _Session(Pair &s, Pair &d):Session(s,d)
        {
            currTypeSize = 0;
        }
        _Session() : Session(), currTypeSize(0){}
};

typedef std::map<DoublePair,_Session> HashMap;
typedef std::multimap<DoublePair,_Session> HashMultiMap;

static size_t total;
static std::map<std::string, std::vector<size_t>> type_size_map;
static HashMap unfinished;
void httpTS_roller(u_char *user, const struct pcap_pkthdr *h, const u_char *pkt)
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

    /* Initialize packet */
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
    if(!ISUSR(src.ip)) return;
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
				//finished.insert(std::make_pair(dp,session));
				unfinished.erase(unfinished.find(dp));
			}
		}
		goto LVERSION_CNT;
	}

    if(unfinished.count(dp))
    {
        auto & session = unfinished[dp];
        session.addPacket(session.getDirection(&p), &p);

		std::string s;
		for(int i=0;i<h->caplen;i++)
		{
			if(pkt[i] == 0) s+=(char)1;
			else s+=pkt[i];
		}

        char type_buf[100];
        if(getField(type_buf, s.c_str(), "Content-Type: ")>=0)
        {
            std::string last_type {session.getType()};
            if(last_type.length()) 
                type_size_map[last_type].push_back(session.currTypeSize);
            
            //if(last_type == "text" && session.currTypeSize < 700)
            //    fprintf(stderr,"Got! PKT_ID = %ld, size = %ld\n", total, session.currTypeSize);
            session.currTypeSize = 0;
            std::string temp_type(type_buf);
            size_t temp_pos = temp_type.find("/");
            if(temp_pos!=std::string::npos)
                session.setType(temp_type.substr(0, temp_pos));
            //fprintf(stderr,"got type %s\n",session.getType().c_str());
            //std::cerr<<"type is: "<<temp_type<<std::endl;
        }

        session.currTypeSize += p.payload_len;
    }


LVERSION_CNT:;
}

void getTypeSizeVector(const std::string &type, std::vector<size_t> &v)
{
    auto & vec = type_size_map[type];
    //v.reserve(vec.size());
    std::copy(vec.begin(), vec.end(), std::back_inserter(v));
}
