#include "judgeStart.h"
#include <set>
#include <stdio.h>
#include "utils.h"
#include <string>

#define LOG_CNT 500000
static std::string name;
static size_t total;
static const __time_t INTERVAL{60};
static __time_t tag,curr;
static int counter = 0;
static const int THRESHOLD = 5;


typedef std::pair<uint32_t,uint16_t> _PAIR;
typedef std::pair<_PAIR,_PAIR> _FLOW;
typedef std::set<_FLOW> SET;

static SET st;

static bool check(uint32_t si,uint32_t di, uint16_t sp, uint16_t dp)
{
	_FLOW f{{si,sp},{di,dp}};
	if(ISUSR(di)) std::swap(f.first,f.second);
	if(st.count(f)) return false;
	auto _si = f.first.first, _di = f.second.first;
	if(ISUSR(_si) && _di == 0xc0a80a01)
	{
		st.insert(f);
		return true;
	}
	return false;
}

void init_filename(const char * f)
{
	name = std::string(f);
}	


void judge_roller(u_char * u, const struct pcap_pkthdr * h, const u_char * pkt)
{
	if(total == 0)
	{
		tag = h->ts.tv_sec;
		curr = tag;
	}
	curr = h->ts.tv_sec;
	if(curr - tag > INTERVAL)
		counter = 0;
	total++;
	if(total % LOG_CNT == 0)
		fprintf(stderr,"%zuk packets done ...\n", total*500/LOG_CNT);
	
	const struct Ethernet *link = (struct Ethernet *)pkt;
	const struct Ipv4 *net = (struct Ipv4 *)(pkt + sizeof(struct Ethernet));
	const struct Tcp *trans = (struct Tcp *)((u_char *)net + 4 * net->ihl);
	const char *app = (char *)((u_char *)trans + 4 * trans->doff);


	uint32_t srcip = ntohl(net->srcip), 
			 dstip = ntohl(net->dstip);
	uint16_t srcport = ntohs(trans->srcport),
			 dstport = ntohs(trans->dstport);

	if(check(srcip,dstip,srcport,dstport)) counter++;
	if(counter>THRESHOLD)
	{
		fprintf(stdout,"%s starts at %zu\n", name.c_str(), h->ts.tv_sec);
		st.clear();
		exit(0);
	}
}

