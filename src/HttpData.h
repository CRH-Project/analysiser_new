#pragma once
#include <iostream>
#include <vector>
#include <algorithm>
#include <set>
#include "headers.h"

#define HTTPS 1
#define HTTP 0
#define VERSION HTTP

struct Pair 
{
	uint32_t ip = 0;
	uint16_t port = 0;
	bool operator==(const Pair & r) const
	{
		return ip==r.ip && port==r.port;
	}
	bool operator<(const Pair & r) const
	{
		if(ip == r.ip)
			return port<r.port;
		return ip<r.ip;
	}
};

struct DoublePair
{
	Pair src;
	Pair dst;
	bool operator==(const DoublePair & r) const
	{
		return src==r.src && dst==r.dst;
	}
	bool operator<(const DoublePair &r) const
	{
		if(src==r.src)
			return dst<r.dst;
		return src<r.src;
			
	}
};

typedef std::pair<uint32_t,uint32_t> SEQ_GAP;
/**
 * data structures
 *
 * packet	-> for http packet info
 * flow		-> for flow info
 * session	-> for session info
 */
class Packet;
class Flow;
class Session;

class Packet
{
	public:
		Pair src;
		Pair dst;
		uint32_t seq;
		uint32_t header_len;
		uint32_t payload_len;
		struct timeval timestp;
	public:
		inline size_t getTotalSize()
		{
			return header_len+payload_len;
		}
};


class Flow 
{
	private:
		size_t packetNumber = 0;
		size_t total_size = 0;
		size_t payload_size = 0;
		//uint32_t minseq;	/* start seq */
		uint32_t maxseq = 0;/* expected largest next seq */
		uint64_t retrans_times = 0;
		std::vector<SEQ_GAP> gaps;
	public:
		Flow() = default;
		void init(Packet * p);	/* to make a new instance, at 
							 * least one packet is needed
							 */
		void addPacket(Packet * p);
		size_t getTotalSize();
		size_t getPayloadSize();
		size_t getPacketNumber();
		size_t getRetransmissionTimes();
};

class Session
{
	public:
		static const char MASK_TCP = 3;
		static const char MASK_VERSION = 12;
		static const char UPLOAD = 1;
		static const char DOWNLOAD = 2;
		static const char ESTABLISHED = 3;
		static const char CLOSED = 0;
		static const char HTTP_11 = 4;
		static const char HTTP_10 = 8;
		static const char HTTP_HYB = 12;
		static const char UNKNOWN_V = 0b00;
	private:
		char state = UNKNOWN_V|CLOSED;	
					/* lowest two bits 
					 *	11 for established, first bit is upload
					 *	10 and 01 for open/closed partly
					 *	00 for closed
					 * the 3 and 4  bits for http verion
					 *	10 -> http 1.0
					 *	01 -> http 1.1
					 */
		Pair src;
		Pair dst;
		struct timeval starttime{0,0};
		struct timeval endtime{0,0};
		Flow upload;	/* src -> dst */
		Flow download;	/* dst -> src */
        std::string type = "";

	private:
		void init(Pair & s, Pair & d);
	public:
		Session()=default;
		Session(Pair & s, Pair & d);
		/* setters */
		void syn(char direction, Packet * p);
		void fin(char direction, Packet * p);
		void addPacket(char direction, Packet * p);
		void setVersion(char version);
        void setType(const std::string & s);
		
		/* getters */
		size_t getPayloadSize();
		size_t getTotalSize();
		char getTcpState();
		char getVersion();
        std::string getType();
		Flow * getFlow(char direction);
		std::pair<size_t, size_t> 
			   getRetransmissionTimes();

		double caculateRate(char direction);
		double caculateThp(char direction);
		double caculateDuration();
		bool isHalfClosed();

		[[deprecated]]
			bool isNewerHttp();
	
    public:
		char getDirection(Packet * p)
		{
			if(p->src == this->src) return UPLOAD;
			else return DOWNLOAD;
		}
		std::string printID();
};


/**
 * FUNCTION -- PCAP_HANDLER
 * pcap_handler http_roller;
 * 
 * roll the pcap file and get http content characteristics
 */
void http_roller(u_char * user, const struct pcap_pkthdr * h, const u_char * pkt);

void tempPrint();
void getFinishedSessions(std::vector<Session> & v);


int initRespondTimeGetter(const char * prefix);
void httpgap_roller(u_char * user, const struct pcap_pkthdr * h, const u_char * pkt);
void endRespondTimeGetter();

/* SOME IMPLEMENTATIONS */
namespace std
{
	template<>
	struct hash<Pair>
	{
		std::size_t operator()(const Pair & p) const noexcept
		{
			return (((uint64_t)(p.ip))<<16) || p.port;
		}
	};

	template<>
	struct hash<DoublePair>
	{
		std::size_t operator()(const DoublePair & d)const noexcept
		{
			std::hash<Pair> hp; 
			__int128 l = hp(d.src),r = hp(d.dst);
			__int128 ans = l*r;
			ans >>= 32;
			return (size_t)(ans);
		}
	};
};
