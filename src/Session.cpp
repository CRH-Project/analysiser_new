#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "HttpData.h"
#include "utils.h"

Session::Session(Pair & s, Pair & d):Session()
{
	this->init(s,d);
}

void Session::init(Pair & s, Pair & d)
{
	state = UNKNOWN_V | CLOSED;
	src = s;dst = d;
}

Flow * Session::getFlow(char direction)
{
	switch(direction & 3)
	{
		case UPLOAD:
			return &upload;
		default:
			return &download;
	}
}

void Session::syn(char direction, Packet * p)
{
	if(this->getTcpState() == CLOSED) starttime = p->timestp;
	this->getFlow(direction)->init(p);
	state |= direction;
}

void Session::fin(char direction, Packet *p)
{
	this->getFlow(direction)->addPacket(p);
	state &= (~direction);
	if(p->timestp.tv_sec == 0)
		fprintf(stderr,"err in packet!\n");
	endtime = p->timestp;
}

void Session::addPacket(char direction, Packet *p)
{
	this->getFlow(direction)->addPacket(p);
}

void Session::setVersion(char version)
{
	//this->state &= ~MASK_VERSION;	/* mask out version bits */
	this->state |= version;
}

size_t Session::getTotalSize()
{
	return upload.getTotalSize() + download.getTotalSize();
}

size_t Session::getPayloadSize()
{
	return upload.getPayloadSize() + download.getPayloadSize();
}

bool Session::isNewerHttp()
{
	return !!(this->state & HTTP_11);
}

char Session::getVersion()
{
	return this->state & MASK_VERSION;
}

std::pair<size_t,size_t> Session::getRetransmissionTimes()
{
	auto upt = this->upload.getRetransmissionTimes(),
		 dwt = this->download.getRetransmissionTimes();
	return {upt,dwt};
}

char Session::getTcpState()
{
	return this->state & MASK_TCP;
}

double Session::caculateRate(char direction)
{
	auto flow = getFlow(direction);
	return flow->getTotalSize()/this->caculateDuration();
}

double Session::caculateThp(char direction)
{
	auto flow = getFlow(direction);
	return flow->getPayloadSize()/this->caculateDuration();
}

double Session::caculateDuration()
{
	auto timegap = this->endtime - this->starttime;
	return timegap.tv_sec + timegap.tv_usec/1000000.0;
}

bool Session::isHalfClosed()
{
	return endtime.tv_sec+endtime.tv_usec!=0;
}

std::string Session::printID()
{
	char buf[200];
	struct in_addr s{htonl(src.ip)};
	std::string ss(inet_ntoa(s));
	struct in_addr d{htonl(dst.ip)};
	char * sd = inet_ntoa(d);
	sprintf(buf,"(%s:%d) -> (%s:%d)",
			ss.c_str(),src.port,
			sd,dst.port);
	return std::string(buf);
}
