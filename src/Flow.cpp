#include "HttpData.h"

void Flow::init(Packet * p)
{
	this->total_size += p->getTotalSize();
	this->payload_size += p->payload_len;
	this->maxseq = p->seq + p->payload_len;
	this->retrans_times = 0;
	this->packetNumber = 1;
}

size_t Flow::getTotalSize()
{
	return this->total_size;
}

size_t Flow::getPayloadSize()
{
	return this->payload_size;
}

void Flow::addPacket(Packet * p)
{
	this->total_size += p->getTotalSize();
	this->payload_size += p->payload_len;
	this->packetNumber++;

	/* use sequence number to judge */
	bool flag = false,	/* flag for remove_if */
		 flag2 = false;	/* flag for retransmission */
		
	uint32_t seq = p->seq,
			 nextseq = p->seq + p->payload_len;
	if(seq > this->maxseq)		/* a new gap */
	{
		maxseq = nextseq;
		SEQ_GAP newgap{maxseq,seq};
		this->gaps.push_back(newgap);
		goto L1;
	}
	if(seq == this->maxseq)		/* add to maxseq */
	{
		maxseq = nextseq;
		goto L1;
	}
	
	for(auto & gap : this->gaps)
	{
		flag2 = false;
		if(seq == gap.first)
		{
			gap.first = nextseq;	
			if(gap.first >= gap.second) flag = true;
			break;
		}
		if(nextseq == gap.second)
		{
			gap.second = seq;
			if(gap.first >= gap.second) flag = true;
			break;
		}
		if(seq>gap.first && nextseq<gap.second)
		{
			gap.second = seq;
			SEQ_GAP newgap{nextseq,gap.second};
			this->gaps.push_back(newgap);
			break;
		}

		flag2 = true;
	}

	if(flag2)	/* retransmission */
	{
		++retrans_times;
		/**
		 * if want to caculate retransmission size
		 * add field like 'retrans_size' in class Flow
		 * and add code to update the field here
		 */
	}

	if(true/*flag*/)	/* some gap is filled */
	{
		std::remove_if(this->gaps.begin(),this->gaps.end(),
				[&](auto & gp)
				{
					if(gp.first >= gp.second) return true;
				});
	}

L1:
	return;
}

size_t Flow::getPacketNumber()
{
	return this->packetNumber;
}
