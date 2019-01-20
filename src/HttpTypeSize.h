#ifndef _HTTPTYPESIZE_HH_
#define _HTTPTYPESIZE_HH_

#include <pcap/pcap.h>
#include <string>
#include <vector>

void httpTS_roller(u_char *, const struct pcap_pkthdr *, const u_char *);
void getTypeSizeVector(const std::string &type, std::vector<size_t> &v);


#endif
