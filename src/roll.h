/*
 * roll.h
 *
 * To pack up calls to pcap_loop()
 *
 */
#ifndef _ROLL_HH_
#define _ROLL_HH_

#include <pcap/pcap.h>

static u_char err[100];
void rool_error();
int roll(const char * fileName, pcap_handler ph);


#endif 
