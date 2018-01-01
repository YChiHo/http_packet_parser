#pragma once
#ifndef HTTP_PARSER_H
#define HTTP_PARSER_H
#include <iostream>
#include <fstream>
#include <string>
#include <stdarg.h>
#include <pcap/pcap.h>
//#include <direct.h>
#endif // HTTP_PARSER_H

#define PCAP_OPENFLAG_PROMISCUOUS 1

#ifdef _WIN32_
#define WPCAP
#pragma comment(lib, "wpcap.lib")
#endif
using namespace std;

typedef struct eth_hdr {	//ethernet_header
	unsigned char eth_dest[6];
	unsigned char eth_src[6];
	u_short eth_type;
} ETH_HDR, *ETH_HDR;

typedef struct ip_hdr {		//ip_header
	u_int8_t  HdrLength:4;
	u_int8_t  Version:4;
	u_int8_t  TOS;
	u_int16_t Length;
	u_int16_t Id;
	u_int16_t FragOff0;
	u_int8_t  TTL;
	u_int8_t  Protocol;
	u_int16_t Checksum;
	u_int32_t SrcAddr;
	u_int32_t DstAddr;
} IP_HDR, *IP_HDR;

typedef struct tcp_hdr
{
	u_int16_t SrcPort;
	u_int16_t DstPort;
	u_int32_t SeqNum;
	u_int32_t AckNum;
	u_int16_t Reserved1:4;
	u_int16_t HdrLength:4;
	u_int16_t Fin:1;
	u_int16_t Syn:1;
	u_int16_t Rst:1;
	u_int16_t Psh:1;
	u_int16_t Ack:1;
	u_int16_t Urg:1;
	u_int16_t Reserved2:2;
	u_int16_t Window;
	u_int16_t Checksum;
	u_int16_t UrgPtr;
} TCP_HDR, *TCP_HDR;

class Http_Parser {

public:

	typedef struct _line {
		string one;
		string two;
		string three;
	}Line;

	typedef struct _message {
		Line *first_Line;
		string header;
		string body;
	}message;

public:
	Http_Parser();  //init
	void init(message *msg);
	string Get_Data(string filepath);
	string Get_Line(string data);
	void pcap_init();
	void Reqeust_Line_Parser(string requestLine);
	bool request_Option(string method);
	void message_Parser();
	void err_print();

public:
	ETH_HDR *ethhdr = new ETH_HDR;
	IP_HDR *iphdr = new IP_HDR;
	TCP_HDR *tcpphdr = new TCP_HDR;

};
