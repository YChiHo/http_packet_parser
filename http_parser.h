#ifndef HTTP_PARSER_H
#define HTTP_PARSER_H
#include <iostream>
#include <fstream>
#include <string>
#include <regex>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pcap/pcap.h>
#include <arpa/inet.h>
//#include <direct.h>
#endif // HTTP_PARSER_H

#define PCAP_OPENFLAG_PROMISCUOUS 1
#define TYPE_IP 0x0800
#define TYPE_TCP 0x06

#ifdef _WIN32_
#define WPCAP
#pragma comment(lib, "wpcap.lib")
#endif
using namespace std;

typedef struct ip_address{
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
}ip_address;

typedef struct eth_hdr {  //ethernet_header
  unsigned char eth_dest[6];
  unsigned char eth_src[6];
  u_short eth_type;
} ETH_HDR;

typedef struct ip_hdr {   //ip_header
  u_int8_t  HdrLength:4;
  u_int8_t  Version:4;
  u_int8_t  TOS;
  u_int16_t Length;
  u_int16_t Id;
  u_int16_t FragOff0;
  u_int8_t  TTL;
  u_int8_t  Protocol;
  u_int16_t Checksum;
  ip_address SrcAddr;
  ip_address DstAddr;
} IP_HDR;

typedef struct tcp_hdr{   //tcp_header
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
} TCP_HDR;

class Http_Parser {

public:

  typedef struct _message {
    string one = "";
    string two = "";
    string three = "";
    string header;
    string body;
  }message;

public:
  Http_Parser();
  void init(message *msg);
  string Get_Data(string filepath);
  string* Substr_First_Line(string line);
  string Content_Type(string header);
  string Content_Length(string header);
  void parse(string data, message *request_Message, message *response_Message);
  bool request_Option(string method);
  void pcap_run();
  void task(pcap_t *handle, struct pcap_pkthdr *header, u_char *packet);
  void err_print();

public:
  ETH_HDR *ethhdr = new ETH_HDR;
  IP_HDR *iphdr = new IP_HDR;
  TCP_HDR *tcphdr = new TCP_HDR;
  string tmp[3];

};



