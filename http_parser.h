#ifndef HTTP_PARSER_H
#define HTTP_PARSER_H
#include <iostream>
#include <thread>
#include <algorithm>
#include <fstream>
#include <string>
#include <regex>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pcap/pcap.h>
#include <zlib.h>
#include "json/json.h"
#endif // HTTP_PARSER_H

#ifdef __linux__
#include <arpa/inet.h>
#endif

#ifdef _WIN32_
#define WPCAP
#pragma comment(lib, "wpcap.lib")
#endif

#define PCAP_OPENFLAG_PROMISCUOUS 1
#define TYPE_IP 0x0800
#define TYPE_TCP 0x06

#define FILE_READ_SIZE 4096
#define GZ_SIZE 8192

#define NATE_MAIL "/app/newmail/send/send/ "
#define DAUM_MAIL "/hanmailex/SendMail.daum?tabIndex=1&method=autoSave "
#define JSON_FILE_NAME "test.json" // "/root/Document/http_parser/"

enum{OTHERS, POST, GET};
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
    string one    = "";
    string two    = "";
    string three  = "";
    string header = "";
    string body   = "";
  }message;

  typedef struct _type1 {
    string key;
    string value;
  }json;

  typedef struct _f_v{
    string field;
    string value;
  }f_v;

public:
  Http_Parser();
  bool Get_Data(string filepath, string* data);
  bool Substr_First_Line(string line, message *message);
  string Content_Length(string header, int start, int end);
  string Content_Type(string header);
  string Accept(string header);
  int Parse(string *data, message *msg, int locate = 0);
  int Post_Or_Get(string str);
  string Urldecode(string *str);
  void Body_Parser_1(string msg);
  void Json_Parser(string msg);
  void Fv_Parser(string msg);
  bool Request_Option(string method);
  void Gzip_Uncompress(string filename);
  void Pcap_Run();
  void Task(pcap_t *handle, struct pcap_pkthdr *header, u_char *packet);
  void Err_Print();
  void Run();

public:
  ETH_HDR *ethhdr = new ETH_HDR;
  IP_HDR *iphdr = new IP_HDR;
  TCP_HDR *tcphdr = new TCP_HDR;

};

// string::size_type pos = str17.find (str18, 0); 
// 0번째 인덱스부터, "str18"이 일치하는 시작위치를 리턴
