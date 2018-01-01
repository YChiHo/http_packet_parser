#pragma once
#ifndef HTTP_PARSER_H
#define HTTP_PARSER_H
#include <iostream>
#include <fstream>
#include <string>
#include <stdarg.h>
//#include <direct.h>
#endif // HTTP_PARSER_H

using namespace std;


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
	void Reqeust_Line_Parser(string requestLine);
	bool request_Option(string method);
	void message_Parser();
	void err_print();

};
