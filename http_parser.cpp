#include "http_parser.h"

Http_Parser::Http_Parser() {
}

// init variable
void Http_Parser::init(message *msg) {
	try {
		// msg->first_Line->one = "";
		// msg->first_Line->two = "";
		// msg->first_Line->three = "";
		// msg->header = "";
		// msg->body = "";
	}
	catch (int Exception) {
		err_print();
		return;
	}
}

// read data
string Http_Parser::Get_Data(string filepath) {

	string read_data;
	string tmp;
	read_data.clear(); tmp.clear();
	fstream f(filepath.c_str());

	try {
		if (f.is_open() == true) {
			while (getline(f, tmp)) {
				read_data += tmp;
				read_data += "\r\n";
			}
			f.close();
		}
	}
	catch (int Exception) {
		err_print();
		f.close();
		return "";
	}

	return read_data;
}

// 싹둑 first line
string* Http_Parser::Substr_First_Line(string line){
	int status;
	if(line.find(" ") != string::npos ){

		status = line.find(" ");
		tmp[0] = line.substr(0, status + 1);
		line.erase(0, status + 1);

		status = line.find(" ");
		tmp[1] = line.substr(0, status + 1);
		line.erase(0, status + 1);

		tmp[2] = line;
	}
	return tmp;
}

// get content-length
string Http_Parser::Content_Length(string header){
	std::string data = header;
	int lo, lenstr;
	string length;
	if ((lo = data.find("Content-Length: ")) > 0){
		lenstr = strlen("Content-Length: ");
		data.erase(0, lo);
		lo = data.find("\r\n");
		length = data.substr(lenstr, lo-lenstr);
		return length;
	}
	else
		return "0";
}

// get content-type
string Http_Parser::Content_Type(string header){			// need Modify
	string data = header;
	int lo, lenstr;
	string length;
	lo = data.find("Content-Type: ");
	lenstr = strlen("Content-Type: ");
	data.erase(0, lo);
	lo = data.find("\r\n");
	length = data.substr(lenstr, lo-lenstr);

	if(length.find("urlencoded") > 0)
		return "urlencoded";
	else if(length.find(""))
		return "";
	else
		return "sorry";
	return length;
}

string Http_Parser::Accept(string header){
	string data = header;
	int lo;
	string str;
	lo = data.find("Accept: ");
	data.erase(0, lo);
	lo = data.find("\r\n");
	str = data.substr(0, lo);
	return str;
}

// First_Line, Header, Body parse
void Http_Parser::parse(string data, message *request_Message, message *response_Message) {
	int locate;
	string line;
	string *tmp;
	//rq first line
	locate = data.find("\r\n");
	line = data.substr(0, locate + 1);
	tmp = Substr_First_Line(line);
	request_Message->one = tmp[0];
	request_Message->two = tmp[1];
	request_Message->three = tmp[2];
	data.erase(0, locate + 2);

	if(request_Option(request_Message->one) == true){

		//rq header
		locate = data.find("\r\n\r");
		request_Message->header = data.substr(0, locate + 1);
		data.erase(0, locate + 5);

		//rq body
		locate = stoi(Content_Length(request_Message->header));
		if( locate != 0 ){
			request_Message->body = data.substr(0, locate);
			data.erase(0, locate);
		}

		for(int i = 0 ; i < 3 ; i++)
			tmp[i] = "";
		line = "";

		//rs first line
		locate = data.find("\r\n");
		line = data.substr(0, locate + 1);
		tmp = Substr_First_Line(line);
		data.erase(0, locate + 2);
		response_Message->one = tmp[0];
		response_Message->two = tmp[1];
		response_Message->three = tmp[2];

		//rs header
		locate = data.find("\r\n\r");
		response_Message->header = data.substr(0, locate + 1);
		data.erase(0, locate + 5);

		//rs body
		locate = stoi(Content_Length(response_Message->header));
		if( locate != 0 ){
			response_Message->body = data.substr(0, locate + 1);
			data.erase(0, locate + 1);
		}
	}
}

// Post or Get
int Http_Parser::PostOrGet(string str){
	if (	strncmp(str.c_str(), "POST ", sizeof("POST ")) == 0) return 1;
	else if(strncmp(str.c_str(), "GET "	, sizeof("GET "	)) == 0) return 2;
	else return 0;
}

// URL Decode
string Http_Parser::Urldecode(string str){
    string ret;
    char ch;
    int i, ii, len = str.length();

    for (i=0; i < len; i++){
        if(str[i] != '%'){
            if(str[i] == '+')
                ret += ' ';
            else
                ret += str[i];
        }else{
            sscanf(str.substr(i + 1, 2).c_str(), "%x", &ii);
            ch = static_cast<char>(ii);
            ret += ch;
            i = i + 2;
        }
    }
    return ret;
}

// json parser
void Http_Parser::json_parser(string msg){
	int lo, index = 0;
	Http_Parser::json json_[100];
	//json parse
	lo = msg.find("{");
	msg.erase(0, lo + 2);

	while(msg.length() != 0){
		lo = msg.find('"');

		if(msg[lo+1] == ':'){
			json_[index].key = msg.substr(0, lo);
			msg.erase(0, lo + 3);
		}
		lo = msg.find('"');
		if(msg[lo+1] == ','){
			json_[index].value = msg.substr(0, lo);
			msg.erase(0, lo + 3);
		}
		else if(msg[lo+1] == '}'){
			json_[index].value = msg.substr(0, lo);
			msg.clear();	
		}
		else{
			lo = msg.find(',');
			json_[index].value = msg.substr(0, lo - 1);
			msg.erase(0, lo + 2);
		}
		if( json_[index].key == "subject" 		||
			json_[index].key == "body" 			||
			json_[index].key == "to" 			||
			json_[index].key == "cc" 			||
			json_[index].key == "bcc" 			||
			json_[index].key == "from" 			||
			json_[index].key == "file_list" 	||
			json_[index].key == "email"   )
			cout << json_[index].key << " : " << json_[index].value << endl;
		index++;
	}
}

// field-value parser
void Http_Parser::fv_parser(string msg){
	int lo, index = 0;
	string tmp_data = "";
	Http_Parser::f_v fv[100];
	while( 1 ){
		//  &
		lo = msg.find('&');
		if (lo <= 0) break;
		tmp_data = msg.substr(0, lo);
		msg.erase(0, lo + 1);
		//  field
		lo = tmp_data.find('=');
		fv[index].field = tmp_data.substr(0, lo);
		tmp_data.erase(0, lo + 1);
		//  value
		fv[index].value = tmp_data;
		tmp_data.clear();
		if( fv[index].field == "TO" 			||
			fv[index].field == "CC" 			||
			fv[index].field == "BCC" 			||
			fv[index].field == "SUBJECT" 		||
			fv[index].field == "PID" 			||
			fv[index].field == "BODY" 			||
			fv[index].field == "from" 			||
			fv[index].field == "USER_FROM_NAME" ||
			fv[index].field == "HOST" )
			cout << fv[index].field << " : " << fv[index].value << endl;
		index ++;
	}
}

// check request option
bool Http_Parser::request_Option(string method) {
	if (method == "GET " 	||
		method == "POST " 	||
		method == "HEAD " 	||
		method == "PUT " 	||
		method == "DELETE "	||
		method == "TRACE ")
		return true;
	else return false;
}

/* modify tcp payload ----------------------------------------------------------------- */
void Http_Parser::pcap_run() {
	pcap_t *handle;																	/* Session handle				 */
	u_char *packet;
	struct pcap_pkthdr *header;
    char errbuf[PCAP_ERRBUF_SIZE];

	if ((handle = pcap_open_live("eth1", BUFSIZ, PCAP_OPENFLAG_PROMISCUOUS, 10, errbuf)) == NULL) {	//device name, bufsize, promiscuous mode, time, error buffer
		err_print();
		pcap_close(handle);
		return;
	}
	else {
		task(handle, header, packet);
	}
}

void Http_Parser::task(pcap_t *handle, struct pcap_pkthdr *header, u_char *packet) {
        int res;
        u_char *payload;
        int ip_len, size_payload;
        while ((res = pcap_next_ex(handle, &header, (const u_char **)&packet)) >= 0) {
                if (res == 0) continue;
                else if (res == -1) {
                        cout << "pcap_next_ex Error !" << endl;
                        break;
                }
                else {

                        ethhdr = (ETH_HDR *)packet;

                        if (ntohs(ethhdr->eth_type) == TYPE_IP) {//IP
                        		memset(&payload, 0x00, sizeof(payload));
                                iphdr = (IP_HDR *)(sizeof(ETH_HDR) + packet);
                                ip_len = ntohs(iphdr->Length);

                                if(iphdr->Protocol == TYPE_TCP){
                                	tcphdr = (TCP_HDR *)(sizeof(ETH_HDR) + sizeof(IP_HDR) + packet);
                                	payload = (u_char *)(sizeof(ETH_HDR) + sizeof(IP_HDR) + sizeof(TCP_HDR) + packet + 12);
                                	size_payload = ip_len - ( sizeof(IP_HDR) + (tcphdr->HdrLength * 4) - 9 );
                                	payload[size_payload - 1 ] = '\0';
                                	if(ntohs(tcphdr->SrcPort) == 80 || ntohs(tcphdr->DstPort) == 80){
                                	/* print log */
                                	printf("%d.%d.%d.%d:%d -> %d.%d.%d.%d:%d\n",
                                		iphdr->SrcAddr.byte1, iphdr->SrcAddr.byte2, iphdr->SrcAddr.byte3, iphdr->SrcAddr.byte4, ntohs(tcphdr->SrcPort),
                                		iphdr->DstAddr.byte1, iphdr->DstAddr.byte2, iphdr->DstAddr.byte3, iphdr->DstAddr.byte4, ntohs(tcphdr->DstPort));
                                	printf("SeqNum : %u\nAckNum : %u\nReserved1 : %u\nHdrLength : %u\nReserved2 : %u\nWindow : %u\nChecksum : %u\nUrgPtr : %u\n",
                                		tcphdr->SeqNum, tcphdr->AckNum, tcphdr->Reserved1, tcphdr->HdrLength, tcphdr->Reserved2, tcphdr->Window, tcphdr->Checksum, tcphdr->UrgPtr);
                                	cout << "=====================================" << endl;
                                	for(int i = 0 ; i< size_payload ; i++)
                                		printf("%c", payload[i]);
                                	for(int i = 0 ; i < size_payload ; i++)
                                		printf("%02x ", payload[i]);
                                	// cout << payload<<endl;
                                	cout << endl << "=====================================" << endl<<endl;
                                	}
                                }
                        }
                }
        }
}

void Http_Parser::err_print(){
 		ofstream errfile("err.txt");					// make error file
 		streambuf* orig = cerr.rdbuf();					// save stream buffer
 		cerr.rdbuf(errfile.rdbuf());					// change stream buffer
 		cerr.rdbuf(orig);								// restore origin stream buffer
		cerr.rdbuf();
}
/* ------------------------------------------------------------------------------------ */

// running function
void run(string filename) {
	int tmp;
	int lo, index = 0;
	string tmp_data = "";

	Http_Parser hp;
	Http_Parser::message request_Message;
	Http_Parser::message response_Message;
	hp.init(&request_Message);	hp.init(&response_Message);

	tmp_data = hp.Get_Data(filename);
	hp.parse(tmp_data, &request_Message, &response_Message);
	tmp_data.clear();
	//POST == 1 GET == 2 OTHERS == 0
	if((tmp = hp.PostOrGet(request_Message.one)) == 1){
		// POST
		// Nate Mail request message.
		if(strncmp(request_Message.two.c_str(), "/app/newmail/send/send/ ", sizeof("/app/newmail/send/send/ ")) == 0){
			if(strncmp(hp.Content_Type(request_Message.header).c_str(), "urlencoded", sizeof("urlencoded")) == 0){
				request_Message.body = hp.Urldecode(request_Message.body);
				hp.json_parser(request_Message.body);
			}
		}
		// Nate Mail response message.



		// Daum Mail request message.
		if(strncmp(request_Message.two.c_str(), "/hanmailex/SendMail.daum?tabIndex=1&method=autoSave ", sizeof("/hanmailex/SendMail.daum?tabIndex=1&method=autoSave ")) == 0){
			if(strncmp(hp.Content_Type(request_Message.header).c_str(), "urlencoded", sizeof("urlencoded")) == 0){
				request_Message.body = hp.Urldecode(request_Message.body);
				hp.fv_parser(request_Message.body);
			}
			else{
				cout << "Sorry Not matched urlencoded." <<endl;
			}
		}
		// Daum Mail response message.
		
	}
	else if(tmp = 2){
		// GET
		// response body gzip uncompress
		cout << response_Message.body <<endl;
	}
	else{
		// OTHERS
		cout << "Sorry, I can't. Bye" << endl;
	}
}

int main() {
	string filename;
		while (1){
			cout << "\nInsert File Name : ";
			cin >> filename;
			run(filename);
		}
}

