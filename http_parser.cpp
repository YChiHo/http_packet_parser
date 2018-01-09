#include "http_parser.h"

Http_Parser::Http_Parser() {
}

// read data
void Http_Parser::Get_Data(string filepath, string* data) {

	char buf[FILE_READ_SIZE];
	int len;

	FILE *fp = fopen(filepath.c_str(), "r");

	if ( fp == NULL ) {
		err_print();
		fclose(fp);
		return;
	}
	else{
		while( feof(fp) != true ){
			len = fread(buf, sizeof(buf[0]), sizeof(buf) / sizeof(buf[0]), fp);
			*data += buf;
			memset(buf, 0x00, FILE_READ_SIZE);
		}
		fclose(fp);
	}
}

// 싹둑 first line
bool Http_Parser::Substr_First_Line(string line, message *message){

	int status;
	if(line.find(" ") != string::npos){

		if((status = line.find(" ")) > 0){
			message->one = line.substr(0, status + 1);
			line.erase(0, status + 1);
		}
		else
			return false;
		
		if((status = line.find(" ")) > 0){
			message->two = line.substr(0, status + 1);
			line.erase(0, status + 1);
		}
		else
			return false;

		if((status = line.find("\r\n")) > 0)
			message->three = line.substr(0, status);
	}
	return true;
}

// get content-length
string Http_Parser::Content_Length(string header, int start, int end){
	std::string data = header;
	int lo, lenstr;
	string length;
	if ((lo = data.find("Content-Length: "), start, end) > 0){
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
	if((lo = data.find("Content-Type: ")) > 0){
		lenstr = strlen("Content-Type: ");
		data.erase(0, lo);
		lo = data.find("\r\n");
		length = data.substr(lenstr, lo-lenstr);
	}

	if(length.find("urlencoded") > 0)
		return "urlencoded";
	else if(length.find("application/json"))
		return "json";
	else
		return "";
}

string Http_Parser::Accept(string header){
	string data = header;
	int lo;
	string str;
	if((lo = data.find("Accept: ")) > 0){
		data.erase(0, lo);
		lo = data.find("\r\n");
		str = data.substr(0, lo);
		return str;
	}
	else
		return "";
}

// First_Line, Header, Body parse
int Http_Parser::parse(string *data, message *msg, int locate) {

	int lo, start_header_locate, end_header_locate;
	string line;

	//first line
	lo = data->find("\r\n", locate);
	line = data->substr(locate, lo + 2);
	if(Substr_First_Line(line, msg) == true){
		locate = lo + 2;
		start_header_locate = lo + 2;

		//header
		lo = data->find("\r\n\r\n", locate);
		msg->header = data->substr(locate, lo - locate);
		locate = lo + 4;
		end_header_locate = lo + 4;

		//body
		if((lo = stoi(Content_Length(msg->header, start_header_locate, end_header_locate))) != 0 ){
			msg->body = data->substr(locate, lo);
			locate += lo;
		}
	}
	else
		return -1;
	return locate;
}

// Post or Get
int Http_Parser::PostOrGet(string str){
	if (	strncmp(str.c_str(), "POST ", sizeof("POST ")) == 0) return 1;
	else if(strncmp(str.c_str(), "GET "	, sizeof("GET "	)) == 0) return 2;
	else return 0;
}

// URL Decode
string Http_Parser::Urldecode(string *str){
    string ret;
    char ch;
    int i, ii;

    for (i=0; i < str->length(); i++){
        if(str[0][i] != '%'){
            if(str[0][i] == '+')
                ret += ' ';
            else
                ret += str[0][i];
        }else{
            sscanf(str->substr(i + 1, 2).c_str(), "%x", &ii);
            ch = static_cast<char>(ii);		//static_cast, const_cast, reinterpret_cast, dynamic_cast
            ret += ch;
            i = i + 2;
        }
    }
    return ret;
}

// json parser
void Http_Parser::body_parser_1(string msg){ // number, boolean, [] check.
	

}

		// JSON sample data
		// { "pi": 3.141,
		//   "happy": true,
		//   "name": "Niels",
		//   "nothing": null,
		//   "answer": {
		//     "everything": 42
		//   },
		//   "list": [1, 0, 2],
		//   "object": {
		//     "currency": "USD",
		//     "value": 42.99
		//   }
		//	}

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
			fv[index].field == "USER_FROM_NAME" )
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
void Http_Parser::run(string filename) {
	int tmp;
	int lo, index = 0;
	string data;

	message request_Message;
	message response_Message;

	data.clear();
	Get_Data(filename, &data);
	lo = parse(&data, &request_Message);
	lo = parse(&data, &response_Message, lo);

	//POST == 1 GET == 2 OTHERS == 0
	if((tmp = PostOrGet(request_Message.one)) == 1){
		// POST
		// Nate Mail request message.
		if(request_Message.two.compare(NATE_MAIL) == 0){
			if(Content_Type(request_Message.header).find("urlencoded") == 0){
				request_Message.body = Urldecode(&request_Message.body);
				// cout << request_Message.body << endl;
				body_parser_1(request_Message.body);
			}
		}

		// Nate Mail response message.
		// if(Content_Type(response_Message.header).find("json") > 0){
			// body_parser_1(response_Message.body);
		// }

		// Daum Mail request message.
		if(request_Message.two.compare(DAUM_MAIL) == 0){
			if(Content_Type(request_Message.header).find("urlencoded") > 0){
				request_Message.body = Urldecode(&request_Message.body);
				fv_parser(request_Message.body);
			}
		}
		// Daum Mail response message.
	}
	else if(tmp = 2){
		// GET
		// body gzip uncompress
		cout << response_Message.body <<endl;
	}
	else{
		// OTHERS
		cout << "Sorry, I can't. Bye" << endl;
	}
}

int main() {
	Http_Parser hp;
	string filename;
		// while (1){
			cout << "\nInsert File Name : ";
			cin >> filename;
			hp.run(filename);
		// }
}
