#include "http_parser.h"

Http_Parser::Http_Parser() {
	//Hello World
	// ctrl+K+D 줄맞춤
	//jsoncpp, zlib
}

// read data
bool Http_Parser::Get_Data(string filepath, string* data) {
	FILE *fp;
	char buf[FILE_READ_SIZE];
	int len;
	
	fp = fopen(filepath.c_str(), "r");

	if ( fp != NULL ) {
		while( feof(fp) != true ){
			len = fread(buf, sizeof(buf[0]), sizeof(buf) / sizeof(buf[0]), fp);
			*data += buf;
			memset(buf, 0x00, FILE_READ_SIZE);
		}
		fclose(fp);
		return true;
	}
	else{
		Err_Print();
		return false;
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
string Http_Parser::Content_Type(string header){
	string data = header;
	int lo, lenstr;
	string length;
	if((lo = data.find("Content-Type: ")) > 0){
		lenstr = strlen("Content-Type: ");
		data.erase(0, lo);
		lo = data.find("\r\n");
		length = data.substr(lenstr, lo-lenstr);
	}

	return length;
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
int Http_Parser::Parse(string *data, message *msg, int locate) {

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
int Http_Parser::Post_Or_Get(string str){
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

// NATE MAIL Body Parser
void Http_Parser::Body_Parser_1(string msg){
	int lo, index = 0;
	json json_[100];
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

// json parser
void Http_Parser::Json_Parser(string msg){
	
	FILE* JSON_File = NULL;
	Json::Reader reader;
	Json::Value root;
	Json::StyledWriter writer;
	size_t fileSize;

	if(msg[0] == '['){
		msg.erase(0, 1);
		msg.pop_back();
	}
	bool parsingRet = reader.parse(msg, root);

	if (!parsingRet){
		std::cout << "Failed to parse Json : " << reader.getFormattedErrorMessages();
		return;
	}
	else{
		if((JSON_File = fopen(JSON_FILE_NAME, "r")) == NULL){
			if((JSON_File = fopen(JSON_FILE_NAME, "w")) != NULL){
				fileSize = fwrite(writer.write(root).c_str(), 1, writer.write(root).length(), JSON_File);
				fclose(JSON_File);
			}
			else
				cout << "json write fail" << endl;
		}
		else {
			if((JSON_File = fopen(JSON_FILE_NAME, "a+")) != NULL){
				fileSize = fwrite(writer.write(root).c_str(), 1, writer.write(root).length(), JSON_File);
				fclose(JSON_File);
			}
			else
				cout << "json write fail" << endl;
		}
	}	
}

// field-value parser
void Http_Parser::Fv_Parser(string msg){
	int lo, index = 0;
	string tmp_data = "";
	f_v fv[100];
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
bool Http_Parser::Request_Option(string method) {
	if (method == "GET " 	||
		method == "POST " 	||
		method == "HEAD " 	||
		method == "PUT " 	||
		method == "DELETE "	||
		method == "TRACE ")
		return true;
	else return false;
}

// Gzip uncompress
void Http_Parser::Gzip_Uncompress(string filename){
	gzFile gzf = gzopen(filename.c_str(), "rb");
	char* gzbuf = (char*) malloc(GZ_SIZE * sizeof(char) + 1);
	// gzFile *ungzf = gzopen("Hello.txt", "wb+");
	
	if(gzf == NULL) {
		cout << "File Open Error" << endl;
		return;
	}

	if (gzread(gzf, gzbuf, GZ_SIZE) < 0) {
		cout << "Gz Read Error" << endl;
		return;
	}

	else 
		cout << gzbuf << endl;

	return;
}

/* modify tcp payload ----------------------------------------------------------------- */
void Http_Parser::Pcap_Run() {
	pcap_t *handle;																	/* Session handle				 */
	u_char *packet;
	struct pcap_pkthdr *header;
    char errbuf[PCAP_ERRBUF_SIZE];

	if ((handle = pcap_open_live("eth1", BUFSIZ, PCAP_OPENFLAG_PROMISCUOUS, 10, errbuf)) == NULL) {	//device name, bufsize, promiscuous mode, time, error buffer
		Err_Print();
		pcap_close(handle);
		return;
	}
	else {
		Task(handle, header, packet);
	}
}

void Http_Parser::Task(pcap_t *handle, struct pcap_pkthdr *header, u_char *packet) {
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

void Http_Parser::Err_Print(){
 		ofstream errfile("err.txt");					// make error file
 		streambuf* orig = cerr.rdbuf();					// save stream buffer
 		cerr.rdbuf(errfile.rdbuf());					// change stream buffer
 		cerr.rdbuf(orig);								// restore origin stream buffer
		cerr.rdbuf();
}
/* ------------------------------------------------------------------------------------ */

// running function
void Http_Parser::Run() {
	
	string filename;
	int post_get;
	bool real_data;

	while (1){
		string data;
		int lo, index = 0;
		message request_message;
		message response_message;

		cout << "\nInsert File Name : ";
		cin >> filename;

		data.clear();
		real_data = Get_Data(filename, &data);
		if( data.length() > 0 && real_data == true){
			lo = Parse(&data, &request_message);
			lo = Parse(&data, &response_message, lo);

			if((post_get = Post_Or_Get(request_message.one)) == POST){

				/* NATE MAIL----------------------------------------------------- */
				// request message.
				if(request_message.two.compare(NATE_MAIL) == 0){
					if(Content_Type(request_message.header).find("urlencoded") >= 0){
						request_message.body = Urldecode(&request_message.body);
						Body_Parser_1(request_message.body);
					}
					// response message.
					if(Content_Type(response_message.header).find("json") >= 0){
						Json_Parser(response_message.body);
					}
					// else if(Content_Type(response_message.header).find("gzip") >= 0)
					// 	Gzip_Uncompress();

				}
				/* NATE MAIL----------------------------------------------------- */

				/* Daum MAIL----------------------------------------------------- */
				// request message.
				if(request_message.two.compare(DAUM_MAIL) == 0){
					if(Content_Type(request_message.header).find("urlencoded") >= 0){
						request_message.body = Urldecode(&request_message.body);
						Fv_Parser(request_message.body);
					}
				}
				// Daum Mail response message.
				/* Daum MAIL----------------------------------------------------- */
			}
			else if(post_get == GET){
			// GET
			// body gzip uncompress
				// Gzip_Uncompress(response_message.body);
				
			}
			else{
		// OTHERS
				cout << "Sorry, I can't. Bye" << endl;
			}
		}
		else
			continue;
	}
}

int main() {
	Http_Parser hp;
	hp.Run();
}