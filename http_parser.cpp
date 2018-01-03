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

string Http_Parser::Content_Length(string header){
	std::string data = header;
	int lo, lenstr;
	string length;
	lo = data.find("Content-Length: ");
	lenstr = strlen("Content-Length: ");
	data.erase(0, lo);
	lo = data.find("\r\n");
	length = data.substr(lenstr, lo-lenstr);
	return length;
}

string Http_Parser::Content_Type(string header){			// need Modify
	std::string data = header;
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
			request_Message->body = data.substr(0, locate + 1);
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

bool Http_Parser::request_Option(string method) {
	if (method == "GET " 	||
		method == "POST " 	||
		method == "HEAD " 	||
		method == "PUT " 	||
		method == "DELETE " ||
		method == "TRACE ")
		return true;
	else return false;
}

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

// running function
void run(string filename) {
	string tmp_data = "";

	Http_Parser hp;
	Http_Parser::message request_Message;
	Http_Parser::message response_Message;
	hp.init(&request_Message);	hp.init(&response_Message);

	tmp_data = hp.Get_Data(filename);
	hp.parse(tmp_data, &request_Message, &response_Message);

	//----------------------------------- fl, rq h, rq b, fl, rs h, rs b ok//
	//TODO : rq Header parsing ---> 
	//body : decoding

}

int main() {
	string filename;
		//while (1){
			cout << "Insert File Name : ";
			cin >> filename;
			run(filename);
		//}
}
