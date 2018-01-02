#include "http_parser.h"

Http_Parser::Http_Parser() {
}

// init variable
void Http_Parser::init(message *msg) {
	try {
		// msg->first_Line->one.clear();
		// msg->first_Line->two.clear();
		// msg->first_Line->three.clear();
		// msg->header.clear();
		// msg->body.clear();
	}
	catch (int Exception) {
		err_print();
		return;
	}
}

// read data
string Http_Parser::Get_Data(string filepath) {

	string read_Data = NULL;
	string tmp = NULL;
	fstream f(filepath.c_str());

	try {
		if (f.is_open() == true) {
			while (getline(f, tmp)) {
				read_Data += tmp;
			}
			f.close();
		}
	}
	catch (int Exception) {
		err_print();
		f.close();
		return "";
	}

	return read_Data;
}

string Http_Parser::Get_Line(string data) {
	string line;
	line = data.substr(0, data.find("\r\n"));
	return line;
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

bool Http_Parser::request_Option(string method) {
	if (method == "GET " ||
		method == "POST " ||
		method == "HEAD " ||
		method == "PUT " ||
		method == "DELETE " ||
		method == "TRACE ")
		return true;
	else return false;
}

 void Http_Parser::err_print(){
 		ofstream errfile("err.txt");					// make error file
 		streambuf* orig = cerr.rdbuf();					// save stream buffer
 		cerr.rdbuf(errfile.rdbuf());					// change stream buffer
 		cerr.rdbuf(orig);								// restore origin stream buffer
		cerr.rdbuf();
 }

// running function
void run(char *argv) {
	string tmp_data = "";

	Http_Parser::message request_Message;
	Http_Parser::message response_Message;
	Http_Parser hp;
	hp.init(&request_Message);	hp.init(&response_Message);
	hp.pcap_run();
	//hp.Get_Line(tmp_data);
}

int main(int argc, char **argv) {

	if (argc < 2 || argc > 2){
		cout << "Example : " << argv[0] << " sample_file\n";
		return 0;
	}

	else{
		while (1)
			run(argv[1]);
	}


}
