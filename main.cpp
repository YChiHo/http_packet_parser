#include "http_parser.h"

Http_Parser::Http_Parser() {
}

// 변수 초기화
void Http_Parser::init(message *msg) {
	try {
		msg->first_Line->one.clear();
		msg->first_Line->two.clear();
		msg->first_Line->three.clear();
		msg->header.clear();
		msg->body.clear();
	}
	catch (int Exception) {
		err_print();
		return;
	}
}

// 파일에서 데이터 읽기
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

void Http_Parser::pcap_init() {
	pcap_t *handle;																	/* Session handle				 */
	struct pcap_pkthdr *header;														/*								 */
	char errbuf[PCAP_ERRBUF_SIZE];													/* Error string					 */
	bpf_u_int32 mask = 0;															/* Our netmask					 */
	bpf_u_int32 net = 0;															/* Our IP						 */
	u_char *packet;																	/*				  				 */
	pcap_if_t *alldevs, *d;															/*	 							 */
	int i = 0, num;

	if ((handle = pcap_open_live(d->name, BUFSIZ, PCAP_OPENFLAG_PROMISCUOUS, 1, errbuf)) == NULL) {	//장치이름, 패킷캡쳐부분, promiscuous mode, 시간, 에러버퍼
		fprintf(stderr, "Couldn't open device %s: %s\n", d->name, errbuf);
		return;
	}


}

void task(pcap_t *handle, struct pcap_pkthdr *header, u_char *packet) {
	int res;
	while ((res = pcap_next_ex(handle, &header, (const u_char **)&packet)) >= 0) {
		if (res == 0) continue;
		else if (res == -1) {
			cout << "pcap_next_ex Error !" << endl;
			break;
		}
		else packet_hand(packet, header->caplen);
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
 		ofstream errfile("err.txt");					// 에러 출력할 파일 지정
 		streambuf* orig = cerr.rdbuf();					// 기존 스트림 버퍼 저장
 		cerr.rdbuf(errfile.rdbuf());					// 출력할 파일로 스트림버퍼 재 지정
 		cerr.rdbuf(orig);								// 기존 스트림버퍼 복구
		cerr.rdbuf();
 }

// 실질 함수 실행
void run(char **argv) {
	string tmp_data = "";

	Http_Parser::message request_Message;
	Http_Parser::message response_Message;
	Http_Parser hp;
	hp.init(&request_Message);	hp.init(&response_Message);

	//hp.Get_Line(tmp_data);
}

int main(int argc, char **argv) {

	if (argc < 2 || argc > 2)
		cout << "Example : " << argv[0] << " sample_file\n";

	while (1)
		run(argv);

	return 0;
}
