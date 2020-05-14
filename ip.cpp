#include<cstring>
#include<fstream>
#include<cstdlib>
#include<iostream>
#include<sstream>
#include<cmath>
using namespace std;

struct IP{
	string ip_packet;
	string ip_version;
	int ip_headLength;
	string ip_service;
	int ip_length;
	string ip_identifier;
	string ip_flag;
	int ip_offset;
	int ip_TTL;
	string ip_protocol;
	string ip_verifier;
	string ip_source_address;
	string ip_destination_address;
}ip_1;

void show()
{
	cout << "版本：" << ip_1.ip_version << endl;
	cout << "首部长度："<< ip_1.ip_headLength << "字节" << endl;
	cout << "区分服务："<< ip_1.ip_service << endl;
	cout << "总长度：" << ip_1.ip_length << "字节" << endl;
	cout << "标识："<< ip_1.ip_identifier<<endl;
	cout << "标志：" << ip_1.ip_flag<<endl;
	cout << "片偏移:" << ip_1.ip_offset << "位" <<endl;
	cout << "生存时间："<< ip_1.ip_TTL<<endl;
	cout << "协议："<<ip_1.ip_protocol<<endl;
	cout << "首部检验和："<<ip_1.ip_verifier<<endl;
	cout << "源地址：" << ip_1.ip_source_address<<endl;
	cout << "目的地址：" << ip_1.ip_destination_address << endl;
}

string S_clear(char *data)
{
	char content[255];
	int i = 0;
	int f = 0;
	while(data[i]!='\0')
	{
		if(data[i]!= ' '&& data[i]!='\t'&&data[i]!='\n')
		{
			content[f] = data[i];
			f++;
		}
		i++;
	}
	return content;
}

void read_file()
{
	FILE *in;
	int i;
	char data[255]="None";
	const char* fName = "ip_packet.txt";
	in = fopen(fName,"r");
	if(in==NULL)
	{
		cout << "File cannnot be opened." << endl;
		exit(0);
	}
	else
	{
		cout << "File opened for reading." << endl;
	}
	for(i=0;!feof(in);i++)
	{
		data[i]=fgetc(in);
	}
	ip_1.ip_packet = S_clear(data);
	fclose(in);
}

void write_file()
{
	fstream out;
	const char* fname = "out.txt";
	out.open(fname,ios::out);
	if(!out.is_open())
	{
		cout << "File cannnot be opened." << endl;
		exit(0);
	}
	else
	{
		cout << "File opened for writing." << endl;
	}
	out << "版本：" << ip_1.ip_version << endl;
	out << "首部长度："<< ip_1.ip_headLength << "位" << endl;
	out << "区分服务："<< ip_1.ip_service << endl;
	out << "总长度：" << ip_1.ip_length << "位" << endl;
	out << "标识："<< ip_1.ip_identifier<<endl;
	out << "标志：" << ip_1.ip_flag<<endl;
	out << "片偏移:" << ip_1.ip_offset << "位" <<endl;
	out << "生存时间："<< ip_1.ip_TTL<<endl;
	out << "协议："<<ip_1.ip_protocol<<endl;
	out << "首部检验和："<<ip_1.ip_verifier<<endl;
	out << "源地址：" << ip_1.ip_source_address<<endl;
	out << "目的地址：" << ip_1.ip_destination_address << endl;
	out.close();
//	fprintf("");
}
void get_version()
{
	string version;
	version = ip_1.ip_packet[0];
	if(version == "4")
	{
		ip_1.ip_version = "IPV4";
	}
	else if(version == "6")
	{
		ip_1.ip_version = "IPV6";
	}
	else
	{
		cout << "ERROR!" << endl;
		exit(0);
	}
}

void get_hLength()
{
	string hLength;
	int hL;
	stringstream stream;
	hLength = ip_1.ip_packet[1];
	stream << std::hex << hLength;
	stream >> hL;
	ip_1.ip_headLength = hL * 4; 
}

void get_service()
{
	
}

void get_Length()
{
	string Length;
	int L;
	stringstream stream;
	Length = ip_1.ip_packet.substr(4,4);
	stream << std::hex <<Length;
	stream >> L;
	ip_1.ip_length = L; 
}

void get_identifier()
{
	string identify;
	identify = ip_1.ip_packet.substr(8,4);
	ip_1.ip_identifier = identify;
	
}

void get_flag()
{
	stringstream stream;
	string flag;
	int f;
	flag = ip_1.ip_packet[12];
	stream << std::hex <<flag;
	stream >> f;
	f = f/2;
	if((f%4)/2 == 0)
	{
		ip_1.ip_flag = "允许分片；";
		if(f%2 == 1)
		{
			ip_1.ip_flag += "还有分片。";
		}
		else
		{
			ip_1.ip_flag += "最后一个分片。";
		}
	}
	else
	{
		ip_1.ip_flag = "不允许分片。";
	}
}

void get_offset()
{
	stringstream stream;
	string offset;
	int off;
	offset = ip_1.ip_packet.substr(12,4);
	stream << std::hex << offset;
	stream >> off;
	off = off % (int)pow(2,13);
	ip_1.ip_offset = off;	
}

void get_TTL()
{
	stringstream stream;
	string time;
	int t;
	time = ip_1.ip_packet.substr(16,2);
	stream << std::hex << time;
	stream >> t;
	ip_1.ip_TTL = t;
}

void get_protocol()
{
	stringstream stream;
	string protocol;
//	int p;
	protocol = ip_1.ip_packet.substr(18,2);
//	stream << std::hex << protocol;
//	stream >> p;
	if(protocol == "01")
	{
		ip_1.ip_protocol = "ICMP";
	}
	else if(protocol == "02")
	{
		ip_1.ip_protocol = "IGMP";
	}
	else if(protocol == "06")
	{
		ip_1.ip_protocol = "TCP";
	}
	else if(protocol == "17")
	{
		ip_1.ip_protocol = "UDP";
	}
	else if(protocol == "89")
	{
		ip_1.ip_protocol = "OSPF";
	}
}

void get_verifier()
{
	string verifier;
	verifier = ip_1.ip_packet.substr(20,4);
	ip_1.ip_verifier = verifier;
	
}

string get_Saddress(int n=24)
{
	stringstream stream;
	string address;
	string ad;
	char a[10];
	int i;
	address = ip_1.ip_packet.substr(n,8);
	stream << std::hex <<address.substr(0,2);
	stream >> i;
	stream.clear();
	itoa(i,a,10);
	ad += a;
	ad +=".";
	stream << std::hex <<address.substr(2,2);
	stream >> i;
	stream.clear();
	itoa(i,a,10);
	ad += a;
	ad += ".";
	stream << std::hex <<address.substr(4,2);
	stream >> i;
	stream.clear();
	itoa(i,a,10);
	ad += a;
	ad +=".";
	stream << std::hex <<address.substr(6,2);
	stream >> i;
	stream.clear();
	itoa(i,a,10);
	ad += a;
	return ad;
}

string get_Daddress()
{
	return get_Saddress(32);
}

int main()
{
	read_file();
	get_version();
	get_hLength();
	get_identifier();
	get_verifier();
	get_protocol();
	get_Length();
	get_flag();	
	get_offset();
	get_TTL();
	ip_1.ip_source_address = get_Saddress();
	ip_1.ip_destination_address = get_Daddress();
	
	show();
	write_file();
	return 0;
}
