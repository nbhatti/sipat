#include "Configuration.h"
#include <stdio.h>
#include <string.h>
#include <iostream>
#include "UdpHandler.h"
#include "TcpHandler.h"
#include "SCTPHandler.h"

using namespace std;

Configuration::Configuration()
{
	ignoreSeenIPPackets = DO_NOT_IGNORE;
	sortDestinationsAccordingTime = false;
	cfPrint = false;
	txtPrint = false;
	logLevel = LL_INFO;

	sip = true;
	dns = true;
	ignoreSERDnsWatchdog = false;
	ignorePTR = false;
	ignoreOPTIONS = false;
	sctp_flow = false;

	ignore_unexpected_dns = false;
	printStream = false;
}

void Configuration::printHelp()
{
	const char *help = 
		"\nParameters:\n"
		" -r <input PCAP file>  read PCAP file\n"
		"                       at least one PCAP file must be given\n"
		"\n"
		" -a <protocol:address=alias>    add alias for message source/destination\n"
		"                                for example udp:1.2.3.4:5060=uac\n"
		"                                supported protocols: udp\n"
		" -o <output XML file>           file to print callflow into\n"
		"\nControlling output:\n"
		" -print-cf <output XML file>    file to print XML callflow into\n"
		" -print-txt <output text file>  file to print textual callflow into\n"
		" -debug                         switch on debugging\n"
		"\nHandling specific protocols:\n"
		" -dns                           handle DNS (default)\n"
		" -no-dns                        do not handle DNS\n"
		" -sip                           handle SIP (default)\n"
		" -no-sip                        do not handle SIP\n"
		"\nTuning:\n"
		" -ignore-seen                   the same as -ignore-id-unsafe\n"
		" -ignore-id-unsafe              ignore IP packets with the same nonzero IP id\n"
		" -ignore-id-safe                ignore IP packets with the same nonzero IP id and DF unset\n"
		" -ignore-same-data              ignore IP packets with the same data for short time interval\n"
		" -do-not-ignore                 do not ignore any IP packets (default)\n"
		"\n"
		" -ignore-ser-dns-wd             ignore SER DNS watchdog queries (_sip._udp)\n"
		" -ignore-dns-ptr                ignore DNS PTR queries and responses\n"
		"\n"
		" -time-sort-destinations        sort destinations in CF according usage time\n"
		" -no-destinations-sort          don not sort destinations in CF\n"
		" -verify-cf <input XML file>    compare callflow with description in given file\n"
		" -ignore-unexpected-dns         ignore unexpected DNS messages in callflow verification\n"
		;
	printf("arguments:\n%s", help);
}

bool readIPandPort(unsigned char *addr, unsigned int *dst_port, 
		const char *s, unsigned int len, bool *ignore_port)
{
	int ip, idx;

	enum { read_ip, read_port } state;
	
	state = read_ip;
	ip = 0;
	idx = 0;
	*dst_port = 0;
	*ignore_port = true; /* port not given */
	for (unsigned int i = 0; i < len; i++) {
		switch (state) {
			case read_ip:
				if ((s[i] >= '0') && (s[i] <= '9')) {
					ip = 10 * ip + (s[i] - '0');
				}
				else {
					if (s[i] == '.') {
						addr[idx] = (unsigned char)ip;
						if (idx == 3) state = read_port;
						else {
							idx++;
							ip = 0;
						}
					}
					else {
						if (s[i] == ':') {
							addr[idx] = (unsigned char)ip;
							state = read_port;
						}
						else return false;
					}
				}
				break;

			case read_port:
				if ((s[i] >= '0') && (s[i] <= '9')) {
					*dst_port = 10 * (*dst_port) + (s[i] - '0');
					*ignore_port = false;
				}
				else {
					if (s[i] == '*') {
						if (!(*ignore_port)) return false; /* already tried to set port */
						*dst_port = 0;
					}
					else return false;
				}
				break;
		}

	}
	if (state == read_ip) {
		addr[idx] = (unsigned char)ip;
		if (idx == 3) return true;
		else return false;
	}

	return true;
}
		
bool Configuration::handleProtocolAlias(const char *proto, 
		unsigned int proto_len,
		const char *addr, unsigned int addr_len, 
		const char *name)
{
#define check_proto(p)	((strlen(p) == proto_len) && (strncasecmp(p, proto, proto_len) == 0))
	
	//printf("handling alias for address: %.*s\n", addr_len, addr);

	if (check_proto("udp")) {
		unsigned int port;
		unsigned char ip_addr[4];
		bool ignore_port;
		if (!readIPandPort(ip_addr, &port, addr, addr_len, &ignore_port)) {
			printf("invalid UDP address (not in the format IP:port)\n");
			return false;
		}
		IPAddress ip(ip_addr);
		UdpDestination *d = new UdpDestination(ip, port, ignore_port);
		if (d) {
			d->setName(name);
			//d->cfprintDef(cout, 0, 0);
			//d->cfprintValue(cout);
			dm.add(d);
		}
		return true;
	}

	if (check_proto("tcp")) {
		unsigned int port;
		unsigned char ip_addr[4];
		bool ignore_port;
		if (!readIPandPort(ip_addr, &port, addr, addr_len, &ignore_port)) {
			printf("invalid TCP address (not in the format IP:port)\n");
			return false;
		}
		IPAddress ip(ip_addr);
		TcpDestination *d = new TcpDestination(ip, port, ignore_port);
		if (d) {
			d->setName(name);
			//d->cfprintDef(cout, 0, 0);
			//d->cfprintValue(cout);
			dm.add(d);
		}
		return true;
	}

	if (check_proto("sctp")) {
		unsigned int port;
		unsigned char ip_addr[4];
		bool ignore_port;
		if (!readIPandPort(ip_addr, &port, addr, addr_len, &ignore_port)) {
			printf("invalid SCTP address (not in the format IP:port)\n");
			return false;
		}
		IPAddress ip(ip_addr);
		SCTPDestination *d = new SCTPDestination(ip, port, ignore_port);
		if (d) {
			d->setName(name);
			//d->cfprintDef(cout, 0, 0);
			//d->cfprintValue(cout);
			dm.add(d);
		}
		return true;
	}

	return false;
}

bool Configuration::handleAlias(const char *alias_arg)
{
	enum { reading_proto, reading_addr, reading_name } state;
	
	unsigned int proto_len = 0;
	const char *proto = alias_arg;
	unsigned int addr_len = 0;
	const char *addr = NULL;
	unsigned int name_len = 0;
	const char *name = NULL;
	int eq_pos = -1;

	state = reading_proto;

	for (int i = 0; alias_arg[i]; i++) {
		if ((alias_arg[i] == '=') && (eq_pos < 0)) eq_pos = i;
		switch (state) {
			case reading_proto:
				if (alias_arg[i] == ':') {
					state = reading_addr;
					addr = alias_arg + i + 1;
				}
				else proto_len++;
				break;

			case reading_addr:
				if (alias_arg[i] == '=') {
					state = reading_name;
					name = alias_arg + i + 1;
				}
				else addr_len++;
				break;

			case reading_name:
				name_len++; /* not needed to go through the string to the end? */
		}
	}

	bool res = false;
	if ((proto_len > 0) && (addr_len > 0) && (name_len > 0)) {
		res = handleProtocolAlias(proto, proto_len, 
			addr, addr_len, name);
	}
	if (!res) {
		/* is not fully given or unknown protocol, try to handle as TCP and UDP */
		if (eq_pos < 0) return false; /* no '=' ...invalid alias */

		// might be that protocol is not given - try UDP and TCP and SCTP
		if (handleProtocolAlias("udp", 3, alias_arg, eq_pos, 
				alias_arg + eq_pos + 1)) res = true;
		if (handleProtocolAlias("tcp", 3, alias_arg, eq_pos, 
				alias_arg + eq_pos + 1)) res = true;
		if (handleProtocolAlias("sctp", 4, alias_arg, eq_pos, 
				alias_arg + eq_pos + 1)) res = true;
	}

	/* here we have name zero terminated */

	return res;
}

bool Configuration::readArgs(int argc, char **argv)
{
	for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "-r") == 0) {
			if (++i >= argc) return false;
			inputFiles.push_back(argv[i]);
			continue;
		}
/*		if (strcmp(argv[i], "-o") == 0) {
			if (++i >= argc) return false;
			cfPrint = true;
			cfPrintFile = argv[i];
			continue;
		}*/
		if (strcmp(argv[i], "-a") == 0) {
			if (++i >= argc) return false;
			if (!handleAlias(argv[i])) {
				printf("can't handle alias: %s\n", argv[i]);
				//return false;
			}
			continue;
		}
		if (strcmp(argv[i], "-print-cf") == 0) {
			if (++i >= argc) return false;
			cfPrint = true;
			cfPrintFile = argv[i];
			continue;
		}
		if (strcmp(argv[i], "-print-txt") == 0) {
			if (++i >= argc) return false;
			txtPrint = true;
			txtPrintFile = argv[i];
			continue;
		}
		if (strcmp(argv[i], "-print-stream") == 0) {
			if (++i >= argc) return false;
			printStream = true;
			printStreamFile = argv[i];
			continue;
		}
		if (strcmp(argv[i], "-ignore-id-safe") == 0) {
			/* for compatibility reasons */
			ignoreSeenIPPackets = IGNORE_IP_ID_SAFE;
			continue;
		}
		if (strcmp(argv[i], "-ignore-same-data") == 0) {
			/* for compatibility reasons */
			ignoreSeenIPPackets = IGNORE_SHORT_INTERVAL_SAME_DATA;
			continue;
		}
		if (strcmp(argv[i], "-ignore-id-unsafe") == 0) {
			/* for compatibility reasons */
			ignoreSeenIPPackets = IGNORE_IP_ID_UNSAFE;
			continue;
		}
		if (strcmp(argv[i], "-ignore-seen") == 0) {
			ignoreSeenIPPackets = IGNORE_IP_ID_UNSAFE;
			continue;
		}
		if (strcmp(argv[i], "-do-not-ignore") == 0) {
			ignoreSeenIPPackets = DO_NOT_IGNORE;
			continue;
		}
		if (strcmp(argv[i], "-time-sort-destinations") == 0) {
			sortDestinationsAccordingTime = true;
			continue;
		}
		if (strcmp(argv[i], "-no-destinations-sort") == 0) {
			sortDestinationsAccordingTime = false;
			continue;
		}
		if (strcmp(argv[i], "-ignore-OPTIONS") == 0) {
			ignoreOPTIONS = true;
			continue;
		}
		if (strcmp(argv[i], "-debug") == 0) {
			logLevel = LL_DEBUG;
			continue;
		}
		if (strcmp(argv[i], "-sip") == 0) {
			sip = true;
			continue;
		}
		if (strcmp(argv[i], "-no-sip") == 0) {
			sip = false;
			continue;
		}
		if (strcmp(argv[i], "-dns") == 0) {
			dns = true;
			continue;
		}
		if (strcmp(argv[i], "-no-dns") == 0) {
			dns = false;
			continue;
		}
		if (strcmp(argv[i], "-ignore-ser-dns-wd") == 0) {
			ignoreSERDnsWatchdog = true;
			continue;
		}
		if (strcmp(argv[i], "-ignore-dns-ptr") == 0) {
			ignorePTR = true;
			continue;
		}
		if (strcmp(argv[i], "-sctp-flow") == 0) {
			sctp_flow = true;
			continue;
		}
		if (strcmp(argv[i], "-no-sctp-flow") == 0) {
			sctp_flow = false;
			continue;
		}
		if (strcmp(argv[i], "-verify-cf") == 0) {
			if (++i >= argc) return false;
			flowTemplateFile = argv[i];
			continue;
		}
		if (strcmp(argv[i], "-ignore-unexpected-dns") == 0) {
			ignore_unexpected_dns = true;
			continue;
		}

		return false; /* unknown argument here */
	}
	return true;
}
