/* 
Copyright (C) 2005-2011 Tekelec

This file is part of SIP-A&T, set of tools for SIP analysis and testing.

SIP-A&T is free software; you can redistribute it and/or modify it under the
terms of the GNU General Public License as published by the Free Software
Foundation; either version 2 of the License, or (at your option) any later
version

SIP-A&T is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
A PARTICULAR PURPOSE.  See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with
this program; if not, write to the Free Software Foundation, Inc., 59 Temple
Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include <stdio.h>
#include "helper.h"

#include "LinkHandlers.h"
#include "ProtocolHandler.h"
#include "IPHandler.h"
#include "UdpHandler.h"
#include "TcpHandler.h"
#include "SCTPHandler.h"
#include "SIPHandler.h"
#include "DNSHandler.h"

#include "LogManager.h"

#include "MessageFlowTemplate.h"
#include "SIPMessageTemplate.h"
#include "DNSMessageTemplate.h"

#include <iostream>
#include <fstream>

using namespace std;

extern "C" {
#include <pcap.h>
}

#include "Configuration.h"

////////////////////////////////////////////////////////////////////

class BasicLog: public Log {
	protected:
		LogLevel logLevel;
	public:
		BasicLog() { logLevel = LL_DEBUG; }
		virtual void vlog_ex(LogLevel level, const char *file, int line, const char *s, va_list ap);
		void setLogLevel(LogLevel ll) { logLevel = ll; }
};

class SimpleLogManager: public LogManager {
	protected:
		BasicLog log;
	public:
		virtual Log *createLog(const char *log_id) { return &log; }
		virtual void releaseLog(Log *l) { /* nothing to do */ }
		void setLogLevel(LogLevel ll) { log.setLogLevel(ll); }
};


void BasicLog::vlog_ex(LogLevel level, const char* file, int line, const char *s, va_list ap)
{
	char *l;
	char error[] = "ERROR";
	char warning[] = "WARNING";
	char info[] = "";
	char debug[] = "";

	if (level > logLevel) {
		//printf("not printing\n");
		return; /* do not print */
	}

	switch (level) {
		case LL_ERR: l = error; break;
		case LL_WARN: l =  warning; break;
		case LL_INFO: l = info; break;
		case LL_DEBUG: l = debug; break;
	}
	if (file) printf("%s [%s:%d]: ", l, file, line);
	else if (*l) printf("%s: ", l);
	vprintf(s, ap);
}


////////////////////////////////////////////////////////////////////

static int process_packets(ProtocolHandlerContext *handlers, pcap_t *p)
{
	struct pcap_pkthdr *header;
	const u_char *data;
	int r;
	int link;
	ProtocolHandler *h = NULL;
	Log *log = LogManager::getDefaultLog(NULL);

	link = pcap_datalink(p);
	switch (link) {

		case DLT_EN10MB:
			h = handlers->find(EthernetHandler::id);
			break;

		case DLT_LINUX_SLL:
			h = handlers->find(LinuxSLLHandler::id);
			break;

		default:
			 h = NULL;
		
	}
	if (!h) {
		ERR("unsupported datalink: %d (%s)\n", link, pcap_datalink_val_to_name(link)); 
		return E_UNSUPPORTED_DATALINK;
	}

	r = pcap_next_ex(p, &header, &data);
	while (r > 0) {

		if (header->len != header->caplen) {
			WARN("ignoring not whole packet (captured %d of %d bytes)\n", 
					header->caplen, header->len); 
			/* not whole packet */
			r = pcap_next_ex(p, &header, &data);
			continue;
		}

		h->processPacket(&header->ts, (unsigned char *)data, header->len, NULL);
		r = pcap_next_ex(p, &header, &data);
		
		log->log(LL_DEBUG, "\n-----\n\n");
	}
	if (r == -2) return 0;
	return -1;
}

static int process_pcap_file(Log *l, ProtocolHandlerContext *context, const char *filename)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *p;
	int res;

	p = pcap_open_offline(filename, errbuf);
	if (!p) {
		res = E_INVALID_DUMP_FILE;
		l->error("can't open dump file: %s\n", filename);
	}
	else {
		res = process_packets(context, p);
		pcap_close(p);
	}

	return res;
}

bool printToFile(string &file_name)
{
	if (file_name.size() == 0) return false; /* empty file name */
	if (strcmp(file_name.c_str(), "-") == 0) 
		return false; /* file name is - */
	return true;
}

int process_pcap_files(Configuration &cfg)
{
	int res = 0;
	MessageFlow flow(&cfg.dm, true, cfg.sortDestinationsAccordingTime);
	ProtocolHandlerContext handlers(&flow, true);

	if (cfg.printStream) flow.printStreamToFile(cfg.printStreamFile.c_str());

	Log *l = LogManager::getDefaultLog(NULL);
	if (!l) return -1; /* can't log */

	/* prepare protocol handlers */
	handlers.add(new EthernetHandler());
	handlers.add(new LinuxSLLHandler());
	handlers.add(new IPHandler(cfg.ignoreSeenIPPackets));
	handlers.add(new DNSHandler(cfg.dns, cfg.ignoreSERDnsWatchdog, cfg.ignorePTR));
	handlers.add(new UdpHandler());
	handlers.add(new TcpHandler());
	handlers.add(new SCTPHandler(cfg.sctp_flow));
	SIPHandler *sip = new SIPHandler(cfg.sip);
	if (sip) sip->setIgnoreOPTIONS(cfg.ignoreOPTIONS);
	handlers.add(sip);
	if (handlers.initContext()) {
		l->error("can't initialize handler context\n");
		return -1;
	}

	for (unsigned int i = 0; i < cfg.inputFiles.size(); i++) {
		process_pcap_file(l, &handlers, cfg.inputFiles[i].c_str());
	}

	if (cfg.cfPrint) {
		if (printToFile(cfg.cfPrintFile)) {
			std::ofstream out;
			out.open(cfg.cfPrintFile.c_str());
			flow.cfprint(out);
			out.close();
		}
		else flow.cfprint(cout);
	}
	if (cfg.txtPrint) {
		if (printToFile(cfg.txtPrintFile)) {
			std::ofstream out;
			out.open(cfg.txtPrintFile.c_str());
			flow.txtprint(out);
			out.close();
		}
		else {
			flow.txtprint(cout);
		}
	}

	if (cfg.flowTemplateFile.size() > 0) {
		MessageFlowTemplate flowTemplate(cfg.ignore_unexpected_dns);

		flowTemplate.registerTemplate("sip-request", new SIPRequestTemplateFactory());
		flowTemplate.registerTemplate("sip-reply", new SIPResponseTemplateFactory());
		flowTemplate.registerTemplate("dns-request", new DNSRequestTemplateFactory());
		flowTemplate.registerTemplate("dns-reply", new DNSResponseTemplateFactory());

		if (!flowTemplate.readFromXMLFile(cfg.flowTemplateFile.c_str())) {
			printf("can't read call flow template\n");
			res = -1;
			return res;
		}

		if (!flowTemplate.verify(&flow)) {
			res = -1;
			printf("flow verfication FAILED\n");
		}
		else {
			res = 0;
			printf("flow verfication OK\n");
		}
	}

	return res;
}

static void print_args(int argc, char **argv, std::ostream &out)
{
	int i;

	out << "\n\n==============================================================\n";

/*	out << "\nProgram arguments:\n";
	for (i = 1; i < argc; i++) {
		out << "   " << argv[i] << "\n";
	}*/
	out << "\nRun:\n";
	for (i = 0; i < argc; i++) {
		out << argv[i] << " ";
	}
	out << "\n";
}

int main(int argc, char **argv)
{
	SimpleLogManager m;
	Configuration cfg;

	LogManager::setDefaultLogManager(&m);

	if (!cfg.readArgs(argc, argv)) {
		cfg.printHelp();
		return -1;
	}
	m.setLogLevel(cfg.logLevel);

	int res = process_pcap_files(cfg);
	
	if (cfg.txtPrint) { 
		// append configuration to text print
		if (printToFile(cfg.txtPrintFile)) {
			std::ofstream f;
			f.open(cfg.txtPrintFile.c_str(), std::ofstream::app);
			print_args(argc, argv, f);
			f.close();
		}
		else {
			print_args(argc, argv, cout);
		}
	}
	
	LogManager::setDefaultLogManager(NULL);

	return res;
}
