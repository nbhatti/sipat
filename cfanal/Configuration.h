#ifndef __CONFIGURATION_H
#define __CONFIGURATION_H

#include <cfanal/Destination.h>
#include <string>
#include <vector>
#include <cfanal/LogManager.h>
#include <cfanal/IPHandler.h>
#include <cfanal/MessageFlowTemplate.h>

class Configuration
{
/*	protected:
		bool debugLevelChanged;*/

	public:
		IPPacketIgnoreType ignoreSeenIPPackets;
		bool sortDestinationsAccordingTime;
		DestinationManager dm;
		std::vector<std::string> inputFiles;

		std::string flowTemplateFile;
		bool ignore_unexpected_dns; // in call verification

		LogLevel logLevel;

		/** handle DNS messages */
		bool dns;

		/** handle SIP messages */
		bool sip;
		
		/** handle (print) SCTP flows */
		bool sctp_flow;

		bool cfPrint;
		std::string cfPrintFile;

		std::string txtPrintFile;
		bool txtPrint;

		bool printStream; /* print packets into file during processing them, don't store them in memory */
		std::string printStreamFile;

		bool ignoreSERDnsWatchdog;
		bool ignorePTR;
		bool ignoreOPTIONS;

		Configuration();
		bool readArgs(int argc, char **argv);
		bool handleProtocolAlias(const char *proto, unsigned int proto_len,
				const char *addr, unsigned int addr_len, 
				const char *name);
		bool handleAlias(const char *alias_arg);

		void printHelp();
};

#endif
