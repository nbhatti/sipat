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
