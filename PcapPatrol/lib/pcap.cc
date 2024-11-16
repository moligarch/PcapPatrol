#include "pch.h"
#include "PcapPatrol/pcap.h"

#include <pcapplusplus/PcapFileDevice.h>


namespace PCP
{
	Analyzer::Analyzer(const std::filesystem::path& pcap_file) :
		reader_(pcpp::IFileReaderDevice::getReader(pcap_file.string()))
	{
	}

}
