#ifndef PCAP_PATROL_PCAP_H_
#define PCAP_PATROL_PCAP_H_
#include <filesystem>
#include <memory>
#include <pcapplusplus/PcapFileDevice.h>



namespace PCP
{
	class Analyzer
	{
	public:
		Analyzer(const std::filesystem::path& pcap_file);
		~Analyzer();

	private:
		std::unique_ptr<pcpp::IFileReaderDevice> reader_;
	};
}



#endif //PCAP_PATROL_PCAP_H_