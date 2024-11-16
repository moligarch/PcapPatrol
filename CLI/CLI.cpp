#include <iostream>
#include <pcapplusplus/PcapFileDevice.h>
#include <pcapplusplus/Packet.h>
#include <pcapplusplus/EthLayer.h>
#include <pcapplusplus/IPv4Layer.h>
#include <pcapplusplus/TcpLayer.h>
#include <pcapplusplus/HttpLayer.h>
#include <unordered_map>
#include <vector>

int main(int argc, char* argv[])
{
    // open a pcap file for reading
    std::string pcapPath;
    std::cout << "Enter pcap file path: ";
    std::getline(std::cin, pcapPath);
    pcpp::PcapFileReaderDevice reader(pcapPath);
    if (!reader.open())
    {
        std::cerr << "Error opening the pcap file" << std::endl;
        return 1;
    }

    // create maps to store IP addresses and their repetition counts
    //std::unordered_map<std::string, int> ipv4SrcCounts;
    //std::unordered_map<std::string, int> ipv4DstCounts;

    //std::unordered_map<std::string, int> ipv6SrcCounts;
    //std::unordered_map<std::string, int> ipv6DstCounts;
    //std::unordered_map<std::string, int> ethSrcCounts;
    //std::unordered_map<std::string, int> ethDstCounts;

    int nPacket{ 0 };
    // read packets from the pcap file
    pcpp::RawPacket rawPacket;
    do {
        if (!reader.getNextPacket(rawPacket))
        {
            std::cerr << "Reading pcap file finished." << std::endl;
            break;
        }
        nPacket++;

        // parse the raw packet into a parsed packet
        pcpp::Packet parsedPacket(&rawPacket);

        pcpp::EthLayer* l1 = parsedPacket.getLayerOfType<pcpp::EthLayer>();
        auto l2 = dynamic_cast<pcpp::IPv4Layer * >(l1->getNextLayer());
        auto l3 = dynamic_cast<pcpp::TcpLayer*>(l2->getNextLayer());
        //auto l4_req = dynamic_cast<pcpp::HttpRequestLayer*>(l3->getNextLayer());
        //auto l4_res = dynamic_cast<pcpp::HttpResponseLayer*>(l3->getNextLayer());

        std::string srcMac = l1->getSourceMac().toString();
        std::string destMac = l1->getDestMac().toString();

        std::string srcIPv4 = l2->getSrcIPv4Address().toString();
        std::string destIPv4 = l2->getDstIPv4Address().toString();
        
    } while (true);

    // close the pcap file
    reader.close();

    // Output the counts of IP addresses
    //if (!ipv4SrcCounts.empty() && !ipv4DstCounts.empty())
    //{
    //    std::cout << "IPv4 Source Address Counts:" << std::endl;
    //    for (const auto& entry : ipv4SrcCounts) {
    //        std::cout << entry.first << " : " << entry.second << std::endl;
    //    }

    //    std::cout << "IPv4 Destination Address Counts:" << std::endl;
    //    for (const auto& entry : ipv4DstCounts) {
    //        std::cout << entry.first << " : " << entry.second << std::endl;
    //    }
    //}

    /*if (!ipv6SrcCounts.empty() && !ipv6DstCounts.empty())
    {
        std::cout << "IPv6 Source Address Counts:" << std::endl;
        for (const auto& entry : ipv6SrcCounts) {
            std::cout << entry.first << " : " << entry.second << std::endl;
        }

        std::cout << "IPv6 Destination Address Counts:" << std::endl;
        for (const auto& entry : ipv6DstCounts) {
            std::cout << entry.first << " : " << entry.second << std::endl;
        }
    }

    if (!ethSrcCounts.empty() && !ipv4DstCounts.empty())
    {
        std::cout << "Eth Source Address Counts:" << std::endl;
        for (const auto& entry : ethSrcCounts) {
            std::cout << entry.first << " : " << entry.second << std::endl;
        }

        std::cout << "Eth Destination Address Counts:" << std::endl;
        for (const auto& entry : ethDstCounts) {
            std::cout << entry.first << " : " << entry.second << std::endl;
        }
    }*/

    std::cout << "Total Number of Packet: " << nPacket << std::endl;

    return 0;
}