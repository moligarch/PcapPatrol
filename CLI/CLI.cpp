#include <iostream>
#include <pcapplusplus/PcapFileDevice.h>
#include <pcapplusplus/Packet.h>
#include <pcapplusplus/EthLayer.h>
#include <pcapplusplus/IPv4Layer.h>
#include <pcapplusplus/TcpLayer.h>
#include <pcapplusplus/DhcpLayer.h>
#include <sstream>
#include <iomanip>


std::string getProtocolTypeAsString(pcpp::ProtocolType protocolType)
{
    switch (protocolType)
    {
    case pcpp::Ethernet:
        return "Ethernet";
    case pcpp::IPv4:
        return "IPv4";
    case pcpp::TCP:
        return "TCP";
    case pcpp::HTTPRequest:
    case pcpp::HTTPResponse:
        return "HTTP";
    default:
        return "Unknown";
    }
}


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
        std::cout << "#" << nPacket << " Packet" << std::endl;
        // parse the raw packet into a parsed packet
        pcpp::Packet parsedPacket(&rawPacket);

        for (auto* curLayer = parsedPacket.getFirstLayer(); curLayer != nullptr; curLayer = curLayer->getNextLayer())
        {
            std::cout
                << "Layer type: " << getProtocolTypeAsString(curLayer->getProtocol()) << "; " // get layer type
                << "Total data: " << curLayer->getDataLen() << " [bytes]; " // get total length of the layer
                << "Layer data: " << curLayer->getHeaderLen() << " [bytes]; " // get the header length of the layer
                << "Layer payload: " << curLayer->getLayerPayloadSize() << " [bytes]" // get the payload length of the layer (equals total length minus header length)
                << std::endl;
        }

        //auto last = parsedPacket.getLastLayer();
        //auto data = last->getData();
        //auto dataLen = last->getDataLen();

        //std::ostringstream hexOss;
        //std::ostringstream oss;
        //for (size_t i = 0; i < dataLen; ++i) {
        //    hexOss << std::setw(2) << std::setfill('0') << std::hex << static_cast<int>(data[i]);
        //    oss << static_cast<unsigned char>(data[i]);
        //}

        //std::cout << hexOss.str() << std::endl;
        //std::cout << oss.str() << std::endl;

        
    } while (true && nPacket <100);

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