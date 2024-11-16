#include <iostream>
#include <pcapplusplus/IPv4Layer.h>
#include <pcapplusplus/IPv6Layer.h>
#include <pcapplusplus/EthLayer.h>
#include <pcapplusplus/Packet.h>
#include <pcapplusplus/PcapFileDevice.h>
#include <unordered_map>
#include <vector>

int main(int argc, char* argv[])
{
    // open a pcap file for reading
    std::string pcapPath{ "D:/Work/Projects/Windows/PcapPatrol/Samples/2019-01-28-traffic-analysis-exercise.pcap" };
    pcpp::PcapFileReaderDevice reader(pcapPath);
    if (!reader.open())
    {
        std::cerr << "Error opening the pcap file" << std::endl;
        return 1;
    }

    // create maps to store IP addresses and their repetition counts
    std::unordered_map<std::string, int> ipv4Counts;
    std::unordered_map<std::string, int> ipv6Counts;
    std::unordered_map<std::string, int> ethCounts;
    int nPacket{ 0 };
    // read packets from the pcap file
    pcpp::RawPacket rawPacket;
    do {
        if (!reader.getNextPacket(rawPacket))
        {
            std::cerr << "Couldn't read the next packet in the file" << std::endl;
            break;
        }

        nPacket++;
        // parse the raw packet into a parsed packet
        pcpp::Packet parsedPacket(&rawPacket);

        //std::cout << "Packet info:\n"
        //    << parsedPacket.toString() << std::endl;

        // check if the packet is IPv4
        if (parsedPacket.isPacketOfType(pcpp::IPv4))
        {
            // extract source and destination IPs for IPv4
            pcpp::IPv4Layer* ipv4Layer = parsedPacket.getLayerOfType<pcpp::IPv4Layer>();
            pcpp::IPv4Address srcIP = ipv4Layer->getSrcIPv4Address();
            pcpp::IPv4Address destIP = ipv4Layer->getDstIPv4Address();

            // convert IPv4 addresses to string
            std::string srcIPStr = srcIP.toString();
            std::string destIPStr = destIP.toString();

            // increment the count of the IPv4 addresses
            ipv4Counts[srcIPStr]++;
            ipv4Counts[destIPStr]++;
        }
        // check if the packet is IPv6
        else if (parsedPacket.isPacketOfType(pcpp::IPv6))
        {
            // extract source and destination IPs for IPv6
            pcpp::IPv6Layer* ipv6Layer = parsedPacket.getLayerOfType<pcpp::IPv6Layer>();
            pcpp::IPv6Address srcIP = ipv6Layer->getSrcIPv6Address();
            pcpp::IPv6Address destIP = ipv6Layer->getDstIPv6Address();

            // convert IPv6 addresses to string
            std::string srcIPStr = srcIP.toString();
            std::string destIPStr = destIP.toString();

            // increment the count of the IPv6 addresses
            ipv6Counts[srcIPStr]++;
            ipv6Counts[destIPStr]++;
        }
        else if (parsedPacket.isPacketOfType(pcpp::Ethernet))
        {
            pcpp::EthLayer* ethLayer = parsedPacket.getLayerOfType< pcpp::EthLayer>();
            std::string srcMAC = ethLayer->getSourceMac().toString();
            std::string dstMAC = ethLayer->getDestMac().toString();
            ethCounts[srcMAC]++;
            ethCounts[dstMAC]++;
        }
    } while (true);

    // close the pcap file
    reader.close();

    // Output the counts of IP addresses
    if (!ipv4Counts.empty())
    {
        std::cout << "IPv4 Address Counts:" << std::endl;
        for (const auto& entry : ipv4Counts) {
            std::cout << entry.first << " : " << entry.second << std::endl;
        }
    }

    if (!ipv6Counts.empty())
    {
        std::cout << "IPv6 Address Counts:" << std::endl;
        for (const auto& entry : ipv6Counts) {
            std::cout << entry.first << " : " << entry.second << std::endl;
        }
    }

    if (!ethCounts.empty()) 
    {
        std::cout << "Eth Address Counts:" << std::endl;
        for (const auto& entry : ethCounts) {
            std::cout << entry.first << " : " << entry.second << std::endl;
        }
    }

    std::cout << "Total Number of Packet: " << nPacket << std::endl;
    return 0;
}