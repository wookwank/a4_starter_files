#include "RoutingTable.h"
#include "StaticRouter.h"

#include <spdlog/spdlog.h>
#include <cstring>
#include <iostream>

#include "protocol.h"
#include "utils.h"

#define ICMP_TYPE_ECHO_REQUEST 8
#define ICMP_TYPE_ECHO_REPLY 0
#define ICMP_TYPE_DEST_UNREACHABLE 3  // ICMP Type 3: Destination Unreachable
#define ICMP_CODE_PORT_UNREACHABLE 3  // ICMP Code 3: Port Unreachable (for Type 3)
#define IP_PROTOCOL_ICMP 1
#define IP_PROTOCOL_UDP 0x11  // UDP Protocol number (17 in decimal)
#define IP_PROTOCOL_TCP 0x06  // TCP Protocol number (6 in decimal)
#define ETHERTYPE_ARP 0x0806  // ARP (Address Resolution Protocol) EtherType
#define ETHERTYPE_IPv4 0x0800  // IPv4 EtherType

StaticRouter::StaticRouter(std::unique_ptr<IArpCache> arpCache, std::shared_ptr<IRoutingTable> routingTable,
                           std::shared_ptr<IPacketSender> packetSender)
    : routingTable(routingTable)
      , packetSender(packetSender)
      , arpCache(std::move(arpCache))
{
}


void StaticRouter::handlePacket(std::vector<uint8_t> packet, std::string iface)
{
    std::unique_lock lock(mutex);

    if (packet.size() < sizeof(sr_ethernet_hdr_t))
    {
        spdlog::error("Packet is too small to contain an Ethernet header.");
        return;
    }


    // TODO: Your code below


    // Extract the Ethernet header from the packet
    const sr_ethernet_hdr_t *ethHeader = reinterpret_cast<const sr_ethernet_hdr_t *>(packet.data());

    // Check the EtherType field
    uint16_t etherType = ntohs(ethHeader->ether_type);

    // ARP
    if (etherType == ETHERTYPE_ARP) {
        spdlog::info("EtherType indicates ARP. Processing ARP packet...");
        handleARP(packet, iface);
    }
    // IPv4
    else if (etherType == ETHERTYPE_IPv4) {
        spdlog::info("EtherType indicates IPv4. Processing IP packet...");
        handleIP(packet, iface);
    }
    else {
        spdlog::warn("Unsupported EtherType: 0x{:04x}. Discarding packet.", etherType);
        return;
    }

}

void handleARP(const std::vector<uint8_t>& packet, const std::string& iface) {
    spdlog::info("Handling ARP packet on interface {}.", iface);
    // TODO: Add ARP handling logic
}

void handleIP(const std::vector<uint8_t>& packet, const std::string& iface) {
    spdlog::info("Handling IP packet on interface {}.", iface);
    
    // Check if the packet is too small to contain an IP header
    // TODO: Not sure if we need this!!!
    if (packet.size() < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)) {
        spdlog::error("Packet is too small to contain an IP header.");
        return;
    }

    // Extract the IP header
    auto *ipHeader = reinterpret_cast<sr_ip_hdr_t *>(packet.data() + sizeof(sr_ethernet_hdr_t));

    if (!isValidIPChecksum(ipHeader)) {
        spdlog::error("Invalid IP checksum. Discarding packet.");
        return;
    }

    spdlog::info("Packet has a valid IP checksum. Processing further...");




    // TODO: All the steps
    // Step 3: Check if the destination IP is one of the router's interfaces
    // Loop through all the router's interfaces - NOT SURE HOW TO DO THIS
    // Step 4: If this is the final destination, process the packet
    // Step 5: If not the final destination, lookup in the routing table
    // Step 6: If no matching routing entry, drop the packet (no route to the destination)
    // Step 7: If we have a route, we need to forward the packet
    // Step 8: ARP Resolution - if the next hop's MAC address is not in the ARP table, send an ARP request
    // Step 9: Forward the packet to the correct link (send the Ethernet frame)




    // Check if this router is the final destination
    if (isFinalDestination(packet)) {
        // Verify the protocol is ICMP
        if (ipHeader->ip_p != IP_PROTOCOL_ICMP) {
            // Check for TCP / UDP
            if (ipHeader->ip_p != IP_PROTOCOL_UDP && ipHeader->ip_p != IP_PROTOCOL_TCP) {
                // Not a UDP or TCP packet, no need to send Port Unreachable
                return;
            }
            else {
                // Send ICMP 3,3
                sendPortUnreachable(ipHeader, iface);
            }
        }
        else {
            // Extract the ICMP header
            auto *icmpHeader = reinterpret_cast<sr_icmp_hdr_t *>(packet.data() + sizeof(sr_ethernet_hdr_t) + (ipHeader->ip_hl * 4));

            if (icmpHeader->icmp_type == ICMP_TYPE_ECHO_REQUEST) {
                // Send echo reply - ICMP 0
                handleEchoRequest(ipHeader, icmpHeader, iface);
                return;
            }
            else {
                spdlog::info("Not an Echo Request, ignoring.");
                return;
            }
        }
    }
    else {
        // Handle TTL
        // If TTL == 0 drop
        // If TTL == 1 send ICMP type 11 code 0
        // If TTL > 1 keep progressing

        if (ipHeader->ip_ttl == 0) {
            spdlog::error("Packet has TTL = 0. Dropping packet.");
            return;
        }

        // Decrement TTL by 1;
        ipHeader->ip_ttl--;

        // Check again if it becomes 0
        if (ipHeader->ip_ttl == 0) {
            // TODO: Send ICMP message type 11 code 0
        }

        // TTL is still greater than 0
        // TODO: Might not need these if we don't need to forward it
        ipHeader->ip_sum = 0;  // Reset checksum before recalculating
        ipHeader->ip_sum = cksum(ipHeader, sizeof(sr_ip_hdr));  // Recompute the checksum

        if (routingTable->getRoutingEntry(iface)) {
            // TODO: Get the next hop IP and check if it's in the ARP cache
            // If it's cached, forward the packet, if not send an ARP request
        }
        else {
            // TODO: Send ICMP message type 3 code 0
        }
        
        
    }

}


// Checks if the given checksum is valid for the ip packet
bool StaticRouter::isValidIPChecksum(const sr_ip_hdr_t *ipHeader) {
    // Save the original checksum
    uint16_t originalChecksum = ntohs(ipHeader->ip_sum);

    // Temporarily set the checksum field to 0
    sr_ip_hdr_t tempHeader = *ipHeader;
    tempHeader.ip_sum = 0;

    // Use the cksum function to compute the checksum
    uint16_t computedChecksum = cksum(&tempHeader, sizeof(sr_ip_hdr_t));

    // Return whether the computed checksum matches the original
    return computedChecksum == originalChecksum;
}

bool StaticRouter::isFinalDestination(const sr_ip_hdr_t *ipHeader) {
    // Store the interfaces into the variable
    const auto interfaces = getRoutingInterfaces();

    // Check if the destination IP matches any of the router's interfaces
    for (const auto& ifaceEntry : interfaces) {
        if (ip_Header->ip_dst == ifaceEntry.second.ip) {
            return true;  // Found the destination IP match, this is the final destination
        }
    }
    
    return false;  // No match, the packet is not meant for this router
}

// Function for sending an ICMP echo response
// TODO: DOUBLE CHECK THIS
void handleEchoRequest(sr_ip_hdr_t *ipHeader, sr_icmp_hdr_t *icmpHeader, const std::string& iface) {
    // Log an Echo Request
    spdlog::info("Handling ICMP Echo Request.");

    uint8_t replyPacket[1500]; // Maximum size for an Ethernet frame
    memset(replyPacket, 0, sizeof(replyPacket));

    // Retrieve the source IP address for the interface
    RoutingInterface ifaceInfo = routingTable.getRoutingInterface(iface);
    ip_addr srcIP = ifaceInfo.ip;

    // Create the IP header for the reply
    sr_ip_hdr_t *replyIPHeader = (sr_ip_hdr_t *)replyPacket;
    memcpy(replyIPHeader, ipHeader, sizeof(sr_ip_hdr_t)); // Copy original IP header
    replyIPHeader->ip_src = srcIP;                         // Set source IP to the interface IP
    replyIPHeader->ip_dst = ipHeader->ip_src;              // Swap source and destination
    replyIPHeader->ip_sum = 0;                             // Clear checksum for recomputation
    replyIPHeader->ip_sum = cksum(replyIPHeader, sizeof(sr_ip_hdr_t)); // Recompute checksum

    // Create the ICMP header for the reply
    sr_icmp_hdr_t *replyICMPHeader = (sr_icmp_hdr_t *)(replyPacket + (replyIPHeader->ip_hl * 4));
    memcpy(replyICMPHeader, icmpHeader, sizeof(sr_icmp_hdr_t)); // Copy original ICMP header
    replyICMPHeader->icmp_type = ICMP_TYPE_ECHO_REPLY;          // Change type to Echo Reply
    replyICMPHeader->icmp_sum = 0;                              // Clear checksum for recomputation

    // Compute the new ICMP checksum
    int icmpLength = ntohs(ipHeader->ip_len) - (replyIPHeader->ip_hl * 4); // Calculate ICMP length
    replyICMPHeader->icmp_sum = cksum(replyICMPHeader, icmpLength);  // Recompute ICMP checksum

    // Send the reply packet (return false if sending fails)
    int replyLength = ntohs(ipHeader->ip_len); // The reply length is the same as the request
    packetSender->sendPacket(replyPacket, iface);
}


void sendPortUnreachable(sr_ip_hdr_t *ipHeader, const std::string& iface) {
    uint8_t replyPacket[1500]; // Maximum size for an Ethernet frame
    memset(replyPacket, 0, sizeof(replyPacket));

    // Create the IP header for the reply (ICMP response)
    sr_ip_hdr_t *replyIPHeader = (sr_ip_hdr_t *)replyPacket;
    memcpy(replyIPHeader, ipHeader, sizeof(sr_ip_hdr_t)); // Copy the original IP header
    replyIPHeader->ip_src = ipHeader->ip_dst;            // Set source IP to destination IP of the original packet
    replyIPHeader->ip_dst = ipHeader->ip_src;            // Set destination IP to the source IP of the original packet
    replyIPHeader->ip_sum = 0;                           // Clear checksum for recomputation
    replyIPHeader->ip_sum = cksum(replyIPHeader, sizeof(sr_ip_hdr_t)); // Recompute checksum

    // Create the ICMP Port Unreachable message
    sr_icmp_hdr_t *replyICMPHeader = (sr_icmp_hdr_t *)(replyPacket + (replyIPHeader->ip_hl * 4));
    replyICMPHeader->icmp_type = ICMP_TYPE_DEST_UNREACHABLE; // Type 3, Destination Unreachable
    replyICMPHeader->icmp_code = ICMP_CODE_PORT_UNREACHABLE; // Code 3, Port Unreachable
    replyICMPHeader->icmp_sum = 0;                          // Clear checksum for recomputation
    replyICMPHeader->icmp_sum = cksum(replyICMPHeader, sizeof(sr_icmp_hdr_t)); // Recompute ICMP checksum

    // Send the Port Unreachable message
    int replyLength = sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t);
    if (!packetSender->sendPacket(replyPacket, replyLength)) {
        std::cerr << "Failed to send Port Unreachable message." << std::endl;
    }
}


void forwardPacket(uint8_t *packet, int packetLength) {

}



