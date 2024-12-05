#include "StaticRouter.h"

#include <spdlog/spdlog.h>

#include <cstring>
#include <iostream>

#include "ArpCache.h"
#include "IArpCache.h"
#include "IPacketSender.h"
#include "RoutingTable.h"
#include "protocol.h"
#include "utils.h"

#define ICMP_TYPE_ECHO_REQUEST 8
#define ICMP_TYPE_ECHO_REPLY 0
#define ICMP_TYPE_DEST_UNREACHABLE 3  // ICMP Type 3:  Destination Unreachable
#define ICMP_CODE_PORT_UNREACHABLE 3  // ICMP Code 3:  Port Unreachable (for Type 3)
#define ICMP_CODE_NET_UNREACHABLE 0   // ICMP Code 0:  Destination Unreachable (for Type 3)
#define ICMP_TYPE_TIME_EXCEEDED 11    // ICMP Type 11: ICMP Time Exceeded
#define ICMP_CODE_TTL_EXPIRED 0       // ICMP Code 0:  TTL expired
#define IP_PROTOCOL_ICMP 1            // ICMP Protocol number
#define IP_PROTOCOL_UDP 0x11          // UDP Protocol number (17 in decimal)
#define IP_PROTOCOL_TCP 0x06          // TCP Protocol number (6 in decimal)
#define ETHERTYPE_ARP 0x0806          // ARP (Address Resolution Protocol) EtherType
#define ETHERTYPE_IPv4 0x0800         // IPv4 EtherType
#define ARP_REQUEST 1
#define ARP_REPLY 2

StaticRouter::StaticRouter(std::unique_ptr<IArpCache> arpCache, std::shared_ptr<IRoutingTable> routingTable,
                           std::shared_ptr<IPacketSender> packetSender)
    : routingTable(routingTable), packetSender(packetSender), arpCache(std::move(arpCache)) {
}

void StaticRouter::handlePacket(std::vector<uint8_t> packet, std::string iface) {
    std::unique_lock lock(mutex);

    if (packet.size() < sizeof(sr_ethernet_hdr_t)) {
        spdlog::error("Packet is too small to contain an Ethernet header.");
        return;
    }

    // TODO: Your code below

    // Extract the Ethernet header from the packet
    const sr_ethernet_hdr_t* ethHeader = reinterpret_cast<const sr_ethernet_hdr_t*>(packet.data());

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

void StaticRouter::handleARP(const std::vector<uint8_t>& packet, const std::string& iface) {
    spdlog::info("Handling ARP packet on interface {}.", iface);
    // TODO: Add ARP handling logic

    // Parse ARP packet
    // sr_arp_hdr_t* arpHeader = reinterpret_cast<sr_arp_hdr_t*>(packet.data() + sizeof(sr_ethernet_hdr_t));

    const sr_arp_hdr_t* arpHeader = reinterpret_cast<const sr_arp_hdr_t*>(packet.data() + sizeof(sr_ethernet_hdr_t));

    // Check if the ARP packet is meant for this router
    if (!isARPPacketForRouter(arpHeader)) {
        spdlog::info("Received ARP packet not intended for this router (Target IP: {}). Ignoring.", arpHeader->ar_tip);
        return;
    }

    // ARP request or response
    // Extract relevant information from the ARP request
    uint32_t senderIP = ntohl(arpHeader->ar_sip);  // Sender IP in the ARP reply
    mac_addr senderMAC;
    std::copy(arpHeader->ar_sha, arpHeader->ar_sha + ETHER_ADDR_LEN, senderMAC.begin());  // Sender MAC in the ARP reply

    // Check if ARP request or response
    if (ntohs(arpHeader->ar_op) == ARP_REQUEST) {
        // This request is for one of the router's IP addresses
        auto* concreteArpCache = dynamic_cast<ArpCache*>(arpCache.get());
        if (concreteArpCache) {
            concreteArpCache->sendArpResponse(senderIP, senderMAC, iface);
        }
        else {
            spdlog::error("Failed to cast arpCache to ArpCache.");
        }
    }
    else if (ntohs(arpHeader->ar_op) == ARP_REPLY) {
        // Check if it's in the requests map
        auto* concreteArpCache = dynamic_cast<ArpCache*>(arpCache.get());
        if (concreteArpCache && concreteArpCache->requestExists(senderIP)) {
            // If there was a pending ARP request, process the ARP reply
            std::ostringstream macStream;
            for (size_t i = 0; i < senderMAC.size(); ++i) {
                if (i > 0) macStream << ":";
                macStream << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(senderMAC[i]);
            }
            spdlog::info("Received valid ARP reply for IP {} from MAC {}.", senderIP, macStream.str());

            arpCache->addEntry(senderIP, senderMAC);
        }
        else {
            // If there was no pending ARP request, drop the ARP reply
            std::ostringstream macStream;
            for (size_t i = 0; i < senderMAC.size(); ++i) {
                if (i > 0) macStream << ":";
                macStream << std::hex << static_cast<int>(senderMAC[i]);
            }
            spdlog::info("Received valid ARP reply for IP {} from MAC {}.", senderIP, macStream.str());
        }
    }
    else {
        // Neither ARP Request or Response???
        spdlog::error("Invalid ARP operation, ignoring.");
        return;
    }
}

void StaticRouter::handleIP(const std::vector<uint8_t>& packet, const std::string& iface) {
    spdlog::info("Handling IP packet on interface {}.", iface);

    // Check if the packet is too small to contain an IP header
    // TODO: Not sure if we need this!!!
    if (packet.size() < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t)) {
        spdlog::error("Packet is too small to contain an IP header.");
        return;
    }

    // Extract the IP header
    const auto* ipHeader = reinterpret_cast<const sr_ip_hdr_t*>(packet.data() + sizeof(sr_ethernet_hdr_t));

    if (!isValidIPChecksum(ipHeader)) {
        spdlog::error("Invalid IP checksum. Discarding packet.");
        return;
    }

    spdlog::info("Packet has a valid IP checksum. Processing further...");

    // Step 1: Check if the destination IP is one of the router's interfaces
    // Step 2: If this is the final destination, process the packet
    // Step 3: If not the final destination, lookup in the routing table
    // Step 4: If no matching routing entry, drop the packet (no route to the destination)
    // Step 5: If we have a route, we need to forward the packet
    // Step 6: ARP Resolution - if the next hop's MAC address is not in the ARP table, send an ARP request
    // Step 7: Forward the packet to the correct link (send the Ethernet frame)

    // Extract the destination IP address
    uint32_t destIP = ipHeader->ip_dst;

    // Check if this router is the final destination
    if (isFinalDestination(ipHeader)) {
        // Verify the protocol is ICMP
        if (ipHeader->ip_p != IP_PROTOCOL_ICMP) {
            // Check for TCP / UDP
            if (ipHeader->ip_p != IP_PROTOCOL_UDP && ipHeader->ip_p != IP_PROTOCOL_TCP) {
                // Not a UDP or TCP packet, no need to send Port Unreachable
                return;
            }
            else {
                // Send ICMP 3,3
                sendPortUnreachable(const_cast<sr_ip_hdr_t*>(ipHeader), iface);
            }
        }
        else {
            // Extract the ICMP header
            auto *ethernetHeader = const_cast<sr_ethernet_hdr_t*>(reinterpret_cast<const sr_ethernet_hdr_t*>(packet.data()));
            sr_icmp_hdr_t *icmpHeader = const_cast<sr_icmp_hdr_t*>(reinterpret_cast<const sr_icmp_hdr_t*>(packet.data() + sizeof(sr_ethernet_hdr_t) + (ipHeader->ip_hl * 4)));
            if (icmpHeader->icmp_type == ICMP_TYPE_ECHO_REQUEST) {
                // Send echo reply - ICMP type 0 (Echo Reply)
                handleEchoRequest(ethernetHeader, const_cast<sr_ip_hdr_t*>(ipHeader), icmpHeader, iface);
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
        auto* mutableIpHeader = const_cast<sr_ip_hdr_t*>(ipHeader);
        mutableIpHeader->ip_ttl--;

        // Check again if it becomes 0
        if (ipHeader->ip_ttl == 0) {
            // Send ICMP message type 11 code 0
            sendICMPTimeExceeded(ipHeader, iface);
        }

        // TTL is still greater than 0
        // TODO: Might not need these if we don't need to forward it
        mutableIpHeader->ip_sum = 0;                                          // Reset checksum before recalculating
        mutableIpHeader->ip_sum = cksum(mutableIpHeader, sizeof(sr_ip_hdr));  // Recompute the checksum

        // Look up the destination in the routing table
        auto route = routingTable->getRoutingEntry(destIP);

        if (route) {
            // Get the next hop IP and check if it's in the ARP cache
            // If it's cached, forward the packet, if not send an ARP request

            // IP address of the next hop
            uint32_t targetIP = route->gateway;

            // Check if it's in ARP Cache
            auto arpEntry = arpCache->getEntry(targetIP);

            if (arpEntry) {
                // TODO: MAYBE PUT THIS INTO A FORWARD PACKET FUNCTION

                // In cache -> Forward it
                mac_addr nextHopMAC = *arpEntry;

                // Construct the Ethernet frame
                size_t ethernetFrameSize = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + ntohs(ipHeader->ip_len);
                std::vector<uint8_t> ethernetFrame(ethernetFrameSize, 0);

                // Fill the Ethernet header
                sr_ethernet_hdr_t* ethHeader = reinterpret_cast<sr_ethernet_hdr_t*>(ethernetFrame.data());
                auto ifaceInfo = routingTable->getRoutingInterface(route->iface);           // Get the interface info for source MAC
                std::memcpy(ethHeader->ether_shost, ifaceInfo.mac.data(), ETHER_ADDR_LEN);  // Set source MAC address
                std::memcpy(ethHeader->ether_dhost, nextHopMAC.data(), ETHER_ADDR_LEN);     // Set destination MAC address
                ethHeader->ether_type = htons(ethertype_ip);                                // Indicating IP payload

                // Copy the IP header and payload into the Ethernet frame
                std::memcpy(ethernetFrame.data() + sizeof(sr_ethernet_hdr_t), ipHeader, sizeof(sr_ip_hdr_t) + ntohs(ipHeader->ip_len));

                // 5. Send the packet through the correct interface
                packetSender->sendPacket(ethernetFrame, route->iface);
            }
            else {
                // Not in cache -> Queue the packet request
                spdlog::info("MAC address not found in ARP cache. Queueing packet and sending ARP request.");
                arpCache->queuePacket(targetIP, packet, route->iface);
            }
        }
        else {
            // Send ICMP message type 3 code 0
            spdlog::error("No routing entry found for destination IP {}. Dropping packet.", destIP);
            sendICMPDestinationUnreachable(ipHeader, iface);
            return;
        }
    }
}

// Checks if the given checksum is valid for the ip packet
bool StaticRouter::isValidIPChecksum(const sr_ip_hdr_t* ipHeader) {
    // Save the original checksum
    uint16_t originalChecksum = ipHeader->ip_sum;

    // Temporarily set the checksum field to 0
    sr_ip_hdr_t tempHeader = *ipHeader;
    tempHeader.ip_sum = 0;

    // Use the cksum function to compute the checksum
    uint16_t computedChecksum = cksum(&tempHeader, sizeof(sr_ip_hdr_t));

    // Return whether the computed checksum matches the original
    return computedChecksum == originalChecksum;
}

bool StaticRouter::isFinalDestination(const sr_ip_hdr_t* ipHeader) {
    // Store the interfaces into the variable
    const auto interfaces = routingTable->getRoutingInterfaces();

    // Check if the destination IP matches any of the router's interfaces
    for (const auto& ifaceEntry : interfaces) {
        if (ipHeader->ip_dst == ifaceEntry.second.ip) {
            return true;  // Found the destination IP match, this is the final destination
        }
    }

    return false;  // No match, the packet is not meant for this router
}

bool StaticRouter::isARPPacketForRouter(const sr_arp_hdr_t* arpHeader) {
    // Retrieve the list of interfaces from the routing table
    const auto interfaces = routingTable->getRoutingInterfaces();

    // Check if the ARP target IP matches any of the router's interfaces
    for (const auto& ifaceEntry : interfaces) {
        if (arpHeader->ar_tip == ifaceEntry.second.ip) {
            return true;  // The ARP packet is intended for this router
        }
    }

    return false;  // No match found; the ARP packet is not for this router
}

/*
    Potentially combine all these send ICMP MSG Functions into one function for better organization!!!
*/

// Function for sending an ICMP echo response
// TODO: DOUBLE CHECK THIS
void StaticRouter::handleEchoRequest(sr_ethernet_hdr_t *ethernetHeader, sr_ip_hdr_t *ipHeader, sr_icmp_hdr_t *icmpHeader, const std::string& iface) {
    // Log an Echo Request
    spdlog::info("Handling ICMP Echo Request.");

    uint8_t replyPacket[1500]; // Maximum size for an Ethernet frame
    memset(replyPacket, 0, sizeof(replyPacket));

    // Retrieve the source IP address and MAC address for the interface
    RoutingInterface ifaceInfo = routingTable->getRoutingInterface(iface);
    ip_addr srcIP = ifaceInfo.ip;
    mac_addr srcMAC = ifaceInfo.mac;

    // Ethernet header for the reply
    sr_ethernet_hdr_t *replyEthernetHeader = (sr_ethernet_hdr_t *)replyPacket;
    memcpy(replyEthernetHeader->ether_shost, srcMAC.data(), ETHER_ADDR_LEN); // Set source MAC address (라우터 인터페이스의 MAC 주소)
    memcpy(replyEthernetHeader->ether_dhost, ethernetHeader->ether_shost, ETHER_ADDR_LEN); // Set destination MAC address (요청 보낸 호스트의 MAC 주소)
    replyEthernetHeader->ether_type = htons(ethertype_ip); // Set EtherType to IP (0x0800)

    // IP header for the reply
    sr_ip_hdr_t *replyIPHeader = (sr_ip_hdr_t *)(replyPacket + sizeof(sr_ethernet_hdr_t));
    memcpy(replyIPHeader, ipHeader, sizeof(sr_ip_hdr_t)); // Copy original IP header

    // Update the IP header fields
    replyIPHeader->ip_src = ipHeader->ip_dst;                    // Set source IP to the router's interface IP
    replyIPHeader->ip_dst = ipHeader->ip_src;         // Set destination IP to the original source IP
    replyIPHeader->ip_ttl -= 1;                       // Decrement TTL by 1
    replyIPHeader->ip_sum = 0;                        // Clear checksum for recomputation
    replyIPHeader->ip_sum = cksum(replyIPHeader, sizeof(sr_ip_hdr_t)); // Recompute checksum

    // ICMP header for the reply
    sr_icmp_hdr_t *replyICMPHeader = (sr_icmp_hdr_t *)((uint8_t *)replyIPHeader + (replyIPHeader->ip_hl * 4));
    memcpy(replyICMPHeader, icmpHeader, sizeof(sr_icmp_hdr_t)); // Copy original ICMP header

    // Update ICMP header fields
    replyICMPHeader->icmp_type = ICMP_TYPE_ECHO_REPLY; // Change type to Echo Reply (0)
    replyICMPHeader->icmp_code = 0;                    // Code is always 0 for Echo Reply
    replyICMPHeader->icmp_sum = 0;                     // Clear checksum for recomputation

    // Copy the ICMP data from the original request to the reply
    uint8_t *icmpData = (uint8_t *)(icmpHeader + 1);       // Pointer to data in the original request
    uint8_t *replyData = (uint8_t *)(replyICMPHeader + 1); // Pointer to data in the reply packet
    int icmpDataLength = ntohs(ipHeader->ip_len) - (ipHeader->ip_hl * 4) - sizeof(sr_icmp_hdr_t);

    if (icmpDataLength > 0) {
        memcpy(replyData, icmpData, icmpDataLength); // Copy the data payload from the original request
    }

    // Compute the new ICMP checksum
    int icmpLength = sizeof(sr_icmp_hdr_t) + icmpDataLength; // Calculate total ICMP length including data
    replyICMPHeader->icmp_sum = cksum(replyICMPHeader, icmpLength); // Recompute ICMP checksum

    // Send the reply packet
    int replyLength = sizeof(sr_ethernet_hdr_t) + ntohs(ipHeader->ip_len); // Total length includes Ethernet, IP, and ICMP
    std::vector<uint8_t> packetVector(replyPacket, replyPacket + replyLength);
    packetSender->sendPacket(packetVector, iface);
}

void StaticRouter::sendPortUnreachable(sr_ip_hdr_t* ipHeader, const std::string& iface) {
    spdlog::info("Sending ICMP Port Unreachable message on interface {}.", iface);

    size_t packetLen = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
    std::vector<uint8_t> packet(packetLen, 0);

    // Fill Ethernet header
    auto* ethHeader = reinterpret_cast<sr_ethernet_hdr_t*>(packet.data());
    auto ifaceInfo = routingTable->getRoutingInterface(iface);
    std::memcpy(ethHeader->ether_shost, ifaceInfo.mac.data(), ETHER_ADDR_LEN);
    std::fill(ethHeader->ether_dhost, ethHeader->ether_dhost + ETHER_ADDR_LEN, 0xFF);  // Set to broadcast
    ethHeader->ether_type = htons(ethertype_ip);

    // Fill IP header
    auto* replyIPHeader = reinterpret_cast<sr_ip_hdr_t*>(packet.data() + sizeof(sr_ethernet_hdr_t));
    replyIPHeader->ip_v = 4;
    replyIPHeader->ip_hl = sizeof(sr_ip_hdr_t) / 4;
    replyIPHeader->ip_tos = 0;
    replyIPHeader->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
    replyIPHeader->ip_id = htons(0);
    replyIPHeader->ip_off = htons(IP_DF);
    replyIPHeader->ip_ttl = 64;
    replyIPHeader->ip_p = ip_protocol_icmp;
    replyIPHeader->ip_src = ifaceInfo.ip;
    replyIPHeader->ip_dst = ipHeader->ip_src;
    replyIPHeader->ip_sum = 0;
    replyIPHeader->ip_sum = cksum(replyIPHeader, sizeof(sr_ip_hdr_t));

    // Fill ICMP header
    auto* replyICMPHeader = reinterpret_cast<sr_icmp_t3_hdr_t*>(packet.data() + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    replyICMPHeader->icmp_type = ICMP_TYPE_DEST_UNREACHABLE;
    replyICMPHeader->icmp_code = ICMP_CODE_PORT_UNREACHABLE;
    replyICMPHeader->icmp_sum = 0;
    std::memcpy(replyICMPHeader->data, ipHeader, ICMP_DATA_SIZE);  // Original IP header and payload
    replyICMPHeader->icmp_sum = cksum(replyICMPHeader, sizeof(sr_icmp_t3_hdr_t));

    // Send the packet
    packetSender->sendPacket(packet, iface);
    spdlog::info("ICMP Port Unreachable message sent.");
}

void StaticRouter::sendICMPDestinationUnreachable(const sr_ip_hdr_t* ipHeader, const std::string& iface) {
    spdlog::info("Sending ICMP Destination Net Unreachable (Type: {}, Code: {}) on interface {}.", ICMP_TYPE_DEST_UNREACHABLE, ICMP_CODE_NET_UNREACHABLE, iface);

    // Allocate space for Ethernet, IP, and ICMP headers
    size_t packetLen = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
    std::vector<uint8_t> packet(packetLen);

    // Fill Ethernet header
    auto* ethHeader = reinterpret_cast<sr_ethernet_hdr_t*>(packet.data());
    auto ifaceInfo = routingTable->getRoutingInterface(iface);
    std::memcpy(ethHeader->ether_shost, ifaceInfo.mac.data(), ETHER_ADDR_LEN);
    std::fill(ethHeader->ether_dhost, ethHeader->ether_dhost + ETHER_ADDR_LEN, 0xFF);  // Broadcast for now
    ethHeader->ether_type = htons(ethertype_ip);

    // Fill IP header
    auto* ipOutHeader = reinterpret_cast<sr_ip_hdr_t*>(packet.data() + sizeof(sr_ethernet_hdr_t));
    ipOutHeader->ip_v = 4;  // IPv4
    ipOutHeader->ip_hl = sizeof(sr_ip_hdr_t) / 4;
    ipOutHeader->ip_tos = 0;
    ipOutHeader->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
    ipOutHeader->ip_id = htons(0);       // No fragmentation
    ipOutHeader->ip_off = htons(IP_DF);  // Don't fragment
    ipOutHeader->ip_ttl = 64;
    ipOutHeader->ip_p = ip_protocol_icmp;
    ipOutHeader->ip_src = ifaceInfo.ip;      // Use the interface's IP address
    ipOutHeader->ip_dst = ipHeader->ip_src;  // Send back to sender
    ipOutHeader->ip_sum = 0;                 // Zero out for checksum calculation
    ipOutHeader->ip_sum = cksum(ipOutHeader, sizeof(sr_ip_hdr_t));

    // Fill ICMP header
    auto* icmpHeader = reinterpret_cast<sr_icmp_t3_hdr_t*>(packet.data() + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    icmpHeader->icmp_type = ICMP_TYPE_DEST_UNREACHABLE;
    icmpHeader->icmp_code = ICMP_CODE_NET_UNREACHABLE;
    icmpHeader->icmp_sum = 0;                                 // Zero out for checksum calculation
    std::memcpy(icmpHeader->data, ipHeader, ICMP_DATA_SIZE);  // Copy original IP header and first 8 bytes of payload
    icmpHeader->icmp_sum = cksum(icmpHeader, sizeof(sr_icmp_t3_hdr_t));

    // Send the packet using the packet sender
    packetSender->sendPacket(packet, iface);
    spdlog::info("ICMP Destination Net Unreachable message sent.");
}

void StaticRouter::sendICMPTimeExceeded(const sr_ip_hdr_t* ipHeader, const std::string& iface) {
    spdlog::info("Sending ICMP Time Exceeded (Type: {}, Code: {}) on interface {}.", ICMP_TYPE_TIME_EXCEEDED, ICMP_CODE_TTL_EXPIRED, iface);

    // Allocate space for Ethernet, IP, and ICMP headers
    size_t packetLen = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
    std::vector<uint8_t> responsePacket(packetLen);

    // Fill Ethernet header
    auto* ethHeader = reinterpret_cast<sr_ethernet_hdr_t*>(responsePacket.data());
    auto ifaceInfo = routingTable->getRoutingInterface(iface);
    std::memcpy(ethHeader->ether_shost, ifaceInfo.mac.data(), ETHER_ADDR_LEN);
    std::fill(ethHeader->ether_dhost, ethHeader->ether_dhost + ETHER_ADDR_LEN, 0xFF);  // Broadcast for now
    ethHeader->ether_type = htons(ethertype_ip);

    // Fill IP header
    auto* ipOutHeader = reinterpret_cast<sr_ip_hdr_t*>(responsePacket.data() + sizeof(sr_ethernet_hdr_t));
    ipOutHeader->ip_v = 4;  // IPv4
    ipOutHeader->ip_hl = sizeof(sr_ip_hdr_t) / 4;
    ipOutHeader->ip_tos = 0;
    ipOutHeader->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
    ipOutHeader->ip_id = htons(0);       // No fragmentation
    ipOutHeader->ip_off = htons(IP_DF);  // Don't fragment
    ipOutHeader->ip_ttl = 64;            // TTL for the reply packet
    ipOutHeader->ip_p = ip_protocol_icmp;
    ipOutHeader->ip_src = ifaceInfo.ip;      // Use the interface's IP address
    ipOutHeader->ip_dst = ipHeader->ip_src;  // Send back to sender
    ipOutHeader->ip_sum = 0;                 // Zero out for checksum calculation
    ipOutHeader->ip_sum = cksum(ipOutHeader, sizeof(sr_ip_hdr_t));

    // Fill ICMP header
    auto* icmpHeader = reinterpret_cast<sr_icmp_t3_hdr_t*>(responsePacket.data() + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    icmpHeader->icmp_type = ICMP_TYPE_TIME_EXCEEDED;          // Type 11, Time Exceeded
    icmpHeader->icmp_code = ICMP_CODE_TTL_EXPIRED;            // Code 0, TTL expired
    icmpHeader->icmp_sum = 0;                                 // Zero out for checksum calculation
    std::memcpy(icmpHeader->data, ipHeader, ICMP_DATA_SIZE);  // Copy original IP header and first 8 bytes of payload
    icmpHeader->icmp_sum = cksum(icmpHeader, sizeof(sr_icmp_t3_hdr_t));

    // Send the packet using the packet sender
    packetSender->sendPacket(responsePacket, iface);
    spdlog::info("ICMP Time Exceeded message sent.");
}

void forwardPacket(uint8_t* packet, int packetLength) {
    // Might need to move the forward packet code into here for organization
}
