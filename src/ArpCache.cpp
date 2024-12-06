#include "ArpCache.h"

#include <spdlog/spdlog.h>

#include <cstring>
#include <iostream>
#include <thread>

#include "protocol.h"
#include "utils.h"

ArpCache::ArpCache(std::chrono::milliseconds timeout, std::shared_ptr<IPacketSender> packetSender, std::shared_ptr<IRoutingTable> routingTable)
    : timeout(timeout), packetSender(std::move(packetSender)), routingTable(std::move(routingTable)) {
    thread = std::make_unique<std::thread>(&ArpCache::loop, this);
}

ArpCache::~ArpCache() {
    shutdown = true;
    if (thread && thread->joinable()) {
        thread->join();
    }
}

void ArpCache::loop() {
    while (!shutdown) {
        tick();
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

// UPDATE: This is a custom function
/**
 * @brief Sends an ARP request to resolve the MAC address for a given destination IP.
 *
 * If an ARP request for the IP exists, it resends the request (up to 7 times).
 * The request is sent using the appropriate network interface and the source
 * IP/MAC address from the routing table. The ARP request is broadcast to
 * resolve the target MAC address.
 *
 * @param dest_ip The destination IP address to resolve.
 */
void ArpCache::sendArpRequest(const uint32_t dest_ip) {
    auto it = requests.find(dest_ip);
    if (it == requests.end()) {
        std::cout << "Error: This should not happen" << std::endl;
        return;
    }
    else {
        ArpRequest& request = it->second;

        if (request.timesSent >= 7) {
            // Drop the request if failed 7 times without a response
            requests.erase(it);

            // TODO: send ICMP dest host unreachable
        }
        else {
            // Resend the ARP request and update the metadata
            auto routingEntryOpt = routingTable->getRoutingEntry(dest_ip);

            if (routingEntryOpt) {
                // If a valid routing entry is found, use its interface to send the ARP request
                const RoutingEntry& routingEntry = routingEntryOpt.value();
                std::string iface = routingEntry.iface;

                RoutingInterface interface = routingTable->getRoutingInterface(iface);
                ip_addr source_ip = ntohl(interface.ip);
                mac_addr source_mac = interface.mac;

                // Ethernet header
                struct sr_ethernet_hdr ether_hdr;
                memset(&ether_hdr, 0, sizeof(ether_hdr));
                memset(ether_hdr.ether_dhost, 0xFF, ETHER_ADDR_LEN);               // Set destination MAC to broadcast address
                memcpy(ether_hdr.ether_shost, source_mac.data(), ETHER_ADDR_LEN);  // Set source MAC address
                ether_hdr.ether_type = htons(ethertype_arp);                       // Set EtherType to ARP (0x0806)

                // ARP header
                struct sr_arp_hdr arp_hdr;
                memset(&arp_hdr, 0, sizeof(arp_hdr));
                arp_hdr.ar_hrd = htons(arp_hrd_ethernet);                   // Set hardware type to Ethernet (1)
                arp_hdr.ar_pro = htons(0x0800);                             // Set protocol type to IPv4 (0x0800)
                arp_hdr.ar_hln = 6;                                         // Set hardware address length (6 for MAC)
                arp_hdr.ar_pln = 4;                                         // Set protocol address length (4 for IPv4)
                arp_hdr.ar_op = htons(arp_op_request);                      // Set ARP operation to request (1)
                memcpy(arp_hdr.ar_sha, source_mac.data(), ETHER_ADDR_LEN);  // Set sender's MAC address (your MAC address)
                arp_hdr.ar_sip = htonl(source_ip);                          // Set sender's IP address (your IP address, convert from string)
                memset(arp_hdr.ar_tha, 0, ETHER_ADDR_LEN);                  // Set target's MAC address to zero (unknown)
                arp_hdr.ar_tip = htonl(dest_ip);                            // Set target IP address (the IP you're looking for)

                // 1. Serialize Ethernet Header
                Packet packet;
                packet.resize(sizeof(ether_hdr));                           // Resize the vector to fit the Ethernet header
                std::memcpy(packet.data(), &ether_hdr, sizeof(ether_hdr));  // Copy Ethernet header into the vector

                // 2. Serialize ARP Header
                packet.resize(packet.size() + sizeof(arp_hdr));                             // Resize the vector to accommodate the ARP header
                std::memcpy(packet.data() + sizeof(ether_hdr), &arp_hdr, sizeof(arp_hdr));  // Copy ARP header after Ethernet header

                // Proceed to resend the ARP request
                packetSender->sendPacket(packet, iface);  // TODO: Need to check this iface

                // Update the request's metadata
                request.lastSent = std::chrono::steady_clock::now();
                request.timesSent++;
            }
            else {
                // If no valid routing entry is found, handle it accordingly
                std::cout << "Error: No valid routing entry for IP " << dest_ip << std::endl;
            }
        }
    }
}

// UPDATE: This is a custom function
/**
 * @brief Sends an ARP response to a given destination IP and MAC address.
 *
 * The function constructs an ARP reply with the source and destination IP/MAC addresses
 * and sends it to the destination using the appropriate network interface. It uses
 * the routing table to determine the source IP/MAC and the correct interface for sending
 * the response.
 *
 * @param dest_ip The destination IP address for the ARP reply.
 * @param dest_mac The destination MAC address to which the ARP reply will be sent.
 */
void ArpCache::sendArpResponse(const uint32_t dest_ip, const mac_addr dest_mac, const std::string& source_iface) {
    // Resend the ARP request and update the metadata
    auto dest_routingEntryOpt = routingTable->getRoutingEntry(dest_ip);

    if (dest_routingEntryOpt) {
        // If a valid routing entry is found, use its interface to send the ARP request
        RoutingInterface interface = routingTable->getRoutingInterface(source_iface);
        ip_addr source_ip = ntohl(interface.ip);
        mac_addr source_mac = interface.mac;

        // Ethernet header
        struct sr_ethernet_hdr ether_hdr;
        memset(&ether_hdr, 0, sizeof(ether_hdr));
        memcpy(ether_hdr.ether_dhost, dest_mac.data(), ETHER_ADDR_LEN);    // Set destination MAC to broadcast address
        memcpy(ether_hdr.ether_shost, source_mac.data(), ETHER_ADDR_LEN);  // Set source MAC address
        ether_hdr.ether_type = htons(ethertype_arp);                       // Set EtherType to ARP (0x0806)

        // ARP header
        struct sr_arp_hdr arp_hdr;
        memset(&arp_hdr, 0, sizeof(arp_hdr));
        arp_hdr.ar_hrd = htons(arp_hrd_ethernet);                   // Set hardware type to Ethernet (1)
        arp_hdr.ar_pro = htons(0x0800);                             // Set protocol type to IPv4 (0x0800)
        arp_hdr.ar_hln = 6;                                         // Set hardware address length (6 for MAC)
        arp_hdr.ar_pln = 4;                                         // Set protocol address length (4 for IPv4)
        arp_hdr.ar_op = htons(arp_op_reply);                        // Set ARP operation to reply (2)
        memcpy(arp_hdr.ar_sha, source_mac.data(), ETHER_ADDR_LEN);  // Set sender's MAC address (your MAC address)
        arp_hdr.ar_sip = htonl(source_ip);                          // Set sender's IP address (your IP address, convert from string)
        memcpy(arp_hdr.ar_tha, dest_mac.data(), ETHER_ADDR_LEN);    // Set target's MAC address to zero (unknown)
        arp_hdr.ar_tip = dest_ip;                                   // Set target IP address (the IP you're looking for)

        // 1. Serialize Ethernet Header
        Packet packet;
        packet.resize(sizeof(ether_hdr));                           // Resize the vector to fit the Ethernet header
        std::memcpy(packet.data(), &ether_hdr, sizeof(ether_hdr));  // Copy Ethernet header into the vector

        // 2. Serialize ARP Header
        packet.resize(packet.size() + sizeof(arp_hdr));                             // Resize the vector to accommodate the ARP header
        std::memcpy(packet.data() + sizeof(ether_hdr), &arp_hdr, sizeof(arp_hdr));  // Copy ARP header after Ethernet header

        // Proceed to resend the ARP request
        packetSender->sendPacket(packet, source_iface);  // TODO: Need to check this iface
    }
    else {
        // If no valid routing entry is found, handle it accordingly
        std::cout << "Error: No valid routing entry for IP " << dest_ip << std::endl;
    }
}

void ArpCache::tick() {
    // DO NOT CHANGE THIS
    std::unique_lock lock(mutex);

    // Loop through the requests and resend timed-out requests
    for (auto& [dest_ip, request] : requests) {
        // Check if the timeout has been reached for the request
        auto durationSinceLastSent = std::chrono::steady_clock::now() - request.lastSent;
        if (durationSinceLastSent >= timeout) {
            // Resend the ARP request
            sendArpRequest(dest_ip);
        }
    }

    // DO NOT CHANGE THIS
    std::erase_if(entries, [this](const auto& entry) {
        return std::chrono::steady_clock::now() - entry.second.timeAdded >= timeout;
    });
}

void ArpCache::addEntry(uint32_t ip, const mac_addr& mac) {
    // DO NOT CHANGE THIS
    std::unique_lock lock(mutex);

    // Check if there are any pending ARP requests for this IP
    auto it = requests.find(ip);
    if (it != requests.end()) {
        // Create or update the ARP entry for the given IP
        ArpEntry entry = {ip, mac, std::chrono::steady_clock::now()};

        // Insert or update the entry in the ARP cache
        entries[ip] = entry;

        // If there are pending requests, resend the awaiting packets
        for (const auto& awaitingPacket : it->second.awaitingPackets) {
            // Get Source mac
            auto source_mac = routingTable->getRoutingInterface(awaitingPacket.iface).mac;

            // Remove constness to modify the Ethernet header
            auto* ethHeader = const_cast<sr_ethernet_hdr_t*>(
                reinterpret_cast<const sr_ethernet_hdr_t*>(awaitingPacket.packet.data()));
            std::memcpy(ethHeader->ether_shost, source_mac.data(), ETHER_ADDR_LEN);  // Set source MAC address
            std::memcpy(ethHeader->ether_dhost, mac.data(), ETHER_ADDR_LEN);         // Set dest MAC address

            packetSender->sendPacket(awaitingPacket.packet, awaitingPacket.iface);
        }

        // After processing the awaiting packets, remove the request from the requests map
        requests.erase(it);
    }
    else {
        std::cout << "Error: This should not happen" << std::endl;
        return;
    }
}

std::optional<mac_addr> ArpCache::getEntry(uint32_t dest_ip) {
    // DO NOT CHANGE THIS
    std::unique_lock lock(mutex);

    // Check if the IP exists in the ARP cache
    auto it = entries.find(dest_ip);
    if (it != entries.end()) {
        return it->second.mac;  // Return the MAC address if found
    }

    return std::nullopt;  // Return nullopt if not found
}

void ArpCache::queuePacket(uint32_t dest_ip, const Packet& packet, const std::string& dest_iface) {
    // DO NOT CHANGE THIS
    std::unique_lock lock(mutex);

    // Check if there is already an existing ARP request for this IP
    auto it = requests.find(dest_ip);
    if (it != requests.end()) {
        // If an ARP request already exists, add the packet to the awaitingPackets list
        it->second.awaitingPackets.push_back({packet, dest_iface});
    }
    else {
        // If no ARP request exists for this IP, create a new one
        ArpRequest newRequest;
        newRequest.ip = dest_ip;
        newRequest.awaitingPackets.push_back({packet, dest_iface});
        newRequest.timesSent = 0;

        // Add the new request to the requests map
        requests[dest_ip] = newRequest;

        // Send the ARP request since it is the first time
        sendArpRequest(dest_ip);
    }
}

// Checks if the request has been sent and is waiting for a response
bool ArpCache::requestExists(uint32_t dest_ip) {
    auto it = requests.find(dest_ip);
    if (it != requests.end()) {
        return true;
    }
    return false;
}
