#include "ArpCache.h"

// #include <spdlog/spdlog.h>

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
void ArpCache::sendArpRequest(uint32_t ip) {
    auto it = requests.find(ip);
    if (it == requests.end()) {
        std::cout << "Error: This should not happen" << std::endl;
        return;
    }
    else {
        ArpRequest& request = it->second;

        if (request.timesSent >= 7) {
            // Drop the request if failed 7 times without a response
            requests.erase(it);
        }
        else {
            // Resend the ARP request and update the metadata
            auto routingEntryOpt = routingTable->getRoutingEntry(ip);

            if (routingEntryOpt) {
                // If a valid routing entry is found, use its interface to send the ARP request
                const RoutingEntry& routingEntry = routingEntryOpt.value();
                std::string iface = routingEntry.iface;

                RoutingInterface interface = routingTable->getRoutingInterface("sw0");
                ip_addr source_ip = interface.ip;
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
                arp_hdr.ar_hrd = htons(1);                                  // Set hardware type to Ethernet (1)
                arp_hdr.ar_pro = htons(0x0800);                             // Set protocol type to IPv4 (0x0800)
                arp_hdr.ar_hln = 6;                                         // Set hardware address length (6 for MAC)
                arp_hdr.ar_pln = 4;                                         // Set protocol address length (4 for IPv4)
                arp_hdr.ar_op = htons(arp_op_request);                      // Set ARP operation to request (1)
                memcpy(arp_hdr.ar_sha, source_mac.data(), ETHER_ADDR_LEN);  // Set sender's MAC address (your MAC address)
                arp_hdr.ar_sip = source_ip;                                 // Set sender's IP address (your IP address, convert from string)
                memset(arp_hdr.ar_tha, 0, ETHER_ADDR_LEN);                  // Set target's MAC address to zero (unknown)
                arp_hdr.ar_tip = ip;                                        // Set target IP address (the IP you're looking for)

                // 1. Serialize Ethernet Header
                Packet packet;
                packet.resize(sizeof(ether_hdr));                           // Resize the vector to fit the Ethernet header
                std::memcpy(packet.data(), &ether_hdr, sizeof(ether_hdr));  // Copy Ethernet header into the vector

                // 2. Serialize ARP Header
                packet.resize(packet.size() + sizeof(arp_hdr));                             // Resize the vector to accommodate the ARP header
                std::memcpy(packet.data() + sizeof(ether_hdr), &arp_hdr, sizeof(arp_hdr));  // Copy ARP header after Ethernet header

                // Proceed to resend the ARP request
                packetSender->sendPacket(packet, iface);

                // Update the request's metadata
                request.lastSent = std::chrono::steady_clock::now();
                request.timesSent++;
            }
            else {
                // If no valid routing entry is found, handle it accordingly
                std::cout << "Error: No valid routing entry for IP " << ip << std::endl;
            }
        }
    }
}

// UPDATE: This is a custom function
void ArpCache::sendArpResponse() {
    // TODO
}

void ArpCache::tick() {
    std::unique_lock lock(mutex);

    // TODO: Your code here

    // Loop through the requests and resend timed-out requests
    for (auto& [ip, request] : requests) {
        // Check if the timeout has been reached for the request
        auto durationSinceLastSent = std::chrono::steady_clock::now() - request.lastSent;
        if (durationSinceLastSent >= timeout) {
            // Resend the ARP request
            sendArpRequest(ip);
        }
    }

    // TODO: Your code should end here

    // Remove entries that have been in the cache for too long
    std::erase_if(entries, [this](const auto& entry) {
        return std::chrono::steady_clock::now() - entry.second.timeAdded >= timeout;
    });
}

void ArpCache::addEntry(uint32_t ip, const mac_addr& mac) {
    std::unique_lock lock(mutex);

    // TODO: Your code below

    // UPDATE: Check if this is a request or reply

    // Create or update the ARP entry for the given IP
    ArpEntry entry = {ip, mac, std::chrono::steady_clock::now()};

    // Insert or update the entry in the ARP cache
    entries[ip] = entry;

    // Check if there are any pending ARP requests for this IP
    auto it = requests.find(ip);
    if (it != requests.end()) {
        // If there are pending requests, resend the awaiting packets
        for (const auto& awaitingPacket : it->second.awaitingPackets) {
            packetSender->sendPacket(awaitingPacket.packet, awaitingPacket.iface);
        }

        // After processing the awaiting packets, remove the request from the requests map
        requests.erase(it);
    }
}

std::optional<mac_addr> ArpCache::getEntry(uint32_t ip) {
    std::unique_lock lock(mutex);

    // TODO: Your code below

    // Check if the IP exists in the ARP cache
    auto it = entries.find(ip);
    if (it != entries.end()) {
        return it->second.mac;  // Return the MAC address if found
    }

    return std::nullopt;  // Return nullopt if not found
}

void ArpCache::queuePacket(uint32_t ip, const Packet& packet, const std::string& iface) {
    std::unique_lock lock(mutex);

    // TODO: Your code below

    // Modify packet data

    // Check if there is already an existing ARP request for this IP
    auto it = requests.find(ip);
    if (it != requests.end()) {
        // If an ARP request already exists, add the packet to the awaitingPackets list
        it->second.awaitingPackets.push_back({packet, iface});
    }
    else {
        // If no ARP request exists for this IP, create a new one
        ArpRequest newRequest;
        newRequest.ip = ip;
        newRequest.awaitingPackets.push_back({packet, iface});
        newRequest.timesSent = 0;

        // Add the new request to the requests map
        requests[ip] = newRequest;

        // Send the ARP request since it is the first time
        sendArpRequest(ip);
    }
}
