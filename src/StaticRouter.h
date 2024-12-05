#ifndef STATICROUTER_H
#define STATICROUTER_H
#include <memory>
#include <mutex>
#include <vector>

#include "IArpCache.h"
#include "IPacketSender.h"
#include "IRoutingTable.h"

class StaticRouter {
   public:
    StaticRouter(std::unique_ptr<IArpCache> arpCache, std::shared_ptr<IRoutingTable> routingTable,
                 std::shared_ptr<IPacketSender> packetSender);

    /**
     * @brief Handles an incoming packet, telling the switch to send out the necessary packets.
     * @param packet The incoming packet.
     * @param iface The interface on which the packet was received.
     */
    void handlePacket(std::vector<uint8_t> packet, std::string iface);

    void handleARP(const std::vector<uint8_t>& packet, const std::string& iface);

    void handleIP(const std::vector<uint8_t>& packet, const std::string& iface);

    bool isValidIPChecksum(const sr_ip_hdr_t* ipHeader);

    bool isFinalDestination(const sr_ip_hdr_t* ipHeader);

    bool isARPPacketForRouter(const uint32_t target_ip, const std::string& iface);

    void handleEchoRequest(sr_ethernet_hdr_t* ethernetHeader, sr_ip_hdr_t* ipHeader, sr_icmp_hdr_t* icmpHeader, const std::string& iface);

    void sendPortUnreachable(sr_ip_hdr_t* ipHeader, const std::string& iface);

    void sendICMPDestinationUnreachable(const sr_ip_hdr_t* ipHeader, const std::string& iface);

    void sendICMPTimeExceeded(const sr_ip_hdr_t* ipHeader, const std::string& iface);

   private:
    std::mutex mutex;

    std::shared_ptr<IRoutingTable> routingTable;
    std::shared_ptr<IPacketSender> packetSender;

    std::unique_ptr<IArpCache> arpCache;
};

#endif  // STATICROUTER_H
