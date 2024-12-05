#ifndef ARPCACHE_H
#define ARPCACHE_H

#include <array>
#include <chrono>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <thread>
#include <unordered_map>
#include <vector>

#include "IArpCache.h"
#include "IPacketSender.h"
#include "IRoutingTable.h"
#include "RouterTypes.h"

class ArpCache : public IArpCache {
   public:
    ArpCache(std::chrono::milliseconds timeout,
             std::shared_ptr<IPacketSender> packetSender, std::shared_ptr<IRoutingTable> routingTable);

    ~ArpCache() override;

    void tick();

    void addEntry(uint32_t ip, const mac_addr& mac) override;

    std::optional<mac_addr> getEntry(uint32_t ip) override;

    void queuePacket(uint32_t ip, const Packet& packet, const std::string& iface) override;

    void sendArpRequest(const uint32_t);
    void sendArpResponse(const uint32_t, const mac_addr);
    bool requestExists(uint32_t dest_ip);

   private:
    void loop();

    std::chrono::milliseconds timeout;

    std::mutex mutex;
    std::unique_ptr<std::thread> thread;
    std::atomic<bool> shutdown = false;

    std::shared_ptr<IPacketSender> packetSender;
    std::shared_ptr<IRoutingTable> routingTable;

    std::unordered_map<ip_addr, ArpEntry> entries;
    std::unordered_map<ip_addr, ArpRequest> requests;
};

#endif  // ARPCACHE_H
