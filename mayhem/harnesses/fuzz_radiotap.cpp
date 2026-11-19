// Fuzz the first parser every received air frame hits in wifibroadcast:
// the radiotap iterator + RadiotapHeaderRx parsing + 802.11 header split.
#include <cstddef>
#include <cstdint>
#include <vector>

#include "radiotap/RadiotapHeaderRx.hpp"
#include "radiotap/radiotap_util.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  // a captured frame (pcap caplen) is never empty and at most 65535 bytes
  if (size == 0 || size > 65535) return -1;
  // own copy so ASan sees reads past the captured frame
  std::vector<uint8_t> pkt(data, data + size);
  auto parsed = radiotap::rx::process_received_radiotap_packet(pkt.data(),
                                                              (int)pkt.size());
  if (parsed.has_value()) {
    (void)radiotap::rx::parsed_radiotap_to_string(parsed.value());
    (void)radiotap::util::radiotap_header_to_string(pkt.data(), (int)pkt.size());
  }
  return 0;
}
