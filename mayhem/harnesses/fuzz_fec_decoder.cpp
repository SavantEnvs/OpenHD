// Fuzz the wifibroadcast FEC receive path (block ring, fragment reassembly,
// Reed-Solomon recovery) the way WBStreamRx drives it: every decrypted radio
// payload that passes FECDecoder::validate_packet_size goes to
// process_valid_packet.
// Input: [1 byte: bit7 forward_gapped, rest rx queue depth][packets...], each packet = u16le length + bytes.
#include <cstddef>
#include <cstdint>
#include <vector>

#include "fec/FECDecoder.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 1) return -1;
  // FECDecoder contract: 1 <= rx_queue_max_depth < 20 (asserted in ctor)
  const unsigned depth = 1 + ((data[0] & 0x7f) % 19);
  const bool forward_gapped = data[0] & 0x80;
  data++;
  size--;
  FECDecoder decoder(depth, MAX_TOTAL_FRAGMENTS_PER_BLOCK, false, forward_gapped);
  volatile size_t sink = 0;
  decoder.mSendDecodedPayloadCallback = [&](const uint8_t *p, std::size_t n) {
    if (n) sink += p[0] + p[n - 1];
  };
  size_t off = 0;
  while (off + 2 <= size) {
    size_t len = data[off] | (data[off + 1] << 8);
    off += 2;
    if (len > size - off) len = size - off;
    std::vector<uint8_t> pkt(data + off, data + off + len);
    off += len;
    if (FECDecoder::validate_packet_size((int)pkt.size())) {
      decoder.process_valid_packet(pkt.data(), (int)pkt.size());
    }
  }
  return 0;
}
