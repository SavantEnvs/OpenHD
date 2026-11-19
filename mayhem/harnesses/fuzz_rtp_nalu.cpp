// Fuzz OpenHD's NALU splitting + RTP packetization of encoder output
// (openhd::RTPHelper::feed_multiple_nalu: find_next_nal, CodecConfigFinder,
// bundled librtp h264/h265 packers). First byte picks h264 / h265.
#include <cstddef>
#include <cstdint>
#include <vector>

#include "openhd_rtp.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 1) return -1;
  const bool h265 = data[0] & 1;
  std::vector<uint8_t> buf(data + 1, data + size);
  // openhd_rtp.h: feed_multiple_nalu "Needs to be aligned on NAL !" — the encoder output it is
  // fed always starts with an Annex-B start code (00 00 01 or 00 00 00 01).
  const bool short_prefix = buf.size() >= 3 && buf[0] == 0 && buf[1] == 0 && buf[2] == 1;
  const bool long_prefix =
      buf.size() >= 4 && buf[0] == 0 && buf[1] == 0 && buf[2] == 0 && buf[3] == 1;
  if (!short_prefix && !long_prefix) return -1;
  openhd::RTPHelper helper(h265);
  volatile size_t sink = 0;
  helper.set_out_cb(
      [&](std::vector<std::shared_ptr<std::vector<uint8_t>>> frags) {
        for (auto &f : frags) sink += f->size();
      });
  helper.feed_multiple_nalu(buf.data(), (int)buf.size());
  return 0;
}
