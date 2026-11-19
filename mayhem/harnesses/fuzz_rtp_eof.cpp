// Fuzz OpenHD's RTP end-of-frame detection on the received/forwarded RTP video stream:
// openhd::RTPFragmentBuffer::buffer_and_forward, the upstream caller of
// openhd::rtp_eof_helper::h264_more_info / h265_more_info (RTP FU-A / H.265 FU header parsing),
// which buffers fragments into frames, tracks IDR FU starts (is_idr_frame) and force-flushes after
// 500 fragments without an end marker.
//
// Input: byte 0 = flags (bit0 h265, bit1 intra refresh, bit2 ultra-secure encryption), then a
// sequence of RTP fragments, each [len_lo len_hi][len bytes] (a truncated last length takes the
// remaining bytes). A fresh RTPFragmentBuffer is used per input, so no state crosses inputs.
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <vector>

#include "openhd_rtp.h"
#include "rtp_eof_helper.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 1) return -1;
  const uint8_t flags = data[0];
  const bool h265 = flags & 1;
  openhd::RTPFragmentBuffer buffer;
  buffer.m_is_h265 = h265;
  buffer.m_uses_intra_refresh = flags & 2;
  buffer.m_enable_ultra_secure_encryption = flags & 4;
  size_t off = 1;
  volatile int sink = 0;
  while (off < size) {
    size_t len = size - off;
    if (len >= 2) {
      const size_t want = data[off] | (size_t(data[off + 1]) << 8);
      off += 2;
      len = std::min(want, size - off);
    } else {
      off = size - len;
    }
    auto frag = std::make_shared<std::vector<uint8_t>>(data + off, data + off + len);
    off += len;
    // the helper on its own (same bytes buffer_and_forward will parse) ...
    auto info = h265 ? openhd::rtp_eof_helper::h265_more_info(frag->data(), frag->size())
                     : openhd::rtp_eof_helper::h264_more_info(frag->data(), frag->size());
    sink = info.is_fu_start + info.is_fu_end + (info.is_fu_start ? info.nal_unit_type : 0);
    // ... and through its real caller, the frame-assembling fragment buffer.
    buffer.buffer_and_forward(frag, 0);
  }
  (void)sink;
  return 0;
}
