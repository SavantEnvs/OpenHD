// Fuzz OpenHD's handling of MAVLink bytes from the flight-controller UART / radio:
// the MAVLink v1/v2 framing (as MEndpoint::parseNewData does it), then OpenHD's
// UartDeduplicator::filter_and_mark, UartPrioritizer::sort_by_priority and the
// re-pack/aggregation into wifibroadcast packets (aggregate_pack_messages).
// Input: [1 byte: priority profile seed][raw MAVLink byte stream].
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vector>

#include "internal/UartDeduplicator.h"
#include "internal/UartPrioritizer.h"
#include "mav_include.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 1) return -1;
  const uint8_t seed = data[0];
  data++;
  size--;
  // fresh parser state per input (one channel, reset like a newly opened endpoint)
  const uint8_t chan = MAVLINK_COMM_0;
  std::memset(mavlink_get_channel_status(chan), 0, sizeof(mavlink_status_t));
  std::memset(mavlink_get_channel_buffer(chan), 0, sizeof(mavlink_message_t));
  std::vector<MavlinkMessage> msgs;
  for (size_t i = 0; i < size; i++) {
    mavlink_message_t msg;
    mavlink_status_t status;
    if (mavlink_parse_char(chan, data[i], &msg, &status) == 1) {
      MavlinkMessage m{msg};
      m.recommended_n_injections = 1 + (msg.seq & 3);
      msgs.push_back(m);
    }
  }
  UartDeduplicator dedup;
  auto filtered = dedup.filter_and_mark(msgs);
  UartPriorityProfile profile;
  profile.rc_priority = seed & 3;
  profile.openhd_priority = (seed >> 2) & 3;
  profile.flight_controller_priority = (seed >> 4) & 3;
  profile.fc_sys_id = (seed & 0x80) ? OHD_SYS_ID_FC_BETAFLIGHT : OHD_SYS_ID_FC;
  UartPrioritizer prio;
  auto sorted = prio.sort_by_priority(filtered, profile);
  volatile size_t sink = 0;
  for (auto &p : aggregate_pack_messages(sorted, 1024)) sink += p.aggregated_data->size();
  return 0;
}
