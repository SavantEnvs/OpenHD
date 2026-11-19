// Fuzz OpenHD's MAVLink parameter server (XMavlinkParamProvider: MAVSDK-derived
// MavlinkMessageHandler + MavlinkParameterReceiver handling PARAM_SET,
// PARAM_EXT_SET, PARAM_REQUEST_READ/LIST, ...) with MAVLink messages framed from
// the fuzz input, as GroundTelemetry/AirTelemetry feed it from the GCS / radio.
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include "mav_include.h"
#include "mavsdk_temporary/XMavlinkParamProvider.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  // fresh parser state per input (one channel, reset like a newly opened endpoint)
  const uint8_t chan = MAVLINK_COMM_1;
  std::memset(mavlink_get_channel_status(chan), 0, sizeof(mavlink_status_t));
  std::memset(mavlink_get_channel_buffer(chan), 0, sizeof(mavlink_message_t));
  std::vector<MavlinkMessage> msgs;
  for (size_t i = 0; i < size; i++) {
    mavlink_message_t msg;
    mavlink_status_t status;
    if (mavlink_parse_char(chan, data[i], &msg, &status) == 1) msgs.push_back(MavlinkMessage{msg});
  }
  XMavlinkParamProvider provider(OHD_SYS_ID_AIR, MAV_COMP_ID_ONBOARD_COMPUTER);
  std::vector<openhd::Setting> settings;
  settings.push_back(openhd::Setting{
      "WB_FREQUENCY",
      openhd::IntSetting{5180, [](std::string, int v) { return v > 0 && v < 7000; }}});
  settings.push_back(openhd::Setting{
      "VIDEO_BITRATE", openhd::IntSetting{8000, [](std::string, int v) { return v >= 0; }}});
  settings.push_back(openhd::Setting{
      "CAM_NAME", openhd::StringSetting{"cam0", [](std::string, std::string v) {
                                          return v.size() < 16;
                                        }}});
  provider.add_params(settings);
  provider.set_ready();
  volatile size_t sink = 0;
  sink += provider.process_mavlink_messages(msgs).size();
  sink += provider.generate_mavlink_messages().size();
  return 0;
}
