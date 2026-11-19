#!/usr/bin/env bash
#
# mayhem/build.sh — build OpenHD's fuzz harnesses and the wifibroadcast unit test.
#
# OpenHD's top-level CMake build needs GStreamer, Poco, libusb, v4l2, libnl … and only produces the
# `openhd` daemon. The fuzzed code (wifibroadcast radiotap/FEC, ohd_video RTP helpers, ohd_common
# logging) is plain C/C++ with no such deps, so this script compiles exactly the upstream source
# files the harnesses need (the same lists upstream's WBLib.cmake / ohd_common / ohd_video CMake files
# use) with $SANITIZER_FLAGS. spdlog is used header-only from the upstream submodule.
#
# Outputs (all under the gitignored mayhem/build/):
#   mayhem/build/bin/<fuzzer>, mayhem/build/bin/<fuzzer>-standalone   sanitized fuzz targets
#   mayhem/build/test/unit_test                                       wifibroadcast unit tests, normal flags
set -euo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
: "${SRC:=/mayhem}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"
O="$SRC/OpenHD"
W="$O/ohd_interface/lib/wifibroadcast/wifibroadcast"
C="$O/ohd_common"
V="$O/ohd_video"
T="$O/ohd_telemetry"
B="$SRC/mayhem/build"
[ -f "$C/lib/spdlog/include/spdlog/spdlog.h" ] && [ -f "$W/src/WBTxRx.cpp" ] || {
  echo "git submodules missing (git submodule update --init --recursive)" >&2; exit 1; }

INC=(-I"$W/src" -I"$W/src/HelperSources" -I"$W/lib" -I"$C/lib/spdlog/include" -I"$C/inc"
     -I"$C/lib/json/include" -I"$V/inc" -I"$V/librtp/inc"
     -I"$T/src" -I"$T/lib/mavlink-headers/mavlink/v2.0")
# upstream WBLib.cmake: SSSE3 FEC path on x86 (-mssse3 -faligned-new=256 -DWIFIBROADCAST_HAS_X86_SSSE3).
# The fuzz build leaves out -faligned-new=256: with it clang routes 64/128-byte-aligned types
# (RxBlock, spdlog's pattern_formatter) through the plain 16-byte-aligned operator new, so UBSan's
# alignment check aborts on the very first input. The test build keeps upstream's exact flags.
SIMD=(-mssse3 -DWIFIBROADCAST_HAS_X86_SSSE3)
CEXTRA=()

WB_FEC_SRCS=("$W/lib/fec/fec_base.cpp" "$W/src/fec/FEC.cpp" "$W/src/fec/FECDecoder.cpp"
             "$W/src/fec/RxBlock.cpp" "$W/src/wifibroadcast_spdlog.cpp")
WB_ALL_SRCS=("${WB_FEC_SRCS[@]}" "$W/src/encryption/KeyPair.cpp" "$W/src/encryption/Encryptor.cpp"
             "$W/src/encryption/Encryption.cpp" "$W/src/encryption/EncryptionFsUtils.cpp"
             "$W/src/encryption/Decryptor.cpp" "$W/src/dummy_link/DummyLink.cpp"
             "$W/src/fec/FECEncoder.cpp" "$W/src/WBStreamRx.cpp" "$W/src/WBStreamTx.cpp"
             "$W/src/WBVideoStreamTx.cpp" "$W/src/WBTxRx.cpp" "$W/src/FunkyQueue.cpp"
             "$W/src/radiotap/RadiotapRxRfAggregator.cpp")
COMMON_SRCS=("$C/src/openhd_spdlog.cpp" "$C/src/config_paths.cpp" "$C/src/openhd_util.cpp"
             "$C/src/openhd_util_filesystem.cpp" "$C/src/openhd_util_time.cpp")
VIDEO_SRCS=("$V/src/openhd_rtp.cpp" "$V/src/rtp_eof_helper.cpp")
LIBRTP_SRCS=("$V"/librtp/src/*.c)
TELEM_SRCS=("$T/src/internal/UartDeduplicator.cpp" "$T/src/internal/UartPrioritizer.cpp")
PARAM_SRCS=("$T"/src/mavsdk_temporary/{XMavlinkParamProvider,mavlink_message_handler,mavlink_parameter_receiver,mavlink_parameter_set,mavlink_parameter_subscription,param_value,mavsdk_time}.cpp
            "$C/src/openhd_settings_imp.cpp")

# compile <objdir> <std> <flags-var-name> <src...>  — parallel, prints the object list in OBJS
compile() {
  local dir="$1" std="$2" flagsvar="$3"; shift 3
  local -n flags="$flagsvar"
  mkdir -p "$dir"
  OBJS=()
  local pids=() s o
  for s in "$@"; do
    o="$dir/$(echo "${s#"$SRC"/}" | tr '/' '_').o"
    OBJS+=("$o")
    if [[ "$s" == *.c ]]; then
      $CC -std=gnu11 "${flags[@]}" "${CEXTRA[@]}" "${INC[@]}" -c "$s" -o "$o" &
    else
      $CXX -std="$std" "${flags[@]}" "${PCH[@]}" "${SIMD[@]}" "${INC[@]}" -c "$s" -o "$o" &
    fi
    pids+=($!)
    if [ "${#pids[@]}" -ge "$MAYHEM_JOBS" ]; then wait "${pids[0]}"; pids=("${pids[@]:1}"); fi
  done
  local p; for p in "${pids[@]}"; do wait "$p"; done
}

# 1) sanitized fuzz build
# shellcheck disable=SC2206
FZ=($SANITIZER_FLAGS $DEBUG_FLAGS -O1 -fsanitize=fuzzer-no-link)
# ohd_common/ohd_video rely on upstream's target_precompile_headers(spdlog/spdlog.h), i.e. a forced include
PCH=()
mkdir -p "$B/bin"
# radiotap.c evaluates `1 << IEEE80211_RADIOTAP_EXT` (1 << 31, an int) for every header, which UBSan's
# shift-base check halts on before any input-dependent code runs; and its iterator advances a NULL
# _arg by 0 (`_arg += size`) on vendor-namespace skips, which pointer-overflow halts on within
# seconds. Both are benign; relax only those two checks, only in that file (ASan stays on).
CEXTRA=(-fno-sanitize=shift-base,pointer-overflow)
compile "$B/fuzz/radiotap" c++17 FZ "$W/lib/radiotap/radiotap.c"; RT_OBJS=("${OBJS[@]}")
CEXTRA=()
compile "$B/fuzz/wb" c++17 FZ "${WB_FEC_SRCS[@]}"; WB_OBJS=("${RT_OBJS[@]}" "${OBJS[@]}")
PCH=(-include spdlog/spdlog.h)
compile "$B/fuzz/common" c++17 FZ "${COMMON_SRCS[@]}"; COMMON_OBJS=("${OBJS[@]}")
compile "$B/fuzz/video" c++17 FZ "${VIDEO_SRCS[@]}" "${LIBRTP_SRCS[@]}"; VIDEO_OBJS=("${OBJS[@]}")
compile "$B/fuzz/telemetry" c++17 FZ "${TELEM_SRCS[@]}"; TELEM_OBJS=("${OBJS[@]}")
compile "$B/fuzz/params" c++17 FZ "${PARAM_SRCS[@]}"; PARAM_OBJS=("${OBJS[@]}")
compile "$B/fuzz/harness" c++17 FZ "$SRC"/mayhem/harnesses/*.cpp "$SRC/mayhem/lsan_off.cc"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$B/fuzz/standalone_main.o"
H="$B/fuzz/harness"
hobj() { echo "$H/mayhem_harnesses_$1.cpp.o"; }
LSAN="$H/mayhem_lsan_off.cc.o"

link() {  # link <name> <objs...>
  local name="$1"; shift
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "$@" "$LSAN" -lpthread -o "$B/bin/$name"
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link "$B/fuzz/standalone_main.o" "$@" "$LSAN" -lpthread \
    -o "$B/bin/$name-standalone"
}
link fuzz_radiotap "$(hobj fuzz_radiotap)" "${WB_OBJS[@]}"
link fuzz_fec_decoder "$(hobj fuzz_fec_decoder)" "${WB_OBJS[@]}"
link fuzz_rtp_eof "$(hobj fuzz_rtp_eof)" "${VIDEO_OBJS[@]}" "${COMMON_OBJS[@]}"
link fuzz_rtp_nalu "$(hobj fuzz_rtp_nalu)" "${VIDEO_OBJS[@]}" "${COMMON_OBJS[@]}"
link fuzz_mavlink_uart "$(hobj fuzz_mavlink_uart)" "${TELEM_OBJS[@]}" "${COMMON_OBJS[@]}"
link fuzz_mavlink_params "$(hobj fuzz_mavlink_params)" "${PARAM_OBJS[@]}" "${COMMON_OBJS[@]}"

# 2) wifibroadcast unit test (upstream executables/unit_test.cpp), normal flags, asserts on
# shellcheck disable=SC2206
TF=(-O2 $COVERAGE_FLAGS)
PCH=()
SIMD=(-mssse3 -faligned-new=256 -DWIFIBROADCAST_HAS_X86_SSSE3)
mkdir -p "$B/test"
compile "$B/test/obj" c++20 TF "$W/lib/radiotap/radiotap.c" "${WB_ALL_SRCS[@]}" "$W/executables/unit_test.cpp"
$CXX "${TF[@]}" "${OBJS[@]}" -lsodium -lpcap -lpthread -o "$B/test/unit_test"
UT_OBJS=("${OBJS[@]}")
# unit_test -m 2 reads ../example_key/txrx.key (relative to its cwd, mayhem/build/test): make it with
# upstream's own wfb_keygen from the fixed bind phrase, as upstream's test setup does.
compile "$B/test/obj" c++20 TF "$W/executables/wfb_keygen.cpp"
$CXX "${TF[@]}" "${OBJS[@]}" "${UT_OBJS[@]:0:${#UT_OBJS[@]}-1}" -lsodium -lpcap -lpthread -o "$B/test/wfb_keygen"
mkdir -p "$B/example_key"
(cd "$B/example_key" && rm -f txrx.key && "$B/test/wfb_keygen" -b openhd >/dev/null && test -s txrx.key)
echo "build.sh: done"
ls -l "$B/bin" "$B/test/unit_test" "$B/example_key/txrx.key"
