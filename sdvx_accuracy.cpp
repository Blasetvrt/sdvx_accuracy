#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>
#include <d3d9.h>
#include <psapi.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <mutex>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

#include "imgui/imgui.h"
#include "imgui/imgui_impl_dx9.h"
#include "spicesdk.h"

namespace sdvx_acc {

static std::mutex g_log_mutex;
static FILE* g_log_file = nullptr;

static std::string get_game_dir() {
    char path[MAX_PATH] = {};
    if (GetModuleFileNameA(nullptr, path, MAX_PATH) == 0) {
        return ".";
    }
    std::string s(path);
    size_t pos = s.find_last_of("\\/");
    return (pos != std::string::npos) ? s.substr(0, pos) : ".";
}

static void log_msg(const char* fmt, ...) {
    std::lock_guard<std::mutex> lock(g_log_mutex);
    if (!g_log_file) {
        std::string p = get_game_dir() + "\\sdvx_accuracy.log";
        g_log_file = fopen(p.c_str(), "w");
    }
    if (!g_log_file) return;

    SYSTEMTIME st;
    GetLocalTime(&st);
    fprintf(g_log_file, "[%02d:%02d:%02d.%03d] [sdvx_accuracy] ",
            st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);

    va_list args;
    va_start(args, fmt);
    vfprintf(g_log_file, fmt, args);
    va_end(args);

    fprintf(g_log_file, "\n");
    fflush(g_log_file);
}

static bool is_readable(const void* ptr, size_t bytes = 8) {
    if (!ptr) return false;
    uintptr_t addr = reinterpret_cast<uintptr_t>(ptr);
    if (addr < 0x10000 || addr > 0x00007FFFFFFFFFFFULL) return false;
    MEMORY_BASIC_INFORMATION mbi = {};
    if (VirtualQuery(ptr, &mbi, sizeof(mbi)) == 0) return false;
    if (mbi.State != MEM_COMMIT) return false;
    const DWORD mask = PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
                       PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
    if ((mbi.Protect & mask) == 0 || (mbi.Protect & PAGE_GUARD) != 0 || (mbi.Protect & PAGE_NOACCESS) != 0) {
        return false;
    }
    uintptr_t region_end = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
    return (addr + bytes) <= region_end;
}

template <typename T>
static bool safe_read(const void* ptr, T& out) {
    if (!is_readable(ptr, sizeof(T))) return false;
    out = *reinterpret_cast<const T*>(ptr);
    return true;
}

static std::string read_msvc_string(const void* str_addr) {
    if (!is_readable(str_addr, 32)) return "";
    const uint8_t* p = reinterpret_cast<const uint8_t*>(str_addr);
    uint64_t size = *reinterpret_cast<const uint64_t*>(p + 0x10);
    uint64_t cap  = *reinterpret_cast<const uint64_t*>(p + 0x18);
    if (size == 0 || size > 4096 || cap > 65536 || size > cap) return "";
    const char* chars = nullptr;
    if (cap >= 16) {
        chars = *reinterpret_cast<const char* const*>(p);
        if (!is_readable(chars, size)) return "";
    } else {
        chars = reinterpret_cast<const char*>(p);
    }
    return std::string(chars, static_cast<size_t>(size));
}

struct SectionRange {
    uintptr_t start = 0;
    uintptr_t end = 0;
};

struct ModuleLayout {
    uintptr_t base = 0;
    size_t size = 0;
    SectionRange text;
    SectionRange rdata;
    SectionRange data;
};

static bool get_module_layout(HMODULE mod, ModuleLayout& out) {
    if (!mod) return false;
    uintptr_t base = reinterpret_cast<uintptr_t>(mod);
    auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    if (!is_readable(dos, sizeof(IMAGE_DOS_HEADER)) || dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
    if (!is_readable(nt, sizeof(IMAGE_NT_HEADERS64)) || nt->Signature != IMAGE_NT_SIGNATURE) return false;

    out.base = base;
    out.size = nt->OptionalHeader.SizeOfImage;

    auto* sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        char name[9] = {};
        memcpy(name, sec[i].Name, 8);
        uintptr_t s_start = base + sec[i].VirtualAddress;
        uintptr_t s_end = s_start + std::max(sec[i].Misc.VirtualSize, sec[i].SizeOfRawData);
        if (strcmp(name, ".text") == 0) out.text = {s_start, s_end};
        else if (strcmp(name, ".rdata") == 0) out.rdata = {s_start, s_end};
        else if (strcmp(name, ".data") == 0) out.data = {s_start, s_end};
    }
    return out.text.start != 0 && out.rdata.start != 0;
}

#pragma pack(push, 1)
struct RTTICompleteObjectLocator64 {
    uint32_t signature;
    uint32_t offset;
    uint32_t cdOffset;
    int32_t  pTypeDescriptor;
    int32_t  pClassDescriptor;
    int32_t  pSelf;
};
#pragma pack(pop)

static std::string get_rtti_class_name(const void* obj_ptr, const ModuleLayout& mod) {
    if (!is_readable(obj_ptr, 8)) return "";
    uintptr_t vftable = *reinterpret_cast<const uintptr_t*>(obj_ptr);
    if (vftable < mod.rdata.start + 8 || vftable >= mod.rdata.end) return "";
    if (!is_readable(reinterpret_cast<const void*>(vftable - 8), 16)) return "";

    uintptr_t col_ptr = *reinterpret_cast<const uintptr_t*>(vftable - 8);
    if (col_ptr < mod.rdata.start || col_ptr + sizeof(RTTICompleteObjectLocator64) > mod.rdata.end) return "";

    const auto* col = reinterpret_cast<const RTTICompleteObjectLocator64*>(col_ptr);
    if (col->signature != 1) return "";

    uintptr_t td_ptr = mod.base + static_cast<uint32_t>(col->pTypeDescriptor);
    if (td_ptr < mod.base || td_ptr + 24 >= mod.base + mod.size) return "";
    if (!is_readable(reinterpret_cast<const void*>(td_ptr + 16), 64)) return "";

    const char* name = reinterpret_cast<const char*>(td_ptr + 16);
    size_t len = strnlen(name, 120);
    if (len == 0 || len >= 120) return "";
    return std::string(name, len);
}

static uintptr_t find_primary_vftable(const ModuleLayout& mod, const char* mangled_name) {
    size_t name_len = strlen(mangled_name);
    int32_t target_td_rva = 0;

    auto search_td_in = [&](SectionRange sec) -> int32_t {
        if (!sec.start || sec.end <= sec.start + 16 + name_len) return 0;
        for (uintptr_t p = sec.start; p + 16 + name_len < sec.end; p += 8) {
            if (memcmp(reinterpret_cast<const void*>(p + 16), mangled_name, name_len + 1) == 0) {
                return static_cast<int32_t>(p - mod.base);
            }
        }
        return 0;
    };

    target_td_rva = search_td_in(mod.data);
    if (!target_td_rva) target_td_rva = search_td_in(mod.rdata);
    if (!target_td_rva) return 0;

    std::vector<uintptr_t> cols;
    for (uintptr_t p = mod.rdata.start; p + sizeof(RTTICompleteObjectLocator64) <= mod.rdata.end; p += 4) {
        const auto* col = reinterpret_cast<const RTTICompleteObjectLocator64*>(p);
        if (col->signature == 1 && col->offset == 0 && col->pTypeDescriptor == target_td_rva) {
            int32_t expected_self = static_cast<int32_t>(p - mod.base);
            if (col->pSelf == expected_self) {
                cols.push_back(p);
            }
        }
    }
    if (cols.empty()) return 0;

    for (uintptr_t p = mod.rdata.start + 8; p + 8 <= mod.rdata.end; p += 8) {
        uintptr_t meta = *reinterpret_cast<const uintptr_t*>(p - 8);
        for (uintptr_t col_addr : cols) {
            if (meta == col_addr) {
                uintptr_t fn0 = *reinterpret_cast<const uintptr_t*>(p);
                if (fn0 >= mod.text.start && fn0 < mod.text.end) {
                    return p;
                }
            }
        }
    }
    return 0;
}

static size_t resolve_vox_path_offset(const ModuleLayout& mod, uintptr_t world_vftable) {
    const size_t default_offset = 0x410;
    if (!world_vftable || !is_readable(reinterpret_cast<const void*>(world_vftable + 8), 8)) {
        return default_offset;
    }
    uintptr_t fn1 = *reinterpret_cast<const uintptr_t*>(world_vftable + 8);
    if (fn1 < mod.text.start || fn1 + 0x200 > mod.text.end) return default_offset;

    const char* needle = "VoxFile Target";
    size_t nlen = strlen(needle);
    uintptr_t str_addr = 0;
    for (uintptr_t p = mod.rdata.start; p + nlen < mod.rdata.end; ++p) {
        if (memcmp(reinterpret_cast<const void*>(p), needle, nlen) == 0) {
            str_addr = p;
            break;
        }
    }
    if (!str_addr) return default_offset;

    const uint8_t* code = reinterpret_cast<const uint8_t*>(fn1);
    for (size_t i = 0; i < 0x180; ++i) {
        if (code[i] == 0x48 && code[i + 1] == 0x8D && code[i + 2] == 0x0D) {
            int32_t disp = *reinterpret_cast<const int32_t*>(code + i + 3);
            uintptr_t target = fn1 + i + 7 + disp;
            if (target == str_addr) {
                for (size_t back = 7; back <= 28 && i >= back; ++back) {
                    size_t pos = i - back;
                    if ((code[pos] == 0x48 || code[pos] == 0x4C) && code[pos + 1] == 0x8D) {
                        uint8_t modrm = code[pos + 2];
                        if ((modrm & 0xC0) == 0x80 && (modrm & 0x07) != 0x04) {
                            uint32_t off = *reinterpret_cast<const uint32_t*>(code + pos + 3);
                            if (off >= 0x100 && off <= 0x1000) {
                                return static_cast<size_t>(off);
                            }
                        }
                    }
                }
            }
        }
    }
    return default_offset;
}

template <typename Fn>
static bool hook_vftable_slot(uintptr_t vftable, size_t slot_index, Fn detour_fn, Fn* out_orig) {
    if (!vftable) return false;
    void** slot_addr = reinterpret_cast<void**>(vftable + slot_index * sizeof(void*));
    if (!is_readable(slot_addr, sizeof(void*))) return false;

    void* current = *slot_addr;
    if (current == reinterpret_cast<void*>(detour_fn)) return true;

    DWORD old_prot = 0;
    if (!VirtualProtect(slot_addr, sizeof(void*), PAGE_READWRITE, &old_prot)) {
        return false;
    }
    void* prev = InterlockedExchangePointer(slot_addr, reinterpret_cast<void*>(detour_fn));
    if (out_orig && *out_orig == nullptr) {
        *out_orig = reinterpret_cast<Fn>(prev);
    }
    DWORD dummy = 0;
    VirtualProtect(slot_addr, sizeof(void*), old_prot, &dummy);
    return true;
}

enum class JudgeGrade : uint32_t {
    Unjudged      = 0,
    ErrorEarly    = 1,
    NearEarly     = 2,
    CritEarly     = 3,
    SCritEarly    = 4,
    HoldCrit      = 5,
    SCritLate     = 6,
    CritLate      = 7,
    NearLate      = 8,
    ErrorLate     = 9,
    ErrorTimeout  = 10
};

#pragma pack(push, 1)
struct RawJudgeResult {
    uint32_t grade;
    float    judge_time;
    float    delta_sec;
    uint32_t note_id;
    uint32_t tick_index;
    uint32_t lane;
    uint8_t  lane_type;
    uint8_t  pad19[3];
    uint32_t tick_kind;
    uint8_t  tick_kind_type;
    uint8_t  pad21[3];
    float    hold_ratio;
};
#pragma pack(pop)
static_assert(sizeof(RawJudgeResult) == 0x28, "RawJudgeResult size mismatch");

struct BpmEvent {
    int   measure = 1;
    int   beat = 1;
    int   offset = 0;
    float time_sec = 0.0f;
    float bpm = 120.0f;
};

struct TimeSigEvent {
    int measure = 1;
    int num = 4;
    int den = 4;
};

struct ChartSection {
    int         index = 0;
    int         start_measure = 1;
    int         end_measure = 1;
    float       start_time = 0.0f;
    float       end_time = 0.0f;
    float       bpm = 120.0f;
    std::string label;

    uint32_t total_ticks = 0;
    uint32_t judged_ticks = 0;
    uint32_t chip_notes = 0;
    uint32_t s_crit = 0;
    uint32_t hold_crit = 0;
    uint32_t crit_early = 0;
    uint32_t crit_late = 0;
    uint32_t near_early = 0;
    uint32_t near_late = 0;
    uint32_t error_early = 0;
    uint32_t error_late = 0;
    uint32_t error_miss = 0;
    double   sum_delta_ms = 0.0;
    uint32_t timed_hits = 0;
};

struct TrackedTick {
    uint32_t note_id = 0;
    uint32_t tick_index = 0;
    float    target_time = 0.0f;
    uint32_t lane = 0;
    uint8_t  lane_type = 1;
    uint32_t tick_kind = 1;
    uint8_t  tick_kind_type = 1;
    int      measure = 1;
    int      section_idx = 0;

    uint32_t grade = 0;
    float    judge_time = 0.0f;
    float    delta_ms = 0.0f;

    bool is_chip() const {
        return tick_kind_type == 1 && tick_kind == 1;
    }
    bool is_laser_slam() const {
        return tick_kind_type == 2 && tick_kind == 1;
    }
    bool has_timing_offset() const {
        return is_chip() && grade >= 1 && grade <= 9 && grade != 5;
    }
    int unified_lane() const {
        if (lane_type == 2 || tick_kind_type == 2) {
            int l = (lane >= 1 && lane <= 2) ? static_cast<int>(lane - 1) : (lane == 0 ? 0 : 1);
            return 6 + std::clamp(l, 0, 1);
        }
        int b = (lane >= 1 && lane <= 6) ? static_cast<int>(lane - 1) : static_cast<int>(lane);
        return std::clamp(b, 0, 5);
    }
};

struct LaneStats {
    uint32_t total = 0;
    uint32_t judged = 0;
    uint32_t s_crit = 0;
    uint32_t crit_early = 0;
    uint32_t crit_late = 0;
    uint32_t near_early = 0;
    uint32_t near_late = 0;
    uint32_t errors = 0;
    double   sum_ms = 0.0;
    uint32_t timed_hits = 0;
};

struct SummaryStats {
    uint32_t total_ticks = 0;
    uint32_t judged_ticks = 0;
    uint32_t total_chips = 0;
    uint32_t judged_chips = 0;

    uint32_t s_crit_chip = 0;
    uint32_t s_crit_hold = 0;
    uint32_t crit_early = 0;
    uint32_t crit_late = 0;
    uint32_t near_early = 0;
    uint32_t near_late = 0;
    uint32_t error_early = 0;
    uint32_t error_late = 0;
    uint32_t error_miss = 0;

    uint32_t total_early = 0;
    uint32_t total_late = 0;

    double   mean_ms = 0.0;
    double   stddev_ms = 0.0;
    float    min_ms = 0.0f;
    float    max_ms = 0.0f;
    uint32_t timed_hits = 0;

    static constexpr int HIST_BINS = 41;
    static constexpr float HIST_MIN_MS = -61.5f;
    static constexpr float HIST_MAX_MS = +61.5f;
    uint32_t hist[HIST_BINS] = {};
    uint32_t hist_max_count = 1;

    LaneStats lanes[8] = {};
};

struct VoxHoldSpan {
    int   lane = 0;
    float start_sec = 0.0f;
    float end_sec = 0.0f;
};

struct VoxLaserSeg {
    int   laser_idx = 0;
    float start_sec = 0.0f;
    float end_sec = 0.0f;
    float start_pos = 0.0f;
    float end_pos = 0.0f;
    bool  wide = false;
};

struct VoxChartInfo {
    std::string virtual_path;
    std::string disk_path;
    std::string song_code;
    std::string diff_label;
    int         beat_resolution = 480;
    int         end_measure = 1;
    float       duration_sec = 10.0f;
    float       initial_bpm = 120.0f;
    float       min_bpm = 120.0f;
    float       max_bpm = 120.0f;
    std::vector<float>        measure_times;
    std::vector<BpmEvent>     bpm_events;
    std::vector<TimeSigEvent> timesig_events;
    std::vector<VoxHoldSpan>  holds;
    std::vector<VoxLaserSeg>  lasers;
};

static std::string resolve_vox_disk_path(const std::string& vpath) {
    if (vpath.empty()) return "";
    std::string rel = vpath;
    while (!rel.empty() && (rel.front() == '/' || rel.front() == '\\')) {
        rel.erase(rel.begin());
    }
    for (char& c : rel) {
        if (c == '/') c = '\\';
    }
    std::string base = get_game_dir();

    std::vector<std::string> candidates;
    if (rel.rfind("data\\", 0) == 0) {
        std::string sub = rel.substr(5);
        candidates.push_back(base + "\\data_mods\\" + sub);
        candidates.push_back(base + "\\plus\\" + sub);
        candidates.push_back(base + "\\contents\\data\\" + sub);
    }
    candidates.push_back(base + "\\" + rel);
    candidates.push_back(base + "\\contents\\" + rel);

    for (const auto& c : candidates) {
        DWORD attr = GetFileAttributesA(c.c_str());
        if (attr != INVALID_FILE_ATTRIBUTES && !(attr & FILE_ATTRIBUTE_DIRECTORY)) {
            return c;
        }
    }
    return candidates.front();
}

static void parse_vox_chart(const std::string& vpath, float fallback_end_sec, VoxChartInfo& out) {
    out = VoxChartInfo{};
    out.virtual_path = vpath;
    out.disk_path = resolve_vox_disk_path(vpath);
    out.duration_sec = std::max(fallback_end_sec, 10.0f);

    size_t slash = vpath.find_last_of("/\\");
    std::string fname = (slash != std::string::npos) ? vpath.substr(slash + 1) : vpath;
    size_t dot = fname.find_last_of('.');
    if (dot != std::string::npos) fname = fname.substr(0, dot);

    out.diff_label = "CHART";
    if (fname.size() > 3 && fname[fname.size() - 3] == '_') {
        std::string dc = fname.substr(fname.size() - 2);
        fname = fname.substr(0, fname.size() - 3);
        if (dc == "1n") out.diff_label = "NOVICE";
        else if (dc == "2a") out.diff_label = "ADVANCED";
        else if (dc == "3e") out.diff_label = "EXHAUST";
        else if (dc == "4i") out.diff_label = "INFINITE";
        else if (dc == "5m") out.diff_label = "MAXIMUM";
        else if (dc == "6u") out.diff_label = "ULTIMATE";
        else out.diff_label = dc;
    }
    out.song_code = fname;

    std::ifstream ifs(out.disk_path);
    if (!ifs.is_open()) {
        int num_m = std::max(1, static_cast<int>(std::ceil(out.duration_sec / 2.0f)));
        out.end_measure = num_m;
        out.measure_times.resize(num_m + 1);
        for (int i = 0; i <= num_m; ++i) out.measure_times[i] = i * 2.0f;
        out.bpm_events.push_back({1, 1, 0, 0.0f, 120.0f});
        return;
    }

    enum Section {
        SEC_NONE, SEC_BEAT_RES, SEC_BEAT_INFO, SEC_BPM_INFO, SEC_END_POS,
        SEC_TRACK1, SEC_TRACK2, SEC_TRACK3, SEC_TRACK4, SEC_TRACK5, SEC_TRACK6, SEC_TRACK7, SEC_TRACK8
    };
    Section cur_sec = SEC_NONE;

    struct RawBpm { int m, b, o; float bpm; };
    struct RawHold { int lane, m, b, o, dur; };
    struct RawLaserNode { int laser_idx, m, b, o; float pos; int node_type; int wide; };

    std::vector<RawBpm> raw_bpms;
    std::vector<RawHold> raw_holds;
    std::vector<RawLaserNode> raw_lasers[2];

    std::string line;
    while (std::getline(ifs, line)) {
        while (!line.empty() && (line.back() == '\r' || line.back() == '\n' || line.back() == ' ' || line.back() == '\t'))
            line.pop_back();
        size_t first = line.find_first_not_of(" \t");
        if (first == std::string::npos) continue;
        std::string s = line.substr(first);
        if (s.rfind("//", 0) == 0) continue;

        if (s[0] == '#') {
            if (s.rfind("#BEAT RESOLUTION", 0) == 0) cur_sec = SEC_BEAT_RES;
            else if (s.rfind("#BEAT INFO", 0) == 0) cur_sec = SEC_BEAT_INFO;
            else if (s.rfind("#BPM INFO", 0) == 0) cur_sec = SEC_BPM_INFO;
            else if (s.rfind("#END POSITION", 0) == 0) cur_sec = SEC_END_POS;
            else if (s.rfind("#TRACK1", 0) == 0) cur_sec = SEC_TRACK1;
            else if (s.rfind("#TRACK2", 0) == 0) cur_sec = SEC_TRACK2;
            else if (s.rfind("#TRACK3", 0) == 0) cur_sec = SEC_TRACK3;
            else if (s.rfind("#TRACK4", 0) == 0) cur_sec = SEC_TRACK4;
            else if (s.rfind("#TRACK5", 0) == 0) cur_sec = SEC_TRACK5;
            else if (s.rfind("#TRACK6", 0) == 0) cur_sec = SEC_TRACK6;
            else if (s.rfind("#TRACK7", 0) == 0) cur_sec = SEC_TRACK7;
            else if (s.rfind("#TRACK8", 0) == 0) cur_sec = SEC_TRACK8;
            else if (s.rfind("#END", 0) == 0) cur_sec = SEC_NONE;
            else cur_sec = SEC_NONE;
            continue;
        }

        if (cur_sec == SEC_BEAT_RES) {
            int r = std::atoi(s.c_str());
            if (r > 0) out.beat_resolution = r;
        } else if (cur_sec == SEC_BEAT_INFO) {
            int m = 1, b = 1, o = 0, num = 4, den = 4;
            if (std::sscanf(s.c_str(), "%d,%d,%d %d %d", &m, &b, &o, &num, &den) >= 5) {
                if (m >= 1 && num >= 1 && den >= 1) {
                    out.timesig_events.push_back({m, num, den});
                }
            }
        } else if (cur_sec == SEC_BPM_INFO) {
            int m = 1, b = 1, o = 0;
            float bpm = 120.0f;
            if (std::sscanf(s.c_str(), "%d,%d,%d %f", &m, &b, &o, &bpm) >= 4) {
                if (m >= 1 && bpm > 1.0f && bpm < 10000.0f) {
                    raw_bpms.push_back({m, b, o, bpm});
                }
            }
        } else if (cur_sec == SEC_END_POS) {
            int m = 1, b = 1, o = 0;
            if (std::sscanf(s.c_str(), "%d,%d,%d", &m, &b, &o) >= 1) {
                if (m >= 1) out.end_measure = std::max(out.end_measure, m);
            }
        } else if (cur_sec == SEC_TRACK1 || cur_sec == SEC_TRACK8) {
            int m = 1, b = 1, o = 0, ntype = 0, spin = 0, filt = 0, wide = 1;
            float pos = 0.0f;
            if (std::sscanf(s.c_str(), "%d,%d,%d %f %d %d %d %d", &m, &b, &o, &pos, &ntype, &spin, &filt, &wide) >= 5) {
                int lidx = (cur_sec == SEC_TRACK1) ? 0 : 1;
                raw_lasers[lidx].push_back({lidx, m, b, o, std::clamp(pos, 0.0f, 1.0f), ntype, wide});
            }
        } else if (cur_sec >= SEC_TRACK2 && cur_sec <= SEC_TRACK7) {
            int m = 1, b = 1, o = 0, dur = 0, kind = 0;
            if (std::sscanf(s.c_str(), "%d,%d,%d %d %d", &m, &b, &o, &dur, &kind) >= 4) {
                int lane = 0;
                if (cur_sec == SEC_TRACK2) lane = 4;
                else if (cur_sec == SEC_TRACK7) lane = 5;
                else lane = static_cast<int>(cur_sec - SEC_TRACK3);
                if (dur > 0) {
                    raw_holds.push_back({lane, m, b, o, dur});
                }
            }
        }
    }

    if (out.timesig_events.empty()) {
        out.timesig_events.push_back({1, 4, 4});
    }
    std::sort(out.timesig_events.begin(), out.timesig_events.end(),
              [](const TimeSigEvent& a, const TimeSigEvent& b) { return a.measure < b.measure; });

    if (raw_bpms.empty()) {
        raw_bpms.push_back({1, 1, 0, 120.0f});
    }

    int max_m = std::max(out.end_measure + 4, 150);
    for (const auto& rb : raw_bpms) max_m = std::max(max_m, rb.m + 2);
    for (const auto& rh : raw_holds) max_m = std::max(max_m, rh.m + 8);
    for (int l = 0; l < 2; ++l) {
        for (const auto& rl : raw_lasers[l]) max_m = std::max(max_m, rl.m + 4);
    }

    std::vector<int64_t> measure_start_tick(max_m + 2, 0);
    std::vector<std::pair<int, int>> measure_sig(max_m + 2, {4, 4});

    size_t ts_idx = 0;
    int cur_num = out.timesig_events[0].num;
    int cur_den = out.timesig_events[0].den;

    int64_t accum_ticks = 0;
    for (int m = 1; m <= max_m + 1; ++m) {
        while (ts_idx < out.timesig_events.size() && out.timesig_events[ts_idx].measure <= m) {
            cur_num = out.timesig_events[ts_idx].num;
            cur_den = out.timesig_events[ts_idx].den;
            ++ts_idx;
        }
        measure_sig[m] = {cur_num, cur_den};
        measure_start_tick[m] = accum_ticks;
        int64_t m_ticks = static_cast<int64_t>(out.beat_resolution) * 4 * cur_num / std::max(1, cur_den);
        if (m_ticks <= 0) m_ticks = out.beat_resolution * 4;
        accum_ticks += m_ticks;
    }

    struct TickBpm {
        int64_t tick;
        int m, b, o;
        float bpm;
    };
    std::vector<TickBpm> tick_bpms;
    for (const auto& rb : raw_bpms) {
        int m = std::clamp(rb.m, 1, max_m);
        int den = std::max(1, measure_sig[m].second);
        int64_t beat_ticks = static_cast<int64_t>(out.beat_resolution) * 4 / den;
        int64_t t = measure_start_tick[m] + static_cast<int64_t>(rb.b - 1) * beat_ticks + rb.o;
        tick_bpms.push_back({std::max<int64_t>(0, t), rb.m, rb.b, rb.o, rb.bpm});
    }
    std::sort(tick_bpms.begin(), tick_bpms.end(),
              [](const TickBpm& a, const TickBpm& b) { return a.tick < b.tick; });

    auto tick_to_seconds = [&](int64_t target_tick) -> float {
        double sec = 0.0;
        int64_t cur_t = 0;
        float cur_bpm = tick_bpms[0].bpm;
        for (size_t i = 0; i < tick_bpms.size(); ++i) {
            int64_t evt_t = tick_bpms[i].tick;
            if (evt_t >= target_tick) break;
            if (evt_t > cur_t) {
                double beats = static_cast<double>(evt_t - cur_t) / static_cast<double>(out.beat_resolution);
                sec += beats * (60.0 / static_cast<double>(cur_bpm));
                cur_t = evt_t;
            }
            cur_bpm = tick_bpms[i].bpm;
        }
        if (target_tick > cur_t) {
            double beats = static_cast<double>(target_tick - cur_t) / static_cast<double>(out.beat_resolution);
            sec += beats * (60.0 / static_cast<double>(cur_bpm));
        }
        return static_cast<float>(sec);
    };

    out.initial_bpm = tick_bpms[0].bpm;
    out.min_bpm = tick_bpms[0].bpm;
    out.max_bpm = tick_bpms[0].bpm;
    out.bpm_events.clear();
    for (const auto& tb : tick_bpms) {
        float t_sec = tick_to_seconds(tb.tick);
        out.bpm_events.push_back({tb.m, tb.b, tb.o, t_sec, tb.bpm});
        out.min_bpm = std::min(out.min_bpm, tb.bpm);
        out.max_bpm = std::max(out.max_bpm, tb.bpm);
    }

    out.measure_times.resize(max_m + 1, 0.0f);
    for (int m = 1; m <= max_m + 1; ++m) {
        out.measure_times[m - 1] = tick_to_seconds(measure_start_tick[m]);
    }

    float end_pos_sec = out.measure_times[std::min(out.end_measure, max_m)];
    out.duration_sec = std::max(fallback_end_sec, end_pos_sec);
    for (int m = 1; m <= max_m; ++m) {
        if (out.measure_times[m - 1] <= out.duration_sec + 0.5f) {
            out.end_measure = std::max(out.end_measure, m);
        }
    }
    if (out.end_measure < static_cast<int>(out.measure_times.size()) - 1) {
        out.measure_times.resize(out.end_measure + 1);
    }

    auto mbo_to_tick = [&](int m, int b, int o) -> int64_t {
        int cm = std::clamp(m, 1, max_m);
        int den = std::max(1, measure_sig[cm].second);
        int64_t beat_ticks = static_cast<int64_t>(out.beat_resolution) * 4 / den;
        return std::max<int64_t>(0, measure_start_tick[cm] + static_cast<int64_t>(b - 1) * beat_ticks + o);
    };

    out.holds.reserve(raw_holds.size());
    for (const auto& rh : raw_holds) {
        int64_t t0 = mbo_to_tick(rh.m, rh.b, rh.o);
        int64_t t1 = t0 + rh.dur;
        out.holds.push_back({rh.lane, tick_to_seconds(t0), tick_to_seconds(t1)});
    }

    for (int l = 0; l < 2; ++l) {
        bool in_chain = false;
        float prev_sec = 0.0f;
        float prev_pos = 0.0f;
        bool prev_wide = false;
        for (const auto& rn : raw_lasers[l]) {
            int64_t t = mbo_to_tick(rn.m, rn.b, rn.o);
            float sec = tick_to_seconds(t);
            bool is_wide = (rn.wide >= 2);
            if (rn.node_type == 1) {
                in_chain = true;
                prev_sec = sec;
                prev_pos = rn.pos;
                prev_wide = is_wide;
            } else if (in_chain) {
                out.lasers.push_back({l, prev_sec, std::max(prev_sec, sec), prev_pos, rn.pos, prev_wide || is_wide});
                prev_sec = sec;
                prev_pos = rn.pos;
                prev_wide = is_wide;
                if (rn.node_type == 2) {
                    in_chain = false;
                }
            }
        }
    }
}

static float get_laser_pos_at_time(const VoxChartInfo& vox, int laser_idx, float t) {
    float best_pos = (laser_idx == 0) ? 0.0f : 1.0f;
    float best_dist = 1e9f;
    for (const auto& seg : vox.lasers) {
        if (seg.laser_idx != laser_idx) continue;
        if (t >= seg.start_sec - 0.02f && t <= seg.end_sec + 0.02f) {
            float span = seg.end_sec - seg.start_sec;
            if (span <= 0.0005f) return seg.end_pos;
            float u = std::clamp((t - seg.start_sec) / span, 0.0f, 1.0f);
            return seg.start_pos + u * (seg.end_pos - seg.start_pos);
        }
        float d = (t < seg.start_sec) ? (seg.start_sec - t) : (t - seg.end_sec);
        if (d < best_dist) {
            best_dist = d;
            best_pos = (t < seg.start_sec) ? seg.start_pos : seg.end_pos;
        }
    }
    return best_pos;
}

struct TrackerState {
    std::mutex mutex;

    void*     last_world = nullptr;
    void*     last_fumen_sub = nullptr;
    void*     last_referee = nullptr;
    uintptr_t last_vec_begin = 0;
    uintptr_t last_vec_end = 0;
    uintptr_t last_first_note = 0;
    bool      in_gameplay = false;
    bool      in_result_scene = false;
    uint64_t  last_world_update_tick = 0;
    float     current_time_sec = 0.0f;
    float     chart_end_sec = 120.0f;
    float     progress = 0.0f;

    VoxChartInfo                         vox;
    std::vector<TrackedTick>             ticks;
    std::unordered_map<uint64_t, size_t> tick_lookup;
    std::vector<ChartSection>            sections;
    SummaryStats                         stats;

    int  measures_per_section = 8;
    bool split_on_bpm_change = true;
};

static TrackerState g_state;

struct UiSettings {
    bool  show_live_hud = true;
    bool  show_live_recent_strip = true;
    bool  show_hold_ticks_on_timeline = false;
    bool  auto_show_on_result = true;
    bool  manual_report_open = false;
    bool  lock_live_hud = false;
    bool  invert_early_late_axis = false;
    float timeline_range_ms = 50.0f;
    int   filter_mode = 0;
    int   selected_section = -1;
    int   selected_tick_idx = -1;
    float preview_center_sec = 0.0f;
    float preview_window_sec = 3.0f;
    int   mistake_filter = 0;
    bool  request_preview_tab = false;
    std::string last_export_status;
    int   vk_toggle_report = VK_F3;
    int   vk_toggle_live_hud = VK_OEM_MINUS;
    int   rebind_target = 0;
};

static UiSettings g_ui;

static const char* key_name_for_vk(int vk) {
    static char buf[32];
    switch (vk) {
        case VK_F1: return "F1";
        case VK_F2: return "F2";
        case VK_F3: return "F3";
        case VK_F4: return "F4";
        case VK_F5: return "F5";
        case VK_F6: return "F6";
        case VK_F7: return "F7";
        case VK_F8: return "F8";
        case VK_F9: return "F9";
        case VK_F10: return "F10";
        case VK_F11: return "F11";
        case VK_F12: return "F12";
        case VK_OEM_MINUS: return "- (Minus)";
        case VK_OEM_PLUS: return "= (Plus)";
        case VK_OEM_4: return "[";
        case VK_OEM_6: return "]";
        case VK_OEM_5: return "\\";
        case VK_OEM_1: return ";";
        case VK_OEM_7: return "'";
        case VK_OEM_COMMA: return ",";
        case VK_OEM_PERIOD: return ".";
        case VK_OEM_2: return "/";
        case VK_BACK: return "Backspace";
        case VK_PAUSE: return "Pause";
        case VK_SCROLL: return "ScrollLock";
        case VK_NUMPAD0: return "Num0";
        case VK_NUMPAD1: return "Num1";
        case VK_NUMPAD2: return "Num2";
        case VK_NUMPAD3: return "Num3";
        case VK_NUMPAD4: return "Num4";
        case VK_NUMPAD5: return "Num5";
        case VK_NUMPAD6: return "Num6";
        case VK_NUMPAD7: return "Num7";
        case VK_NUMPAD8: return "Num8";
        case VK_NUMPAD9: return "Num9";
        case VK_MULTIPLY: return "Num*";
        case VK_ADD: return "Num+";
        case VK_SUBTRACT: return "Num-";
        case VK_DECIMAL: return "Num.";
        case VK_DIVIDE: return "Num/";
        default:
            if ((vk >= '0' && vk <= '9') || (vk >= 'A' && vk <= 'Z')) {
                snprintf(buf, sizeof(buf), "%c", static_cast<char>(vk));
                return buf;
            }
            snprintf(buf, sizeof(buf), "VK_0x%02X", vk);
            return buf;
    }
}

static void save_config() {
    std::string p = get_game_dir() + "\\sdvx_accuracy_config.ini";
    FILE* f = fopen(p.c_str(), "w");
    if (!f) return;
    fprintf(f, "vk_toggle_report=%d\n", g_ui.vk_toggle_report);
    fprintf(f, "vk_toggle_live_hud=%d\n", g_ui.vk_toggle_live_hud);
    fprintf(f, "show_live_hud=%d\n", g_ui.show_live_hud ? 1 : 0);
    fprintf(f, "show_live_recent_strip=%d\n", g_ui.show_live_recent_strip ? 1 : 0);
    fprintf(f, "lock_live_hud=%d\n", g_ui.lock_live_hud ? 1 : 0);
    fprintf(f, "auto_show_on_result=%d\n", g_ui.auto_show_on_result ? 1 : 0);
    fprintf(f, "show_hold_ticks_on_timeline=%d\n", g_ui.show_hold_ticks_on_timeline ? 1 : 0);
    fprintf(f, "invert_early_late_axis=%d\n", g_ui.invert_early_late_axis ? 1 : 0);
    fprintf(f, "timeline_range_ms=%.1f\n", g_ui.timeline_range_ms);
    fclose(f);
}

static void load_config() {
    std::string p = get_game_dir() + "\\sdvx_accuracy_config.ini";
    std::ifstream ifs(p);
    if (!ifs.is_open()) return;
    std::string line;
    while (std::getline(ifs, line)) {
        size_t eq = line.find('=');
        if (eq == std::string::npos) continue;
        std::string k = line.substr(0, eq);
        std::string v = line.substr(eq + 1);
        int iv = std::atoi(v.c_str());
        if (k == "vk_toggle_report" && iv > 0 && iv < 256) g_ui.vk_toggle_report = iv;
        else if (k == "vk_toggle_live_hud" && iv > 0 && iv < 256) g_ui.vk_toggle_live_hud = iv;
        else if (k == "show_live_hud") g_ui.show_live_hud = (iv != 0);
        else if (k == "show_live_recent_strip") g_ui.show_live_recent_strip = (iv != 0);
        else if (k == "lock_live_hud") g_ui.lock_live_hud = (iv != 0);
        else if (k == "auto_show_on_result") g_ui.auto_show_on_result = (iv != 0);
        else if (k == "show_hold_ticks_on_timeline") g_ui.show_hold_ticks_on_timeline = (iv != 0);
        else if (k == "invert_early_late_axis") g_ui.invert_early_late_axis = (iv != 0);
        else if (k == "timeline_range_ms") {
            float fv = static_cast<float>(std::atof(v.c_str()));
            if (fv >= 20.0f && fv <= 120.0f) g_ui.timeline_range_ms = fv;
        }
    }
}

static float get_bpm_at_time(const VoxChartInfo& vox, float t) {
    float bpm = vox.initial_bpm;
    for (const auto& e : vox.bpm_events) {
        if (e.time_sec <= t + 0.005f) bpm = e.bpm;
        else break;
    }
    return bpm;
}

static int get_measure_at_time(const VoxChartInfo& vox, float t) {
    if (vox.measure_times.empty()) return 1;
    auto it = std::upper_bound(vox.measure_times.begin(), vox.measure_times.end(), t + 0.002f);
    int idx = static_cast<int>(it - vox.measure_times.begin()) - 1;
    return std::clamp(idx + 1, 1, std::max(1, vox.end_measure));
}

static void rebuild_sections_locked() {
    g_state.sections.clear();
    const auto& vox = g_state.vox;
    int total_m = std::max(1, vox.end_measure);
    int step = std::clamp(g_state.measures_per_section, 2, 32);

    std::vector<bool> bpm_split_measure(total_m + 2, false);
    if (g_state.split_on_bpm_change && vox.bpm_events.size() > 1) {
        float prev_bpm = vox.bpm_events[0].bpm;
        for (size_t i = 1; i < vox.bpm_events.size(); ++i) {
            int m = vox.bpm_events[i].measure;
            float b = vox.bpm_events[i].bpm;
            if (m > 1 && m <= total_m && std::fabs(b - prev_bpm) >= 5.0f) {
                bpm_split_measure[m] = true;
                prev_bpm = b;
            }
        }
    }

    int cur_start = 1;
    int sec_idx = 0;
    while (cur_start <= total_m) {
        int cur_end = std::min(total_m, cur_start + step - 1);
        for (int m = cur_start + 2; m <= cur_end; ++m) {
            if (bpm_split_measure[m]) {
                cur_end = m - 1;
                break;
            }
        }

        ChartSection sec{};
        sec.index = sec_idx++;
        sec.start_measure = cur_start;
        sec.end_measure = cur_end;
        sec.start_time = (cur_start - 1 < static_cast<int>(vox.measure_times.size()))
                             ? vox.measure_times[cur_start - 1]
                             : 0.0f;
        sec.end_time = (cur_end < static_cast<int>(vox.measure_times.size()))
                           ? vox.measure_times[cur_end]
                           : g_state.chart_end_sec;
        if (cur_end == total_m) {
            sec.end_time = std::max(sec.end_time, g_state.chart_end_sec);
        }
        sec.bpm = get_bpm_at_time(vox, sec.start_time);

        char buf[64];
        snprintf(buf, sizeof(buf), "M%d - M%d", sec.start_measure, sec.end_measure);
        sec.label = buf;

        g_state.sections.push_back(sec);
        cur_start = cur_end + 1;
    }

    if (g_state.sections.empty()) {
        ChartSection sec{};
        sec.index = 0;
        sec.start_measure = 1;
        sec.end_measure = total_m;
        sec.start_time = 0.0f;
        sec.end_time = g_state.chart_end_sec;
        sec.bpm = vox.initial_bpm;
        sec.label = "M1 - End";
        g_state.sections.push_back(sec);
    }

    for (auto& tk : g_state.ticks) {
        tk.measure = get_measure_at_time(vox, tk.target_time);
        int s_idx = 0;
        for (size_t i = 0; i < g_state.sections.size(); ++i) {
            if (tk.measure >= g_state.sections[i].start_measure &&
                tk.measure <= g_state.sections[i].end_measure) {
                s_idx = static_cast<int>(i);
                break;
            }
            if (tk.target_time >= g_state.sections[i].start_time) {
                s_idx = static_cast<int>(i);
            }
        }
        tk.section_idx = s_idx;
    }
}

static void recompute_stats_locked() {
    SummaryStats st{};
    st.total_ticks = static_cast<uint32_t>(g_state.ticks.size());

    for (auto& sec : g_state.sections) {
        sec.total_ticks = 0;
        sec.judged_ticks = 0;
        sec.chip_notes = 0;
        sec.s_crit = 0;
        sec.hold_crit = 0;
        sec.crit_early = 0;
        sec.crit_late = 0;
        sec.near_early = 0;
        sec.near_late = 0;
        sec.error_early = 0;
        sec.error_late = 0;
        sec.error_miss = 0;
        sec.sum_delta_ms = 0.0;
        sec.timed_hits = 0;
    }

    double sum_ms = 0.0;
    double sum_sq_ms = 0.0;

    for (const auto& tk : g_state.ticks) {
        bool chip = tk.is_chip();
        int u_lane = tk.unified_lane();
        st.lanes[u_lane].total++;

        if (chip) st.total_chips++;

        ChartSection* sec = (tk.section_idx >= 0 && tk.section_idx < static_cast<int>(g_state.sections.size()))
                                ? &g_state.sections[tk.section_idx]
                                : nullptr;
        if (sec) {
            sec->total_ticks++;
            if (chip) sec->chip_notes++;
        }

        if (tk.grade == 0) continue;

        st.judged_ticks++;
        st.lanes[u_lane].judged++;
        if (chip) st.judged_chips++;
        if (sec) sec->judged_ticks++;

        switch (static_cast<JudgeGrade>(tk.grade)) {
            case JudgeGrade::ErrorEarly:
                st.error_early++;
                st.total_early++;
                st.lanes[u_lane].errors++;
                if (sec) sec->error_early++;
                break;
            case JudgeGrade::NearEarly:
                st.near_early++;
                st.total_early++;
                st.lanes[u_lane].near_early++;
                if (sec) sec->near_early++;
                break;
            case JudgeGrade::CritEarly:
                st.crit_early++;
                st.total_early++;
                st.lanes[u_lane].crit_early++;
                if (sec) sec->crit_early++;
                break;
            case JudgeGrade::SCritEarly:
                st.s_crit_chip++;
                st.total_early++;
                st.lanes[u_lane].s_crit++;
                if (sec) sec->s_crit++;
                break;
            case JudgeGrade::HoldCrit:
                st.s_crit_hold++;
                st.lanes[u_lane].s_crit++;
                if (sec) sec->hold_crit++;
                break;
            case JudgeGrade::SCritLate:
                st.s_crit_chip++;
                st.total_late++;
                st.lanes[u_lane].s_crit++;
                if (sec) sec->s_crit++;
                break;
            case JudgeGrade::CritLate:
                st.crit_late++;
                st.total_late++;
                st.lanes[u_lane].crit_late++;
                if (sec) sec->crit_late++;
                break;
            case JudgeGrade::NearLate:
                st.near_late++;
                st.total_late++;
                st.lanes[u_lane].near_late++;
                if (sec) sec->near_late++;
                break;
            case JudgeGrade::ErrorLate:
                st.error_late++;
                st.total_late++;
                st.lanes[u_lane].errors++;
                if (sec) sec->error_late++;
                break;
            case JudgeGrade::ErrorTimeout:
                st.error_miss++;
                st.lanes[u_lane].errors++;
                if (sec) sec->error_miss++;
                break;
            default:
                break;
        }

        if (tk.has_timing_offset()) {
            float ms = tk.delta_ms;
            sum_ms += ms;
            sum_sq_ms += static_cast<double>(ms) * static_cast<double>(ms);
            if (st.timed_hits == 0) {
                st.min_ms = ms;
                st.max_ms = ms;
            } else {
                st.min_ms = std::min(st.min_ms, ms);
                st.max_ms = std::max(st.max_ms, ms);
            }
            st.timed_hits++;

            st.lanes[u_lane].sum_ms += ms;
            st.lanes[u_lane].timed_hits++;

            if (sec) {
                sec->sum_delta_ms += ms;
                sec->timed_hits++;
            }

            float norm = (ms - SummaryStats::HIST_MIN_MS) /
                         (SummaryStats::HIST_MAX_MS - SummaryStats::HIST_MIN_MS);
            int bin = static_cast<int>(norm * SummaryStats::HIST_BINS);
            bin = std::clamp(bin, 0, SummaryStats::HIST_BINS - 1);
            st.hist[bin]++;
            st.hist_max_count = std::max(st.hist_max_count, st.hist[bin]);
        }
    }

    if (st.timed_hits > 0) {
        st.mean_ms = sum_ms / static_cast<double>(st.timed_hits);
        double var = (sum_sq_ms / static_cast<double>(st.timed_hits)) - (st.mean_ms * st.mean_ms);
        st.stddev_ms = (var > 0.0) ? std::sqrt(var) : 0.0;
    }

    g_state.stats = st;
}

static ModuleLayout g_sdvx_mod = {};
static size_t       g_vox_offset = 0x410;
static size_t       g_referee_now_offset = 0x118;
static size_t       g_world_fumen_offset = 0xC8;
static size_t       g_world_timer_offset = 0xD8;
static uintptr_t    g_referee_vftable = 0;
static uintptr_t    g_fumen_vftable = 0;
static uintptr_t    g_timer_vftable = 0;

static size_t resolve_referee_now_offset(const ModuleLayout& mod, uintptr_t referee_vftable) {
    const size_t default_off = 0x118;
    if (!referee_vftable || !is_readable(reinterpret_cast<const void*>(referee_vftable + 8), 8))
        return default_off;
    uintptr_t fn1 = *reinterpret_cast<const uintptr_t*>(referee_vftable + 8);
    if (fn1 < mod.text.start || fn1 + 0x100 > mod.text.end) return default_off;

    const uint8_t* code = reinterpret_cast<const uint8_t*>(fn1);
    for (size_t i = 0; i + 12 < 0xA0; ++i) {
        if (code[i] == 0x8B && (code[i + 1] & 0xC0) == 0x80 &&
            code[i + 6] == 0x89 && (code[i + 7] & 0xC0) == 0x80) {
            uint32_t d1 = *reinterpret_cast<const uint32_t*>(code + i + 2);
            uint32_t d2 = *reinterpret_cast<const uint32_t*>(code + i + 8);
            if (d1 >= 0x80 && d1 <= 0x300 && d2 + 4 == d1) {
                return static_cast<size_t>(d1);
            }
        }
    }
    return default_off;
}

static bool is_class_instance(const void* ptr, uintptr_t expected_vft, const char* mangled_name) {
    if (!is_readable(ptr, 16)) return false;
    uintptr_t vft = *reinterpret_cast<const uintptr_t*>(ptr);
    if (expected_vft && vft == expected_vft) return true;
    return get_rtti_class_name(ptr, g_sdvx_mod) == mangled_name;
}

static void* find_world_member(void* world, size_t& cached_off, uintptr_t expected_vft, const char* mangled_name) {
    void* cand = nullptr;
    if (safe_read(reinterpret_cast<const uint8_t*>(world) + cached_off, cand) &&
        is_class_instance(cand, expected_vft, mangled_name)) {
        return cand;
    }
    for (size_t off = 0x40; off <= 0x240; off += 8) {
        if (safe_read(reinterpret_cast<const uint8_t*>(world) + off, cand) &&
            is_class_instance(cand, expected_vft, mangled_name)) {
            cached_off = off;
            return cand;
        }
    }
    return nullptr;
}

static bool is_note_referee_obj(const void* ptr) {
    return is_class_instance(ptr, g_referee_vftable, ".?AVNoteReferee@Game@@");
}

static void find_fumen_sub_and_referee(void* fumen, void*& out_fumen_sub, void*& out_referee) {
    out_fumen_sub = nullptr;
    out_referee = nullptr;
    if (!fumen || !is_readable(fumen, 0x80)) return;

    void* sub18 = nullptr;
    if (safe_read(reinterpret_cast<const uint8_t*>(fumen) + 0x18, sub18) && is_readable(sub18, 0x180)) {
        out_fumen_sub = sub18;
        void* ref160 = nullptr;
        if (safe_read(reinterpret_cast<const uint8_t*>(sub18) + 0x160, ref160) && is_note_referee_obj(ref160)) {
            out_referee = ref160;
            return;
        }
        for (size_t off2 = 0; off2 < 0x200; off2 += 8) {
            void* cand = nullptr;
            if (safe_read(reinterpret_cast<const uint8_t*>(sub18) + off2, cand) && is_note_referee_obj(cand)) {
                out_referee = cand;
                return;
            }
        }
    }

    for (size_t off1 = 0x08; off1 <= 0x78; off1 += 8) {
        void* sub = nullptr;
        if (!safe_read(reinterpret_cast<const uint8_t*>(fumen) + off1, sub) || !is_readable(sub, 0x200))
            continue;
        for (size_t off2 = 0; off2 < 0x200; off2 += 8) {
            void* cand = nullptr;
            if (safe_read(reinterpret_cast<const uint8_t*>(sub) + off2, cand) && is_note_referee_obj(cand)) {
                out_fumen_sub = sub;
                out_referee = cand;
                return;
            }
        }
    }
}

static void load_chart_and_notes_locked(
    void* world,
    void* fumen_sub,
    uintptr_t vec_begin,
    uintptr_t vec_end,
    uintptr_t first_note)
{
    g_state.last_world = world;
    g_state.last_fumen_sub = fumen_sub;
    g_state.last_vec_begin = vec_begin;
    g_state.last_vec_end = vec_end;
    g_state.last_first_note = first_note;
    g_state.ticks.clear();
    g_state.tick_lookup.clear();
    g_ui.selected_section = -1;
    g_ui.selected_tick_idx = -1;
    g_ui.preview_center_sec = 0.0f;
    g_ui.last_export_status.clear();

    float end_sec = 120.0f;
    safe_read(reinterpret_cast<const uint8_t*>(fumen_sub) + 0x170, end_sec);
    if (!(end_sec > 1.0f && end_sec < 3600.0f)) end_sec = 120.0f;

    std::string vpath = read_msvc_string(reinterpret_cast<const uint8_t*>(world) + g_vox_offset);
    log_msg("Loading chart: vox='%s', chart_end=%.2fs (vec=0x%llX..0x%llX)",
            vpath.c_str(), end_sec,
            static_cast<unsigned long long>(vec_begin),
            static_cast<unsigned long long>(vec_end));

    float max_note_time = 5.0f;

    if (vec_begin && vec_end >= vec_begin && (vec_end - vec_begin) <= 0x200000 && ((vec_end - vec_begin) % 16 == 0)) {
        size_t note_count = (vec_end - vec_begin) / 16;
        g_state.ticks.reserve(note_count * 2);

        for (size_t i = 0; i < note_count; ++i) {
            void* note_ptr = nullptr;
            if (!safe_read(reinterpret_cast<const void*>(vec_begin + i * 16), note_ptr) || !note_ptr) continue;
            if (!is_readable(note_ptr, 16)) continue;

            uintptr_t note_vft = 0;
            if (!safe_read(note_ptr, note_vft) || note_vft < g_sdvx_mod.rdata.start || note_vft >= g_sdvx_mod.rdata.end)
                continue;

            uintptr_t fn_get_id = 0;
            if (!safe_read(reinterpret_cast<const void*>(note_vft + 7 * 8), fn_get_id)) continue;
            if (fn_get_id < g_sdvx_mod.text.start || fn_get_id >= g_sdvx_mod.text.end) continue;

            auto get_id_fn = reinterpret_cast<uint32_t(__fastcall*)(void*)>(fn_get_id);
            uint32_t note_id = get_id_fn(note_ptr);

            void* judge_obj = reinterpret_cast<uint8_t*>(note_ptr) + 8;
            uintptr_t judge_vft = 0;
            if (!safe_read(judge_obj, judge_vft) || judge_vft < g_sdvx_mod.rdata.start || judge_vft >= g_sdvx_mod.rdata.end)
                continue;

            uintptr_t fn_get_ticks = 0;
            if (!safe_read(reinterpret_cast<const void*>(judge_vft + 2 * 8), fn_get_ticks)) continue;
            if (fn_get_ticks < g_sdvx_mod.text.start || fn_get_ticks >= g_sdvx_mod.text.end) continue;

            auto get_ticks_fn = reinterpret_cast<void*(__fastcall*)(void*)>(fn_get_ticks);
            void* ticks_vec = get_ticks_fn(judge_obj);
            if (!is_readable(ticks_vec, 24)) continue;

            uintptr_t t_begin = 0, t_end = 0;
            safe_read(reinterpret_cast<const uint8_t*>(ticks_vec) + 0x00, t_begin);
            safe_read(reinterpret_cast<const uint8_t*>(ticks_vec) + 0x08, t_end);
            if (!t_begin || t_end <= t_begin || (t_end - t_begin) > 0x100000 || ((t_end - t_begin) % 0x30 != 0))
                continue;

            size_t num_ticks = (t_end - t_begin) / 0x30;
            for (size_t t_idx = 0; t_idx < num_ticks; ++t_idx) {
                const uint8_t* tp = reinterpret_cast<const uint8_t*>(t_begin + t_idx * 0x30);
                if (!is_readable(tp, 0x30)) break;

                TrackedTick tk{};
                tk.note_id = note_id;
                tk.tick_index = static_cast<uint32_t>(t_idx);
                tk.target_time = *reinterpret_cast<const float*>(tp + 0x00);
                tk.lane = *reinterpret_cast<const uint32_t*>(tp + 0x18);
                tk.lane_type = *reinterpret_cast<const uint8_t*>(tp + 0x1C);
                tk.tick_kind = *reinterpret_cast<const uint32_t*>(tp + 0x20);
                tk.tick_kind_type = *reinterpret_cast<const uint8_t*>(tp + 0x24);

                if (std::isfinite(tk.target_time) && tk.target_time >= 0.0f && tk.target_time < 3600.0f) {
                    max_note_time = std::max(max_note_time, tk.target_time + 1.0f);
                    g_state.ticks.push_back(tk);
                }
            }
        }
    }

    std::stable_sort(g_state.ticks.begin(), g_state.ticks.end(),
                     [](const TrackedTick& a, const TrackedTick& b) {
                         if (std::fabs(a.target_time - b.target_time) > 0.0001f)
                             return a.target_time < b.target_time;
                         return a.unified_lane() < b.unified_lane();
                     });

    g_state.tick_lookup.reserve(g_state.ticks.size() * 2);
    for (size_t i = 0; i < g_state.ticks.size(); ++i) {
        uint64_t key = (static_cast<uint64_t>(g_state.ticks[i].note_id) << 32) |
                       static_cast<uint64_t>(g_state.ticks[i].tick_index);
        g_state.tick_lookup[key] = i;
    }

    if (max_note_time <= 5.5f) {
        max_note_time = end_sec;
    }
    g_state.chart_end_sec = max_note_time;
    parse_vox_chart(vpath, max_note_time, g_state.vox);
    g_state.chart_end_sec = std::max(max_note_time, g_state.vox.duration_sec);

    rebuild_sections_locked();
    recompute_stats_locked();

    log_msg("Loaded %zu note ticks (%u chips, %u holds/lasers) across %zu sections (%d measures, BPM %.1f..%.1f)",
            g_state.ticks.size(),
            g_state.stats.total_chips,
            g_state.stats.total_ticks - g_state.stats.total_chips,
            g_state.sections.size(),
            g_state.vox.end_measure, g_state.vox.min_bpm, g_state.vox.max_bpm);
}

static void sync_referee_judgements_locked(void* referee) {
    if (!referee || !is_readable(referee, 0x120)) return;

    if (referee != g_state.last_referee) {
        g_state.last_referee = referee;
        log_msg("Active NoteReferee found at %p", referee);
    }

    float ref_now = 0.0f;
    if (safe_read(reinterpret_cast<const uint8_t*>(referee) + g_referee_now_offset, ref_now) &&
        std::isfinite(ref_now) && ref_now > 0.0001f && ref_now < 3600.0f) {
        g_state.current_time_sec = ref_now;
    }

    uintptr_t head = 0;
    size_t count = 0;
    if (!safe_read(reinterpret_cast<const uint8_t*>(referee) + 0x10, head) ||
        !safe_read(reinterpret_cast<const uint8_t*>(referee) + 0x18, count)) {
        return;
    }
    if (!head || count == 0 || count > 20000 || !is_readable(reinterpret_cast<const void*>(head), 16)) {
        return;
    }

    uintptr_t node = 0;
    if (!safe_read(reinterpret_cast<const void*>(head), node)) return;

    size_t visited = 0;
    while (node && node != head && visited < count && visited < 20000) {
        if (!is_readable(reinterpret_cast<const void*>(node), 0x30)) break;

        uint32_t note_id = *reinterpret_cast<const uint32_t*>(node + 0x10);
        uintptr_t r_begin = *reinterpret_cast<const uintptr_t*>(node + 0x18);
        uintptr_t r_end   = *reinterpret_cast<const uintptr_t*>(node + 0x20);

        if (r_begin && r_end >= r_begin && (r_end - r_begin) <= 0x100000 &&
            ((r_end - r_begin) % sizeof(RawJudgeResult) == 0)) {
            size_t n_res = (r_end - r_begin) / sizeof(RawJudgeResult);
            const auto* results = reinterpret_cast<const RawJudgeResult*>(r_begin);
            if (is_readable(results, n_res * sizeof(RawJudgeResult))) {
                for (size_t i = 0; i < n_res; ++i) {
                    const RawJudgeResult& r = results[i];
                    uint64_t key = (static_cast<uint64_t>(note_id) << 32) | static_cast<uint64_t>(i);
                    auto it = g_state.tick_lookup.find(key);
                    if (it != g_state.tick_lookup.end()) {
                        TrackedTick& tk = g_state.ticks[it->second];
                        tk.grade = (r.grade <= 10) ? r.grade : 0;
                        tk.judge_time = r.judge_time;
                        tk.delta_ms = r.delta_sec * 1000.0f;
                    } else if (r.grade >= 1 && r.grade <= 10 &&
                               std::isfinite(r.judge_time) && std::isfinite(r.delta_sec)) {
                        TrackedTick tk{};
                        tk.note_id = note_id;
                        tk.tick_index = static_cast<uint32_t>(i);
                        tk.target_time = std::max(0.0f, r.judge_time - r.delta_sec);
                        tk.lane = r.lane;
                        tk.lane_type = r.lane_type;
                        tk.tick_kind = r.tick_kind;
                        tk.tick_kind_type = r.tick_kind_type;
                        tk.measure = get_measure_at_time(g_state.vox, tk.target_time);
                        tk.section_idx = 0;
                        for (size_t s = 0; s < g_state.sections.size(); ++s) {
                            if (tk.measure >= g_state.sections[s].start_measure &&
                                tk.measure <= g_state.sections[s].end_measure) {
                                tk.section_idx = static_cast<int>(s);
                                break;
                            }
                        }
                        tk.grade = r.grade;
                        tk.judge_time = r.judge_time;
                        tk.delta_ms = r.delta_sec * 1000.0f;
                        size_t new_idx = g_state.ticks.size();
                        g_state.ticks.push_back(tk);
                        g_state.tick_lookup[key] = new_idx;
                    }
                }
            }
        }

        node = *reinterpret_cast<const uintptr_t*>(node + 0x00);
        ++visited;
    }

    recompute_stats_locked();
}

using WorldUpdateFn   = void(__fastcall*)(void* world);
using WorldFinishedFn = bool(__fastcall*)(void* world);
using ResultAttachFn  = void*(__fastcall*)(void* scene, void* arg);
using ResultDetachFn  = void*(__fastcall*)(void* scene, void* arg);
using ResultUpdateFn  = void(__fastcall*)(void* scene, float dt);

static WorldUpdateFn   g_orig_world_update   = nullptr;
static WorldFinishedFn g_orig_world_finished = nullptr;
static ResultAttachFn  g_orig_result_attach  = nullptr;
static ResultDetachFn  g_orig_result_detach  = nullptr;
static ResultUpdateFn  g_orig_result_update  = nullptr;

static void __fastcall hk_world_update(void* world) {
    if (g_orig_world_update) {
        g_orig_world_update(world);
    }
    if (!world || !is_readable(world, 0x100)) return;

    float timer_sec = -1.0f;
    void* timer_obj = find_world_member(world, g_world_timer_offset, g_timer_vftable, ".?AVGameTimer@Game@@");
    if (timer_obj) {
        uintptr_t timer_vft = 0;
        uintptr_t fn_get_time = 0;
        if (safe_read(timer_obj, timer_vft) &&
            timer_vft >= g_sdvx_mod.rdata.start && timer_vft < g_sdvx_mod.rdata.end &&
            safe_read(reinterpret_cast<const void*>(timer_vft + 0x10), fn_get_time) &&
            fn_get_time >= g_sdvx_mod.text.start && fn_get_time < g_sdvx_mod.text.end) {
            auto get_time_fn = reinterpret_cast<float(__fastcall*)(void*)>(fn_get_time);
            float t = get_time_fn(timer_obj);
            if (std::isfinite(t) && t >= 0.0f && t < 3600.0f) {
                timer_sec = t;
            }
        }
    }

    void* fumen = find_world_member(world, g_world_fumen_offset, g_fumen_vftable, ".?AVGameFumenPlayer@Game@@");
    if (!fumen || !is_readable(fumen, 0x90)) return;

    void* fumen_sub = nullptr;
    void* referee = nullptr;
    find_fumen_sub_and_referee(fumen, fumen_sub, referee);
    if (!fumen_sub || !is_readable(fumen_sub, 0x180)) return;

    uintptr_t vec_begin = 0, vec_end = 0, first_note = 0;
    safe_read(reinterpret_cast<const uint8_t*>(fumen_sub) + 0x50, vec_begin);
    safe_read(reinterpret_cast<const uint8_t*>(fumen_sub) + 0x58, vec_end);
    if (vec_begin && vec_end > vec_begin && is_readable(reinterpret_cast<const void*>(vec_begin), 8)) {
        safe_read(reinterpret_cast<const void*>(vec_begin), first_note);
    }

    float progress = 0.0f;
    safe_read(reinterpret_cast<const uint8_t*>(fumen) + 0x80, progress);

    std::lock_guard<std::mutex> lock(g_state.mutex);
    g_state.in_gameplay = true;
    g_state.in_result_scene = false;
    g_state.last_world_update_tick = GetTickCount64();
    if (timer_sec >= 0.0f) {
        g_state.current_time_sec = timer_sec;
    }
    if (std::isfinite(progress)) {
        g_state.progress = std::clamp(progress, 0.0f, 1.0f);
    }

    if (world != g_state.last_world ||
        fumen_sub != g_state.last_fumen_sub ||
        vec_begin != g_state.last_vec_begin ||
        vec_end != g_state.last_vec_end ||
        first_note != g_state.last_first_note ||
        g_state.ticks.empty())
    {
        if (vec_begin && vec_end > vec_begin) {
            load_chart_and_notes_locked(world, fumen_sub, vec_begin, vec_end, first_note);
        }
    }

    if (referee) {
        sync_referee_judgements_locked(referee);
    }
}

static bool __fastcall hk_world_finished(void* world) {
    bool res = g_orig_world_finished ? g_orig_world_finished(world) : false;
    if (res) {
        std::lock_guard<std::mutex> lock(g_state.mutex);
        g_state.in_gameplay = false;
    }
    return res;
}

static void* __fastcall hk_result_attach(void* scene, void* arg) {
    void* res = g_orig_result_attach ? g_orig_result_attach(scene, arg) : nullptr;
    {
        std::lock_guard<std::mutex> lock(g_state.mutex);
        g_state.in_gameplay = false;
        g_state.in_result_scene = true;
    }
    log_msg("Entered Score / Result Screen (CResultScene::on_attach)");
    return res;
}

static void* __fastcall hk_result_detach(void* scene, void* arg) {
    {
        std::lock_guard<std::mutex> lock(g_state.mutex);
        g_state.in_result_scene = false;
    }
    log_msg("Left Score / Result Screen (CResultScene::on_detach)");
    return g_orig_result_detach ? g_orig_result_detach(scene, arg) : nullptr;
}

static void __fastcall hk_result_update(void* scene, float dt) {
    if (g_orig_result_update) {
        g_orig_result_update(scene, dt);
    }
    std::lock_guard<std::mutex> lock(g_state.mutex);
    g_state.in_gameplay = false;
    g_state.in_result_scene = true;
}

static std::atomic<bool> g_hooks_installed{false};

static bool try_install_hooks() {
    if (g_hooks_installed.load()) return true;

    HMODULE sdvx = GetModuleHandleW(L"soundvoltex.dll");
    if (!sdvx) return false;

    ModuleLayout layout{};
    if (!get_module_layout(sdvx, layout)) return false;
    g_sdvx_mod = layout;

    uintptr_t world_vft  = find_primary_vftable(layout, ".?AVGameWorldKFC@Game@@");
    uintptr_t result_vft = find_primary_vftable(layout, ".?AVCResultScene@@");
    g_referee_vftable    = find_primary_vftable(layout, ".?AVNoteReferee@Game@@");
    g_fumen_vftable      = find_primary_vftable(layout, ".?AVGameFumenPlayer@Game@@");
    g_timer_vftable      = find_primary_vftable(layout, ".?AVGameTimer@Game@@");

    if (!world_vft) return false;

    g_vox_offset = resolve_vox_path_offset(layout, world_vft);
    g_referee_now_offset = resolve_referee_now_offset(layout, g_referee_vftable);

    bool ok1 = hook_vftable_slot(world_vft, 3, &hk_world_update, &g_orig_world_update);
    bool ok2 = hook_vftable_slot(world_vft, 6, &hk_world_finished, &g_orig_world_finished);

    bool ok3 = false, ok4 = false, ok5 = false;
    if (result_vft) {
        ok3 = hook_vftable_slot(result_vft, 0,  &hk_result_attach, &g_orig_result_attach);
        ok4 = hook_vftable_slot(result_vft, 1,  &hk_result_detach, &g_orig_result_detach);
        ok5 = hook_vftable_slot(result_vft, 15, &hk_result_update, &g_orig_result_update);
    }

    log_msg("Hooks installed on soundvoltex.dll (base=0x%llX): GameWorldKFC vft=0x%llX (vox_off=0x%zX, ok=%d/%d), NoteReferee vft=0x%llX, CResultScene vft=0x%llX (ok=%d/%d/%d)",
            static_cast<unsigned long long>(layout.base),
            static_cast<unsigned long long>(world_vft),
            g_vox_offset, ok1 ? 1 : 0, ok2 ? 1 : 0,
            static_cast<unsigned long long>(g_referee_vftable),
            static_cast<unsigned long long>(result_vft),
            ok3 ? 1 : 0, ok4 ? 1 : 0, ok5 ? 1 : 0);

    g_hooks_installed.store(true);
    return true;
}

static DWORD WINAPI init_thread_proc(LPVOID) {
    load_config();
    log_msg("Background hook installer started.");
    for (int i = 0; i < 600; ++i) {
        if (try_install_hooks()) break;
        Sleep(100);
    }
    return 0;
}

static ImU32 rainbow_scrit_color(float phase, uint8_t alpha = 255) {
    float h = std::fmod(std::fabs(phase) * 0.35f + static_cast<float>(GetTickCount64() % 4000) / 4000.0f, 1.0f);
    float r = 1.0f, g = 1.0f, b = 1.0f;
    ImGui::ColorConvertHSVtoRGB(h, 0.58f, 1.0f, r, g, b);
    return IM_COL32(static_cast<int>(r * 255.0f),
                    static_cast<int>(g * 255.0f),
                    static_cast<int>(b * 255.0f),
                    alpha);
}

static ImU32 color_for_grade(uint32_t grade, uint8_t alpha = 255, float /*phase*/ = 0.0f) {
    switch (static_cast<JudgeGrade>(grade)) {
        case JudgeGrade::SCritEarly:
        case JudgeGrade::SCritLate:
            return IM_COL32(232, 252, 255, alpha);
        case JudgeGrade::HoldCrit:
            return IM_COL32(175, 245, 240, alpha);
        case JudgeGrade::CritEarly:
        case JudgeGrade::CritLate:
            return IM_COL32(255, 218, 45, alpha);
        case JudgeGrade::NearEarly:
            return IM_COL32(255, 75, 100, alpha);
        case JudgeGrade::NearLate:
            return IM_COL32(55, 155, 255, alpha);
        case JudgeGrade::ErrorEarly:
        case JudgeGrade::ErrorLate:
        case JudgeGrade::ErrorTimeout:
            return IM_COL32(255, 25, 40, alpha);
        default:
            return IM_COL32(130, 140, 155, alpha);
    }
}

static const char* name_for_grade(uint32_t grade) {
    switch (static_cast<JudgeGrade>(grade)) {
        case JudgeGrade::SCritEarly:   return "S-CRITICAL (EARLY)";
        case JudgeGrade::SCritLate:    return "S-CRITICAL (LATE)";
        case JudgeGrade::HoldCrit:     return "S-CRITICAL (HOLD/LASER)";
        case JudgeGrade::CritEarly:    return "CRITICAL (EARLY)";
        case JudgeGrade::CritLate:     return "CRITICAL (LATE)";
        case JudgeGrade::NearEarly:    return "NEAR (EARLY)";
        case JudgeGrade::NearLate:     return "NEAR (LATE)";
        case JudgeGrade::ErrorEarly:   return "ERROR (EARLY)";
        case JudgeGrade::ErrorLate:    return "ERROR (LATE)";
        case JudgeGrade::ErrorTimeout: return "ERROR (MISS)";
        default:                       return "UNJUDGED";
    }
}

static const char* lane_name(int unified_lane) {
    static const char* const names[8] = {
        "BT-A", "BT-B", "BT-C", "BT-D", "FX-L", "FX-R", "VOL-L", "VOL-R"
    };
    return (unified_lane >= 0 && unified_lane < 8) ? names[unified_lane] : "NOTE";
}

static void format_time_mmss(float sec, char* buf, size_t cap) {
    if (!std::isfinite(sec) || sec < 0.0f) sec = 0.0f;
    int total_s = static_cast<int>(sec);
    int mins = total_s / 60;
    int secs = total_s % 60;
    int tenths = static_cast<int>((sec - std::floor(sec)) * 10.0f);
    snprintf(buf, cap, "%d:%02d.%d", mins, secs, tenths);
}

static void draw_accuracy_timeline_canvas(
    const char* canvas_id,
    ImVec2 size,
    float view_start_sec,
    float view_end_sec,
    bool interactive_select_section)
{
    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImVec2 p0 = ImGui::GetCursorScreenPos();
    ImVec2 p1 = ImVec2(p0.x + size.x, p0.y + size.y);

    ImGui::InvisibleButton(canvas_id, size);
    bool hovered = ImGui::IsItemHovered();
    bool clicked = ImGui::IsItemClicked(ImGuiMouseButton_Left);
    ImVec2 mouse = ImGui::GetIO().MousePos;

    float duration = std::max(0.1f, view_end_sec - view_start_sec);
    float section_bar_h = interactive_select_section ? 16.0f : 10.0f;
    float plot_top = p0.y + 4.0f;
    float plot_bot = p1.y - section_bar_h - 4.0f;
    float plot_h   = std::max(20.0f, plot_bot - plot_top);
    float center_y = (plot_top + plot_bot) * 0.5f;
    float half_h   = plot_h * 0.45f;

    dl->AddRectFilled(p0, p1, IM_COL32(12, 15, 22, 235), 5.0f);
    dl->AddRect(p0, p1, IM_COL32(60, 75, 100, 180), 5.0f);

    float range_ms = std::max(20.0f, g_ui.timeline_range_ms);
    auto ms_to_y = [&](float ms) -> float {
        float dir = g_ui.invert_early_late_axis ? 1.0f : -1.0f;
        float norm = std::clamp((ms * dir) / range_ms, -1.0f, 1.0f);
        return center_y - norm * half_h;
    };

    float y_scrit_a = ms_to_y(-16.67f);
    float y_scrit_b = ms_to_y(+16.67f);
    dl->AddRectFilled(ImVec2(p0.x + 1, std::min(y_scrit_a, y_scrit_b)),
                      ImVec2(p1.x - 1, std::max(y_scrit_a, y_scrit_b)),
                      IM_COL32(0, 220, 255, 16));

    float y_crit_a = ms_to_y(-33.33f);
    float y_crit_b = ms_to_y(+33.33f);
    dl->AddLine(ImVec2(p0.x + 2, y_crit_a), ImVec2(p1.x - 2, y_crit_a), IM_COL32(255, 180, 50, 45), 1.0f);
    dl->AddLine(ImVec2(p0.x + 2, y_crit_b), ImVec2(p1.x - 2, y_crit_b), IM_COL32(255, 180, 50, 45), 1.0f);

    dl->AddLine(ImVec2(p0.x + 2, center_y), ImVec2(p1.x - 2, center_y), IM_COL32(180, 210, 235, 110), 1.0f);

    const char* top_lbl = g_ui.invert_early_late_axis ? "LATE (+ms)" : "EARLY (-ms)";
    const char* bot_lbl = g_ui.invert_early_late_axis ? "EARLY (-ms)" : "LATE (+ms)";
    ImU32 top_col = g_ui.invert_early_late_axis ? IM_COL32(70, 165, 255, 175) : IM_COL32(255, 80, 105, 175);
    ImU32 bot_col = g_ui.invert_early_late_axis ? IM_COL32(255, 80, 105, 175) : IM_COL32(70, 165, 255, 175);
    dl->AddText(ImVec2(p0.x + 6, plot_top + 2), top_col, top_lbl);
    dl->AddText(ImVec2(p0.x + 6, plot_bot - 15), bot_col, bot_lbl);

    auto time_to_x = [&](float t) -> float {
        float norm = (t - view_start_sec) / duration;
        return p0.x + norm * size.x;
    };

    const auto& m_times = g_state.vox.measure_times;
    float last_label_x = -100.0f;
    for (size_t i = 0; i < m_times.size(); ++i) {
        float mt = m_times[i];
        if (mt < view_start_sec || mt > view_end_sec) continue;
        float x = time_to_x(mt);
        int m_num = static_cast<int>(i) + 1;
        bool is_major = (m_num == 1) || ((m_num - 1) % g_state.measures_per_section == 0);
        dl->AddLine(ImVec2(x, plot_top), ImVec2(x, plot_bot),
                    is_major ? IM_COL32(110, 130, 165, 85) : IM_COL32(70, 80, 100, 32),
                    is_major ? 1.2f : 1.0f);
        if (is_major && (x - last_label_x) > 42.0f && x < p1.x - 32.0f) {
            char mbuf[24];
            snprintf(mbuf, sizeof(mbuf), "M%d", m_num);
            dl->AddText(ImVec2(x + 3, plot_top + 2), IM_COL32(160, 180, 210, 160), mbuf);
            last_label_x = x;
        }
    }

    if (g_state.vox.bpm_events.size() > 1) {
        float prev_bpm = -1.0f;
        for (const auto& be : g_state.vox.bpm_events) {
            if (std::fabs(be.bpm - prev_bpm) < 1.0f) continue;
            prev_bpm = be.bpm;
            if (be.time_sec < view_start_sec || be.time_sec > view_end_sec) continue;
            float x = time_to_x(be.time_sec);
            dl->AddLine(ImVec2(x, plot_top), ImVec2(x, plot_bot), IM_COL32(190, 90, 255, 110), 1.5f);
        }
    }

    int hovered_sec_idx = -1;
    for (const auto& sec : g_state.sections) {
        if (sec.end_time < view_start_sec || sec.start_time > view_end_sec) continue;
        float x0 = std::max(p0.x + 1.0f, time_to_x(sec.start_time));
        float x1 = std::min(p1.x - 1.0f, time_to_x(sec.end_time));
        if (x1 <= x0 + 1.0f) continue;

        ImVec2 sb0(x0, plot_bot + 2.0f);
        ImVec2 sb1(x1 - 1.0f, p1.y - 2.0f);

        uint32_t errs = sec.error_early + sec.error_late + sec.error_miss;
        uint32_t nears = sec.near_early + sec.near_late;
        uint32_t crits = sec.crit_early + sec.crit_late;
        ImU32 sec_col = IM_COL32(40, 48, 62, 200);
        if (sec.judged_ticks > 0) {
            if (errs > 0) {
                sec_col = IM_COL32(255, 25, 45, 225);
                dl->AddRectFilled(sb0, sb1, sec_col, 2.0f);
            } else if (nears > 0) {
                sec_col = (sec.near_early >= sec.near_late)
                              ? IM_COL32(255, 75, 100, 220)
                              : IM_COL32(55, 155, 255, 220);
                dl->AddRectFilled(sb0, sb1, sec_col, 2.0f);
            } else if (crits > 0) {
                sec_col = IM_COL32(255, 218, 45, 215);
                dl->AddRectFilled(sb0, sb1, sec_col, 2.0f);
            } else {
                dl->AddRectFilledMultiColor(sb0, sb1,
                                            IM_COL32(0, 240, 255, 220),
                                            IM_COL32(255, 100, 240, 220),
                                            IM_COL32(255, 230, 80, 220),
                                            IM_COL32(80, 255, 180, 220));
            }
        } else {
            dl->AddRectFilled(sb0, sb1, sec_col, 2.0f);
        }
        if (g_ui.selected_section == sec.index) {
            dl->AddRect(ImVec2(x0, plot_top), ImVec2(x1, p1.y - 1.0f), IM_COL32(255, 255, 255, 220), 2.0f, 0, 2.0f);
        }

        if (hovered && mouse.x >= x0 && mouse.x < x1) {
            hovered_sec_idx = sec.index;
            if (interactive_select_section && clicked) {
                g_ui.selected_section = (g_ui.selected_section == sec.index) ? -1 : sec.index;
            }
        }
    }

    const TrackedTick* closest_tick = nullptr;
    int closest_tick_idx = -1;
    float closest_dist_sq = 144.0f;

    for (size_t idx = 0; idx < g_state.ticks.size(); ++idx) {
        const auto& tk = g_state.ticks[idx];
        if (tk.grade == 0) continue;
        if (tk.target_time < view_start_sec || tk.target_time > view_end_sec) continue;

        bool is_err  = (tk.grade == 1 || tk.grade == 9 || tk.grade == 10);
        bool is_near = (tk.grade == 2 || tk.grade == 8);
        bool is_hold = (tk.grade == 5 || !tk.is_chip());

        if (g_ui.filter_mode == 0 && is_hold && !is_err) {
            if (!g_ui.show_hold_ticks_on_timeline) continue;
        } else if (g_ui.filter_mode == 2 && !is_near && !is_err) {
            continue;
        } else if (g_ui.filter_mode == 3 && !is_err) {
            continue;
        }

        float x = time_to_x(tk.target_time);
        float y = center_y;
        ImU32 col = color_for_grade(tk.grade, 240, tk.target_time);

        if (is_err) {
            dl->AddLine(ImVec2(x, plot_top + 2), ImVec2(x, plot_bot - 2), IM_COL32(255, 25, 40, 165), 1.8f);
            y = tk.has_timing_offset() ? ms_to_y(tk.delta_ms) : (plot_top + 8.0f);
            dl->AddCircleFilled(ImVec2(x, y), 4.2f, col);
        } else if (tk.has_timing_offset()) {
            y = ms_to_y(tk.delta_ms);
            float radius = is_near ? 3.6f : ((tk.grade == 3 || tk.grade == 7) ? 3.1f : 2.5f);
            dl->AddCircleFilled(ImVec2(x, y), radius, col);
        } else {
            y = center_y;
            dl->AddCircleFilled(ImVec2(x, y), 1.8f, IM_COL32(175, 245, 240, 125));
        }

        if (static_cast<int>(idx) == g_ui.selected_tick_idx) {
            dl->AddCircle(ImVec2(x, y), 6.5f, IM_COL32(255, 255, 255, 245), 12, 2.0f);
        }

        if (hovered) {
            float dx = mouse.x - x;
            float dy = mouse.y - y;
            float d2 = dx * dx + dy * dy;
            if (d2 < closest_dist_sq) {
                closest_dist_sq = d2;
                closest_tick = &tk;
                closest_tick_idx = static_cast<int>(idx);
            }
        }
    }

    if (hovered && clicked && closest_tick_idx >= 0) {
        g_ui.selected_tick_idx = closest_tick_idx;
        g_ui.preview_center_sec = g_state.ticks[closest_tick_idx].target_time;
        g_ui.request_preview_tab = true;
    }

    if (g_state.current_time_sec >= view_start_sec && g_state.current_time_sec <= view_end_sec) {
        float px = time_to_x(g_state.current_time_sec);
        dl->AddLine(ImVec2(px, p0.y + 1), ImVec2(px, plot_bot), IM_COL32(255, 255, 255, 220), 1.8f);
    }

    if (hovered && (closest_tick != nullptr || hovered_sec_idx >= 0)) {
        ImGui::BeginTooltip();
        if (closest_tick) {
            char tbuf[32];
            format_time_mmss(closest_tick->target_time, tbuf, sizeof(tbuf));
            ImGui::TextColored(ImColor(color_for_grade(closest_tick->grade)), "%s", name_for_grade(closest_tick->grade));
            ImGui::Text("Measure: M%d  |  Time: %s", closest_tick->measure, tbuf);
            ImGui::Text("Lane: %s (%s)",
                        lane_name(closest_tick->unified_lane()),
                        closest_tick->is_chip() ? "Chip Note" : "Hold / Laser Tick");
            if (closest_tick->has_timing_offset()) {
                ImGui::Text("Offset: %+.2f ms (%s)",
                            closest_tick->delta_ms,
                            closest_tick->delta_ms < 0.0f ? "EARLY" : "LATE");
            }
            if (hovered_sec_idx >= 0) ImGui::Separator();
        }
        if (hovered_sec_idx >= 0 && hovered_sec_idx < static_cast<int>(g_state.sections.size())) {
            const auto& sec = g_state.sections[hovered_sec_idx];
            char s0[24], s1[24];
            format_time_mmss(sec.start_time, s0, sizeof(s0));
            format_time_mmss(sec.end_time, s1, sizeof(s1));
            ImGui::TextColored(ImVec4(0.4f, 0.9f, 1.0f, 1.0f), "Section #%d (%s) [%s - %s] @ %.0f BPM",
                               sec.index + 1, sec.label.c_str(), s0, s1, sec.bpm);
            ImGui::Text("S-CRIT: %u (Hold: %u) | CRIT: %u (E:%u L:%u) | NEAR: %u (E:%u L:%u) | ERROR: %u",
                        sec.s_crit, sec.hold_crit,
                        sec.crit_early + sec.crit_late, sec.crit_early, sec.crit_late,
                        sec.near_early + sec.near_late, sec.near_early, sec.near_late,
                        sec.error_early + sec.error_late + sec.error_miss);
            if (sec.timed_hits > 0) {
                double avg = sec.sum_delta_ms / static_cast<double>(sec.timed_hits);
                ImGui::Text("Section Mean: %+.2f ms (%s)",
                            avg, avg < -0.5 ? "Early Bias" : (avg > 0.5 ? "Late Bias" : "Centered"));
            }
            if (interactive_select_section) {
                ImGui::TextDisabled("Left-click section to zoom | Left-click note to inspect in Chart Preview");
            }
        }
        ImGui::EndTooltip();
    }
}

static const char* short_name_for_grade(uint32_t grade) {
    switch (static_cast<JudgeGrade>(grade)) {
        case JudgeGrade::SCritEarly:   return "S-CRIT";
        case JudgeGrade::SCritLate:    return "S-CRIT";
        case JudgeGrade::HoldCrit:     return "S-HOLD";
        case JudgeGrade::CritEarly:    return "CRIT-E";
        case JudgeGrade::CritLate:     return "CRIT-L";
        case JudgeGrade::NearEarly:    return "NEAR-E";
        case JudgeGrade::NearLate:     return "NEAR-L";
        case JudgeGrade::ErrorEarly:   return "ERR-E";
        case JudgeGrade::ErrorLate:    return "ERR-L";
        case JudgeGrade::ErrorTimeout: return "MISS";
        default:                       return "NONE";
    }
}

static std::string make_export_base_path(const char* ext) {
    std::string dir = get_game_dir() + "\\exports";
    CreateDirectoryA(dir.c_str(), nullptr);

    SYSTEMTIME st;
    GetLocalTime(&st);
    std::string song = g_state.vox.song_code.empty() ? "sdvx_chart" : g_state.vox.song_code;
    for (char& c : song) {
        if (c == '\\' || c == '/' || c == ':' || c == '*' || c == '?' || c == '"' || c == '<' || c == '>' || c == '|')
            c = '_';
    }
    char fname[512];
    snprintf(fname, sizeof(fname), "%s\\%s_%s_%04d%02d%02d_%02d%02d%02d.%s",
             dir.c_str(), song.c_str(), g_state.vox.diff_label.c_str(),
             st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, ext);
    return std::string(fname);
}

static bool export_analysis_csv(std::string& out_path) {
    out_path = make_export_base_path("csv");
    FILE* f = fopen(out_path.c_str(), "w");
    if (!f) return false;

    const auto& st = g_state.stats;
    uint32_t total_err = st.error_early + st.error_late + st.error_miss;
    fprintf(f, "Section,Metric,Value\n");
    fprintf(f, "Summary,Song,%s\n", g_state.vox.song_code.c_str());
    fprintf(f, "Summary,Difficulty,%s\n", g_state.vox.diff_label.c_str());
    fprintf(f, "Summary,Measures,%d\n", g_state.vox.end_measure);
    fprintf(f, "Summary,MinBPM,%.2f\n", g_state.vox.min_bpm);
    fprintf(f, "Summary,MaxBPM,%.2f\n", g_state.vox.max_bpm);
    fprintf(f, "Summary,TotalTicks,%u\n", st.total_ticks);
    fprintf(f, "Summary,JudgedTicks,%u\n", st.judged_ticks);
    fprintf(f, "Summary,TotalChips,%u\n", st.total_chips);
    fprintf(f, "Summary,JudgedChips,%u\n", st.judged_chips);
    fprintf(f, "Summary,SCriticalChip,%u\n", st.s_crit_chip);
    fprintf(f, "Summary,SCriticalHold,%u\n", st.s_crit_hold);
    fprintf(f, "Summary,CriticalEarly,%u\n", st.crit_early);
    fprintf(f, "Summary,CriticalLate,%u\n", st.crit_late);
    fprintf(f, "Summary,NearEarly,%u\n", st.near_early);
    fprintf(f, "Summary,NearLate,%u\n", st.near_late);
    fprintf(f, "Summary,ErrorEarly,%u\n", st.error_early);
    fprintf(f, "Summary,ErrorLate,%u\n", st.error_late);
    fprintf(f, "Summary,ErrorMiss,%u\n", st.error_miss);
    fprintf(f, "Summary,TotalErrors,%u\n", total_err);
    fprintf(f, "Summary,TotalEarly,%u\n", st.total_early);
    fprintf(f, "Summary,TotalLate,%u\n", st.total_late);
    fprintf(f, "Summary,MeanOffsetMs,%.3f\n", st.mean_ms);
    fprintf(f, "Summary,StdDevOffsetMs,%.3f\n", st.stddev_ms);
    fprintf(f, "Summary,MinOffsetMs,%.3f\n", st.min_ms);
    fprintf(f, "Summary,MaxOffsetMs,%.3f\n\n", st.max_ms);

    fprintf(f, "Lane,Judged,Total,SCrit,CritEarly,CritLate,NearEarly,NearLate,Errors,MeanOffsetMs\n");
    for (int l = 0; l < 8; ++l) {
        const auto& ls = st.lanes[l];
        double lmean = (ls.timed_hits > 0) ? (ls.sum_ms / static_cast<double>(ls.timed_hits)) : 0.0;
        fprintf(f, "%s,%u,%u,%u,%u,%u,%u,%u,%u,%.3f\n",
                lane_name(l), ls.judged, ls.total, ls.s_crit,
                ls.crit_early, ls.crit_late, ls.near_early, ls.near_late, ls.errors, lmean);
    }
    fprintf(f, "\n");

    fprintf(f, "SectionIndex,Label,StartMeasure,EndMeasure,StartTimeSec,EndTimeSec,BPM,JudgedTicks,TotalTicks,SCrit,HoldCrit,CritEarly,CritLate,NearEarly,NearLate,ErrorEarly,ErrorLate,ErrorMiss,MeanOffsetMs\n");
    for (const auto& sec : g_state.sections) {
        double smean = (sec.timed_hits > 0) ? (sec.sum_delta_ms / static_cast<double>(sec.timed_hits)) : 0.0;
        fprintf(f, "%d,%s,%d,%d,%.3f,%.3f,%.1f,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u,%.3f\n",
                sec.index + 1, sec.label.c_str(), sec.start_measure, sec.end_measure,
                sec.start_time, sec.end_time, sec.bpm, sec.judged_ticks, sec.total_ticks,
                sec.s_crit, sec.hold_crit, sec.crit_early, sec.crit_late,
                sec.near_early, sec.near_late, sec.error_early, sec.error_late, sec.error_miss, smean);
    }
    fprintf(f, "\n");

    fprintf(f, "TickIdx,NoteID,NoteTickIdx,Measure,SectionIdx,TargetTimeSec,JudgeTimeSec,Lane,NoteType,GradeId,GradeName,OffsetMs\n");
    for (size_t i = 0; i < g_state.ticks.size(); ++i) {
        const auto& tk = g_state.ticks[i];
        fprintf(f, "%zu,%u,%u,%d,%d,%.4f,%.4f,%s,%s,%u,%s,%.3f\n",
                i, tk.note_id, tk.tick_index, tk.measure, tk.section_idx + 1,
                tk.target_time, tk.judge_time, lane_name(tk.unified_lane()),
                tk.is_chip() ? "Chip" : "HoldOrLaser",
                tk.grade, name_for_grade(tk.grade),
                tk.has_timing_offset() ? tk.delta_ms : 0.0f);
    }

    fclose(f);
    return true;
}

struct SoftCanvas {
    int w = 0;
    int h = 0;
    std::vector<uint8_t> px;

    SoftCanvas(int width, int height, uint8_t r = 10, uint8_t g = 14, uint8_t b = 22)
        : w(width), h(height), px(static_cast<size_t>(width) * static_cast<size_t>(height) * 4, 255) {
        for (size_t i = 0; i < static_cast<size_t>(w) * static_cast<size_t>(h); ++i) {
            px[i * 4 + 0] = r;
            px[i * 4 + 1] = g;
            px[i * 4 + 2] = b;
            px[i * 4 + 3] = 255;
        }
    }

    void blend_px(int x, int y, ImU32 col) {
        if (x < 0 || x >= w || y < 0 || y >= h) return;
        uint8_t sr = static_cast<uint8_t>((col >> IM_COL32_R_SHIFT) & 0xFF);
        uint8_t sg = static_cast<uint8_t>((col >> IM_COL32_G_SHIFT) & 0xFF);
        uint8_t sb = static_cast<uint8_t>((col >> IM_COL32_B_SHIFT) & 0xFF);
        uint8_t sa = static_cast<uint8_t>((col >> IM_COL32_A_SHIFT) & 0xFF);
        if (sa == 0) return;
        size_t idx = (static_cast<size_t>(y) * static_cast<size_t>(w) + static_cast<size_t>(x)) * 4;
        if (sa == 255) {
            px[idx + 0] = sr;
            px[idx + 1] = sg;
            px[idx + 2] = sb;
        } else {
            uint32_t inv = 255 - sa;
            px[idx + 0] = static_cast<uint8_t>((sr * sa + px[idx + 0] * inv) / 255);
            px[idx + 1] = static_cast<uint8_t>((sg * sa + px[idx + 1] * inv) / 255);
            px[idx + 2] = static_cast<uint8_t>((sb * sa + px[idx + 2] * inv) / 255);
        }
    }

    void fill_rect(int x0, int y0, int x1, int y1, ImU32 col) {
        int ax0 = std::clamp(std::min(x0, x1), 0, w);
        int ax1 = std::clamp(std::max(x0, x1), 0, w);
        int ay0 = std::clamp(std::min(y0, y1), 0, h);
        int ay1 = std::clamp(std::max(y0, y1), 0, h);
        for (int y = ay0; y < ay1; ++y) {
            for (int x = ax0; x < ax1; ++x) {
                blend_px(x, y, col);
            }
        }
    }

    void draw_rect(int x0, int y0, int x1, int y1, ImU32 col, int thick = 1) {
        fill_rect(x0, y0, x1, y0 + thick, col);
        fill_rect(x0, y1 - thick, x1, y1, col);
        fill_rect(x0, y0, x0 + thick, y1, col);
        fill_rect(x1 - thick, y0, x1, y1, col);
    }

    void draw_line(float x0, float y0, float x1, float y1, ImU32 col, int thick = 1) {
        float dx = x1 - x0;
        float dy = y1 - y0;
        float steps = std::max(std::fabs(dx), std::fabs(dy));
        if (steps < 1.0f) {
            blend_px(static_cast<int>(x0), static_cast<int>(y0), col);
            return;
        }
        int n = static_cast<int>(steps) + 1;
        int r = std::max(0, thick - 1);
        for (int i = 0; i <= n; ++i) {
            float t = static_cast<float>(i) / static_cast<float>(n);
            int cx = static_cast<int>(x0 + dx * t);
            int cy = static_cast<int>(y0 + dy * t);
            for (int oy = -r; oy <= r; ++oy) {
                for (int ox = -r; ox <= r; ++ox) {
                    blend_px(cx + ox, cy + oy, col);
                }
            }
        }
    }

    void fill_circle(int cx, int cy, int rad, ImU32 col) {
        int r2 = rad * rad;
        for (int dy = -rad; dy <= rad; ++dy) {
            for (int dx = -rad; dx <= rad; ++dx) {
                if (dx * dx + dy * dy <= r2) {
                    blend_px(cx + dx, cy + dy, col);
                }
            }
        }
    }

    static const uint8_t* glyph_5x7(char c) {
        static const uint8_t table[96][7] = {
            {0x00,0x00,0x00,0x00,0x00,0x00,0x00}, {0x04,0x04,0x04,0x04,0x00,0x04,0x00},
            {0x0A,0x0A,0x00,0x00,0x00,0x00,0x00}, {0x0A,0x1F,0x0A,0x0A,0x1F,0x0A,0x00},
            {0x04,0x0F,0x14,0x0E,0x05,0x1E,0x04}, {0x18,0x19,0x02,0x04,0x08,0x13,0x03},
            {0x0C,0x12,0x14,0x08,0x15,0x12,0x0D}, {0x04,0x04,0x00,0x00,0x00,0x00,0x00},
            {0x02,0x04,0x08,0x08,0x08,0x04,0x02}, {0x08,0x04,0x02,0x02,0x02,0x04,0x08},
            {0x00,0x04,0x15,0x0E,0x15,0x04,0x00}, {0x00,0x04,0x04,0x1F,0x04,0x04,0x00},
            {0x00,0x00,0x00,0x00,0x04,0x04,0x08}, {0x00,0x00,0x00,0x1F,0x00,0x00,0x00},
            {0x00,0x00,0x00,0x00,0x00,0x04,0x00}, {0x01,0x02,0x02,0x04,0x08,0x08,0x10},
            {0x0E,0x11,0x13,0x15,0x19,0x11,0x0E}, {0x04,0x0C,0x04,0x04,0x04,0x04,0x0E},
            {0x0E,0x11,0x01,0x06,0x08,0x10,0x1F}, {0x1F,0x02,0x04,0x06,0x01,0x11,0x0E},
            {0x02,0x06,0x0A,0x12,0x1F,0x02,0x02}, {0x1F,0x10,0x1E,0x01,0x01,0x11,0x0E},
            {0x06,0x08,0x10,0x1E,0x11,0x11,0x0E}, {0x1F,0x01,0x02,0x04,0x08,0x08,0x08},
            {0x0E,0x11,0x11,0x0E,0x11,0x11,0x0E}, {0x0E,0x11,0x11,0x0F,0x01,0x02,0x0C},
            {0x00,0x04,0x00,0x00,0x00,0x04,0x00}, {0x00,0x04,0x00,0x00,0x04,0x04,0x08},
            {0x02,0x04,0x08,0x10,0x08,0x04,0x02}, {0x00,0x00,0x1F,0x00,0x1F,0x00,0x00},
            {0x08,0x04,0x02,0x01,0x02,0x04,0x08}, {0x0E,0x11,0x01,0x02,0x04,0x00,0x04},
            {0x0E,0x11,0x17,0x15,0x17,0x10,0x0E}, {0x0E,0x11,0x11,0x1F,0x11,0x11,0x11},
            {0x1E,0x11,0x11,0x1E,0x11,0x11,0x1E}, {0x0E,0x11,0x10,0x10,0x10,0x11,0x0E},
            {0x1C,0x12,0x11,0x11,0x11,0x12,0x1C}, {0x1F,0x10,0x10,0x1E,0x10,0x10,0x1F},
            {0x1F,0x10,0x10,0x1E,0x10,0x10,0x10}, {0x0E,0x11,0x10,0x17,0x11,0x11,0x0F},
            {0x11,0x11,0x11,0x1F,0x11,0x11,0x11}, {0x0E,0x04,0x04,0x04,0x04,0x04,0x0E},
            {0x07,0x02,0x02,0x02,0x02,0x12,0x0C}, {0x11,0x12,0x14,0x18,0x14,0x12,0x11},
            {0x10,0x10,0x10,0x10,0x10,0x10,0x1F}, {0x11,0x1B,0x15,0x15,0x11,0x11,0x11},
            {0x11,0x19,0x15,0x13,0x11,0x11,0x11}, {0x0E,0x11,0x11,0x11,0x11,0x11,0x0E},
            {0x1E,0x11,0x11,0x1E,0x10,0x10,0x10}, {0x0E,0x11,0x11,0x11,0x15,0x12,0x0D},
            {0x1E,0x11,0x11,0x1E,0x14,0x12,0x11}, {0x0F,0x10,0x10,0x0E,0x01,0x01,0x1E},
            {0x1F,0x04,0x04,0x04,0x04,0x04,0x04}, {0x11,0x11,0x11,0x11,0x11,0x11,0x0E},
            {0x11,0x11,0x11,0x11,0x11,0x0A,0x04}, {0x11,0x11,0x11,0x15,0x15,0x1B,0x11},
            {0x11,0x11,0x0A,0x04,0x0A,0x11,0x11}, {0x11,0x11,0x0A,0x04,0x04,0x04,0x04},
            {0x1F,0x01,0x02,0x04,0x08,0x10,0x1F}, {0x0E,0x08,0x08,0x08,0x08,0x08,0x0E},
            {0x10,0x08,0x08,0x04,0x02,0x02,0x01}, {0x0E,0x02,0x02,0x02,0x02,0x02,0x0E},
            {0x04,0x0A,0x11,0x00,0x00,0x00,0x00}, {0x00,0x00,0x00,0x00,0x00,0x00,0x1F},
            {0x08,0x04,0x00,0x00,0x00,0x00,0x00}, {0x00,0x00,0x0E,0x01,0x0F,0x11,0x0F},
            {0x10,0x10,0x1E,0x11,0x11,0x11,0x1E}, {0x00,0x00,0x0E,0x10,0x10,0x10,0x0E},
            {0x01,0x01,0x0F,0x11,0x11,0x11,0x0F}, {0x00,0x00,0x0E,0x11,0x1F,0x10,0x0E},
            {0x06,0x08,0x1E,0x08,0x08,0x08,0x08}, {0x00,0x00,0x0F,0x11,0x0F,0x01,0x0E},
            {0x10,0x10,0x1E,0x11,0x11,0x11,0x11}, {0x04,0x00,0x0C,0x04,0x04,0x04,0x0E},
            {0x02,0x00,0x06,0x02,0x02,0x12,0x0C}, {0x10,0x10,0x12,0x14,0x18,0x14,0x12},
            {0x0C,0x04,0x04,0x04,0x04,0x04,0x0E}, {0x00,0x00,0x1A,0x15,0x15,0x11,0x11},
            {0x00,0x00,0x1E,0x11,0x11,0x11,0x11}, {0x00,0x00,0x0E,0x11,0x11,0x11,0x0E},
            {0x00,0x00,0x1E,0x11,0x1E,0x10,0x10}, {0x00,0x00,0x0F,0x11,0x0F,0x01,0x01},
            {0x00,0x00,0x16,0x19,0x10,0x10,0x10}, {0x00,0x00,0x0F,0x10,0x0E,0x01,0x1E},
            {0x08,0x08,0x1E,0x08,0x08,0x09,0x06}, {0x00,0x00,0x11,0x11,0x11,0x13,0x0D},
            {0x00,0x00,0x11,0x11,0x11,0x0A,0x04}, {0x00,0x00,0x11,0x11,0x15,0x15,0x0A},
            {0x00,0x00,0x11,0x0A,0x04,0x0A,0x11}, {0x00,0x00,0x11,0x11,0x0F,0x01,0x0E},
            {0x00,0x00,0x1F,0x02,0x04,0x08,0x1F}, {0x02,0x04,0x04,0x08,0x04,0x04,0x02},
            {0x04,0x04,0x04,0x04,0x04,0x04,0x04}, {0x08,0x04,0x04,0x02,0x04,0x04,0x08},
            {0x00,0x00,0x08,0x15,0x02,0x00,0x00}, {0x1F,0x1F,0x1F,0x1F,0x1F,0x1F,0x1F}
        };
        int idx = static_cast<unsigned char>(c) - 32;
        if (idx < 0 || idx >= 96) idx = 0;
        return table[idx];
    }

    void draw_text(int x, int y, const char* text, ImU32 col, int scale = 1) {
        if (!text) return;
        int cx = x;
        for (const char* p = text; *p; ++p) {
            const uint8_t* g = glyph_5x7(*p);
            for (int row = 0; row < 7; ++row) {
                uint8_t bits = g[row];
                for (int col_b = 0; col_b < 5; ++col_b) {
                    if (bits & (1 << (4 - col_b))) {
                        fill_rect(cx + col_b * scale, y + row * scale,
                                  cx + (col_b + 1) * scale, y + (row + 1) * scale, col);
                    }
                }
            }
            cx += 6 * scale;
        }
    }

    bool save_png(const std::string& path) const {
        FILE* f = fopen(path.c_str(), "wb");
        if (!f) return false;

        auto write_u32_be = [&](uint32_t v) {
            uint8_t b[4] = {
                static_cast<uint8_t>((v >> 24) & 0xFF),
                static_cast<uint8_t>((v >> 16) & 0xFF),
                static_cast<uint8_t>((v >> 8) & 0xFF),
                static_cast<uint8_t>(v & 0xFF)
            };
            fwrite(b, 1, 4, f);
        };

        auto crc32_calc = [](const uint8_t* data, size_t len, uint32_t crc = 0xFFFFFFFFu) -> uint32_t {
            for (size_t i = 0; i < len; ++i) {
                crc ^= data[i];
                for (int k = 0; k < 8; ++k) {
                    crc = (crc & 1) ? ((crc >> 1) ^ 0xEDB88320u) : (crc >> 1);
                }
            }
            return ~crc;
        };

        auto write_chunk = [&](const char type[4], const uint8_t* data, size_t len) {
            write_u32_be(static_cast<uint32_t>(len));
            fwrite(type, 1, 4, f);
            if (len > 0) fwrite(data, 1, len, f);
            uint32_t crc = crc32_calc(reinterpret_cast<const uint8_t*>(type), 4);
            if (len > 0) {
                crc = ~crc;
                for (size_t i = 0; i < len; ++i) {
                    crc ^= data[i];
                    for (int k = 0; k < 8; ++k) {
                        crc = (crc & 1) ? ((crc >> 1) ^ 0xEDB88320u) : (crc >> 1);
                    }
                }
                crc = ~crc;
            }
            write_u32_be(crc);
        };

        const uint8_t sig[8] = {137, 80, 78, 71, 13, 10, 26, 10};
        fwrite(sig, 1, 8, f);

        uint8_t ihdr[13] = {};
        ihdr[0] = static_cast<uint8_t>((w >> 24) & 0xFF);
        ihdr[1] = static_cast<uint8_t>((w >> 16) & 0xFF);
        ihdr[2] = static_cast<uint8_t>((w >> 8) & 0xFF);
        ihdr[3] = static_cast<uint8_t>(w & 0xFF);
        ihdr[4] = static_cast<uint8_t>((h >> 24) & 0xFF);
        ihdr[5] = static_cast<uint8_t>((h >> 16) & 0xFF);
        ihdr[6] = static_cast<uint8_t>((h >> 8) & 0xFF);
        ihdr[7] = static_cast<uint8_t>(h & 0xFF);
        ihdr[8] = 8;
        ihdr[9] = 6;
        write_chunk("IHDR", ihdr, 13);

        size_t row_bytes = static_cast<size_t>(w) * 4 + 1;
        std::vector<uint8_t> raw(row_bytes * static_cast<size_t>(h));
        for (int y = 0; y < h; ++y) {
            raw[static_cast<size_t>(y) * row_bytes] = 0;
            memcpy(&raw[static_cast<size_t>(y) * row_bytes + 1],
                   &px[static_cast<size_t>(y) * static_cast<size_t>(w) * 4],
                   static_cast<size_t>(w) * 4);
        }

        std::vector<uint8_t> zstream;
        zstream.reserve(raw.size() + (raw.size() / 65535 + 2) * 5 + 6);
        zstream.push_back(0x78);
        zstream.push_back(0x01);

        size_t pos = 0;
        uint32_t s1 = 1, s2 = 0;
        while (pos < raw.size()) {
            size_t chunk = std::min<size_t>(65535, raw.size() - pos);
            bool last = (pos + chunk == raw.size());
            zstream.push_back(last ? 0x01 : 0x00);
            uint16_t len16 = static_cast<uint16_t>(chunk);
            uint16_t nlen16 = ~len16;
            zstream.push_back(static_cast<uint8_t>(len16 & 0xFF));
            zstream.push_back(static_cast<uint8_t>((len16 >> 8) & 0xFF));
            zstream.push_back(static_cast<uint8_t>(nlen16 & 0xFF));
            zstream.push_back(static_cast<uint8_t>((nlen16 >> 8) & 0xFF));
            for (size_t i = 0; i < chunk; ++i) {
                uint8_t b = raw[pos + i];
                zstream.push_back(b);
                s1 = (s1 + b) % 65521u;
                s2 = (s2 + s1) % 65521u;
            }
            pos += chunk;
        }
        uint32_t adler = (s2 << 16) | s1;
        zstream.push_back(static_cast<uint8_t>((adler >> 24) & 0xFF));
        zstream.push_back(static_cast<uint8_t>((adler >> 16) & 0xFF));
        zstream.push_back(static_cast<uint8_t>((adler >> 8) & 0xFF));
        zstream.push_back(static_cast<uint8_t>(adler & 0xFF));

        write_chunk("IDAT", zstream.data(), zstream.size());
        write_chunk("IEND", nullptr, 0);
        fclose(f);
        return true;
    }
};

static void render_chart_strip_to_soft_canvas(
    SoftCanvas& img,
    int x0, int y0, int w, int h,
    float start_sec, float end_sec,
    const char* strip_title)
{
    img.fill_rect(x0, y0, x0 + w, y0 + h, IM_COL32(14, 18, 28, 255));
    img.draw_rect(x0, y0, x0 + w, y0 + h, IM_COL32(60, 80, 110, 255), 1);
    img.draw_text(x0 + 8, y0 + 6, strip_title, IM_COL32(0, 235, 255, 255), 2);

    int hw_x0 = x0 + 54;
    int hw_x1 = x0 + w - 64;
    int hw_y0 = y0 + 28;
    int hw_y1 = y0 + h - 10;
    int hw_w  = std::max(40, hw_x1 - hw_x0);
    int hw_h  = std::max(40, hw_y1 - hw_y0);

    img.fill_rect(hw_x0, hw_y0, hw_x1, hw_y1, IM_COL32(8, 10, 16, 255));
    for (int c = 0; c <= 4; ++c) {
        int lx = hw_x0 + (hw_w * c) / 4;
        img.draw_line(static_cast<float>(lx), static_cast<float>(hw_y0),
                      static_cast<float>(lx), static_cast<float>(hw_y1),
                      IM_COL32(55, 68, 90, 255), 1);
    }

    float dur = std::max(0.2f, end_sec - start_sec);
    auto sec_to_y = [&](float t) -> int {
        float u = (t - start_sec) / dur;
        return hw_y1 - static_cast<int>(u * static_cast<float>(hw_h));
    };

    const auto& m_times = g_state.vox.measure_times;
    for (size_t i = 0; i < m_times.size(); ++i) {
        float mt = m_times[i];
        if (mt < start_sec || mt > end_sec) continue;
        int my = sec_to_y(mt);
        img.draw_line(static_cast<float>(hw_x0), static_cast<float>(my),
                      static_cast<float>(hw_x1), static_cast<float>(my),
                      IM_COL32(95, 115, 145, 255), 1);
        char mbuf[24];
        snprintf(mbuf, sizeof(mbuf), "M%zu", i + 1);
        img.draw_text(x0 + 6, my - 4, mbuf, IM_COL32(170, 190, 220, 255), 1);
    }

    for (const auto& hspan : g_state.vox.holds) {
        if (hspan.end_sec < start_sec || hspan.start_sec > end_sec) continue;
        float s0 = std::max(start_sec, hspan.start_sec);
        float s1 = std::min(end_sec, hspan.end_sec);
        int hy1 = sec_to_y(s0);
        int hy0 = sec_to_y(s1);
        int lx0 = hw_x0, lx1 = hw_x1;
        ImU32 hcol = IM_COL32(180, 200, 230, 95);
        if (hspan.lane >= 0 && hspan.lane <= 3) {
            lx0 = hw_x0 + (hw_w * hspan.lane) / 4 + 5;
            lx1 = hw_x0 + (hw_w * (hspan.lane + 1)) / 4 - 5;
        } else if (hspan.lane == 4) {
            lx0 = hw_x0 + 2;
            lx1 = hw_x0 + hw_w / 2 - 2;
            hcol = IM_COL32(255, 155, 40, 85);
        } else if (hspan.lane == 5) {
            lx0 = hw_x0 + hw_w / 2 + 2;
            lx1 = hw_x1 - 2;
            hcol = IM_COL32(255, 155, 40, 85);
        }
        img.fill_rect(lx0, hy0, lx1, hy1, hcol);
    }

    for (const auto& lseg : g_state.vox.lasers) {
        if (lseg.end_sec < start_sec || lseg.start_sec > end_sec) continue;
        int ly0 = sec_to_y(lseg.start_sec);
        int ly1 = sec_to_y(lseg.end_sec);
        int lx0 = hw_x0 + static_cast<int>(lseg.start_pos * static_cast<float>(hw_w));
        int lx1 = hw_x0 + static_cast<int>(lseg.end_pos * static_cast<float>(hw_w));
        ImU32 lcol = (lseg.laser_idx == 0) ? IM_COL32(0, 195, 255, 185) : IM_COL32(255, 65, 185, 185);
        img.draw_line(static_cast<float>(lx0), static_cast<float>(ly0),
                      static_cast<float>(lx1), static_cast<float>(ly1), lcol, 3);
    }

    for (const auto& tk : g_state.ticks) {
        if (tk.target_time < start_sec || tk.target_time > end_sec) continue;
        int ny = sec_to_y(tk.target_time);
        int ul = tk.unified_lane();
        ImU32 col = (tk.grade > 0) ? color_for_grade(tk.grade, 255) : IM_COL32(140, 150, 165, 180);

        if (ul >= 0 && ul <= 3) {
            int lx0 = hw_x0 + (hw_w * ul) / 4 + 3;
            int lx1 = hw_x0 + (hw_w * (ul + 1)) / 4 - 3;
            int nh = tk.is_chip() ? 4 : 2;
            img.fill_rect(lx0, ny - nh, lx1, ny + nh, col);
        } else if (ul == 4 || ul == 5) {
            int lx0 = (ul == 4) ? (hw_x0 + 2) : (hw_x0 + hw_w / 2 + 2);
            int lx1 = (ul == 4) ? (hw_x0 + hw_w / 2 - 2) : (hw_x1 - 2);
            int nh = tk.is_chip() ? 5 : 2;
            img.fill_rect(lx0, ny - nh, lx1, ny + nh, col);
        } else {
            float lpos = get_laser_pos_at_time(g_state.vox, ul - 6, tk.target_time);
            int lx = hw_x0 + static_cast<int>(lpos * static_cast<float>(hw_w));
            img.fill_circle(lx, ny, (tk.grade == 1 || tk.grade == 9 || tk.grade == 10) ? 5 : 3, col);
        }

        if (tk.grade != 0 && tk.grade != 4 && tk.grade != 5 && tk.grade != 6) {
            char jbuf[32];
            if (tk.has_timing_offset()) {
                snprintf(jbuf, sizeof(jbuf), "%s %+.0f", short_name_for_grade(tk.grade), tk.delta_ms);
            } else {
                snprintf(jbuf, sizeof(jbuf), "%s", short_name_for_grade(tk.grade));
            }
            img.draw_text(hw_x1 + 4, ny - 3, jbuf, col, 1);
        }
    }
}

static bool export_analysis_png(std::string& out_path) {
    out_path = make_export_base_path("png");
    const int W = 1800;
    const int H = 1350;
    SoftCanvas img(W, H, 10, 14, 22);

    const auto& st = g_state.stats;
    uint32_t total_err  = st.error_early + st.error_late + st.error_miss;
    uint32_t total_near = st.near_early + st.near_late;
    uint32_t total_crit = st.crit_early + st.crit_late;
    uint32_t total_sc   = st.s_crit_chip + st.s_crit_hold;

    img.fill_rect(16, 16, W - 16, 118, IM_COL32(16, 24, 38, 255));
    img.draw_rect(16, 16, W - 16, 118, IM_COL32(0, 160, 220, 255), 2);

    char line1[256];
    snprintf(line1, sizeof(line1), "SDVX ACCURACY REPORT  |  %s [%s]  |  %d Measures  |  BPM %.0f-%.0f",
             g_state.vox.song_code.empty() ? "UNKNOWN" : g_state.vox.song_code.c_str(),
             g_state.vox.diff_label.c_str(), g_state.vox.end_measure,
             g_state.vox.min_bpm, g_state.vox.max_bpm);
    img.draw_text(30, 30, line1, IM_COL32(0, 240, 255, 255), 2);

    char line2[256];
    snprintf(line2, sizeof(line2),
             "S-CRIT: %u (Chip %u / Hold %u)   CRIT: %u (E:%u L:%u)   NEAR: %u (E:%u L:%u)   ERROR: %u (E:%u L:%u M:%u)",
             total_sc, st.s_crit_chip, st.s_crit_hold,
             total_crit, st.crit_early, st.crit_late,
             total_near, st.near_early, st.near_late,
             total_err, st.error_early, st.error_late, st.error_miss);
    img.draw_text(30, 62, line2, IM_COL32(230, 240, 255, 255), 2);

    char line3[256];
    snprintf(line3, sizeof(line3),
             "Early/Late Ratio: %u EARLY vs %u LATE   |   Mean Offset: %+.2f ms   |   Std Dev: %.2f ms   |   Range: [%.1f ms .. %+.1f ms]",
             st.total_early, st.total_late, st.mean_ms, st.stddev_ms, st.min_ms, st.max_ms);
    img.draw_text(30, 90, line3, IM_COL32(180, 215, 250, 255), 2);

    int tl_x0 = 16, tl_y0 = 132, tl_x1 = W - 16, tl_y1 = 390;
    int tl_w = tl_x1 - tl_x0;
    int tl_h = tl_y1 - tl_y0;
    int plot_top = tl_y0 + 24;
    int plot_bot = tl_y1 - 22;
    int center_y = (plot_top + plot_bot) / 2;
    float half_h = static_cast<float>(plot_bot - plot_top) * 0.45f;

    img.fill_rect(tl_x0, tl_y0, tl_x1, tl_y1, IM_COL32(12, 16, 25, 255));
    img.draw_rect(tl_x0, tl_y0, tl_x1, tl_y1, IM_COL32(60, 80, 110, 255), 1);
    img.draw_text(tl_x0 + 10, tl_y0 + 6, "FULL SONG ACCURACY TIMELINE  (EARLY -ms TOP  |  0ms CENTER  |  LATE +ms BOTTOM)",
                  IM_COL32(180, 220, 255, 255), 2);

    float song_dur = std::max(10.0f, g_state.chart_end_sec);
    float range_ms = std::max(20.0f, g_ui.timeline_range_ms);
    auto ms_to_y = [&](float ms) -> int {
        float norm = std::clamp(-ms / range_ms, -1.0f, 1.0f);
        return center_y - static_cast<int>(norm * half_h);
    };
    auto time_to_x = [&](float t) -> int {
        return tl_x0 + static_cast<int>((t / song_dur) * static_cast<float>(tl_w));
    };

    img.fill_rect(tl_x0 + 2, ms_to_y(-16.67f), tl_x1 - 2, ms_to_y(+16.67f), IM_COL32(0, 220, 255, 22));
    img.draw_line(static_cast<float>(tl_x0 + 2), static_cast<float>(center_y),
                  static_cast<float>(tl_x1 - 2), static_cast<float>(center_y), IM_COL32(180, 210, 240, 140), 1);

    for (size_t i = 0; i < g_state.vox.measure_times.size(); ++i) {
        int x = time_to_x(g_state.vox.measure_times[i]);
        int m_num = static_cast<int>(i) + 1;
        bool major = (m_num == 1) || ((m_num - 1) % g_state.measures_per_section == 0);
        img.draw_line(static_cast<float>(x), static_cast<float>(plot_top),
                      static_cast<float>(x), static_cast<float>(plot_bot),
                      major ? IM_COL32(100, 120, 155, 110) : IM_COL32(60, 70, 90, 45), 1);
        if (major && x < tl_x1 - 40) {
            char mb[24];
            snprintf(mb, sizeof(mb), "M%d", m_num);
            img.draw_text(x + 3, plot_top + 3, mb, IM_COL32(150, 175, 210, 200), 1);
        }
    }

    for (const auto& sec : g_state.sections) {
        int sx0 = std::max(tl_x0 + 2, time_to_x(sec.start_time));
        int sx1 = std::min(tl_x1 - 2, time_to_x(sec.end_time));
        if (sx1 <= sx0 + 1) continue;
        uint32_t errs = sec.error_early + sec.error_late + sec.error_miss;
        uint32_t nears = sec.near_early + sec.near_late;
        uint32_t crits = sec.crit_early + sec.crit_late;
        ImU32 scol = IM_COL32(45, 55, 70, 255);
        if (sec.judged_ticks > 0) {
            if (errs > 0) scol = IM_COL32(255, 25, 40, 255);
            else if (nears > 0) scol = (sec.near_early >= sec.near_late) ? IM_COL32(255, 75, 100, 255) : IM_COL32(55, 155, 255, 255);
            else if (crits > 0) scol = IM_COL32(255, 218, 45, 255);
            else scol = rainbow_scrit_color(sec.start_time, 255);
        }
        img.fill_rect(sx0, plot_bot + 3, sx1 - 1, tl_y1 - 3, scol);
    }

    for (const auto& tk : g_state.ticks) {
        if (tk.grade == 0) continue;
        bool is_err = (tk.grade == 1 || tk.grade == 9 || tk.grade == 10);
        if (!tk.is_chip() && !is_err && !g_ui.show_hold_ticks_on_timeline) continue;
        int x = time_to_x(tk.target_time);
        ImU32 col = color_for_grade(tk.grade, 255, tk.target_time);
        if (is_err) {
            img.draw_line(static_cast<float>(x), static_cast<float>(plot_top + 2),
                          static_cast<float>(x), static_cast<float>(plot_bot - 2), IM_COL32(255, 40, 70, 180), 2);
            int y = tk.has_timing_offset() ? ms_to_y(tk.delta_ms) : (plot_top + 8);
            img.fill_circle(x, y, 4, col);
        } else if (tk.has_timing_offset()) {
            int y = ms_to_y(tk.delta_ms);
            img.fill_circle(x, y, (tk.grade == 2 || tk.grade == 8) ? 4 : 3, col);
        }
    }

    int sec_box_x0 = 16, sec_box_y0 = 404, sec_box_x1 = 1080, sec_box_y1 = 760;
    img.fill_rect(sec_box_x0, sec_box_y0, sec_box_x1, sec_box_y1, IM_COL32(14, 18, 28, 255));
    img.draw_rect(sec_box_x0, sec_box_y0, sec_box_x1, sec_box_y1, IM_COL32(60, 80, 110, 255), 1);
    img.draw_text(sec_box_x0 + 10, sec_box_y0 + 8, "SECTION BREAKDOWN", IM_COL32(0, 235, 255, 255), 2);

    int max_rows = std::min<int>(16, static_cast<int>(g_state.sections.size()));
    for (int i = 0; i < max_rows; ++i) {
        const auto& sec = g_state.sections[i];
        int ry = sec_box_y0 + 34 + i * 20;
        char slbl[64];
        snprintf(slbl, sizeof(slbl), "#%02d %s (%.0f)", sec.index + 1, sec.label.c_str(), sec.bpm);
        img.draw_text(sec_box_x0 + 10, ry + 3, slbl, IM_COL32(210, 225, 245, 255), 1);

        int bx0 = sec_box_x0 + 165, bx1 = sec_box_x0 + 620, bw = bx1 - bx0;
        img.fill_rect(bx0, ry + 2, bx1, ry + 15, IM_COL32(28, 34, 46, 255));
        uint32_t denom = std::max<uint32_t>(1, sec.judged_ticks);
        float cx = static_cast<float>(bx0);
        auto dseg = [&](uint32_t cnt, ImU32 c) {
            if (!cnt) return;
            float sw = (static_cast<float>(cnt) / static_cast<float>(denom)) * static_cast<float>(bw);
            img.fill_rect(static_cast<int>(cx), ry + 2, static_cast<int>(cx + sw), ry + 15, c);
            cx += sw;
        };
        dseg(sec.s_crit + sec.hold_crit, rainbow_scrit_color(sec.start_time, 255));
        dseg(sec.crit_early + sec.crit_late, IM_COL32(255, 218, 45, 255));
        dseg(sec.near_early, IM_COL32(255, 75, 100, 255));
        dseg(sec.near_late,  IM_COL32(55, 155, 255, 255));
        dseg(sec.error_early + sec.error_late + sec.error_miss, IM_COL32(255, 25, 40, 255));

        double avg = (sec.timed_hits > 0) ? (sec.sum_delta_ms / static_cast<double>(sec.timed_hits)) : 0.0;
        char sstat[128];
        snprintf(sstat, sizeof(sstat), "SC:%u  CR:%u(%u/%u)  NR:%u(%u/%u)  ER:%u  Mean:%+.1fms",
                 sec.s_crit + sec.hold_crit,
                 sec.crit_early + sec.crit_late, sec.crit_early, sec.crit_late,
                 sec.near_early + sec.near_late, sec.near_early, sec.near_late,
                 sec.error_early + sec.error_late + sec.error_miss, avg);
        img.draw_text(bx1 + 12, ry + 4, sstat, IM_COL32(200, 215, 235, 255), 1);
    }

    int lane_box_x0 = 1094, lane_box_y0 = 404, lane_box_x1 = W - 16, lane_box_y1 = 760;
    img.fill_rect(lane_box_x0, lane_box_y0, lane_box_x1, lane_box_y1, IM_COL32(14, 18, 28, 255));
    img.draw_rect(lane_box_x0, lane_box_y0, lane_box_x1, lane_box_y1, IM_COL32(60, 80, 110, 255), 1);
    img.draw_text(lane_box_x0 + 10, lane_box_y0 + 8, "PER-LANE ACCURACY & OFFSET HISTOGRAM", IM_COL32(0, 235, 255, 255), 2);

    for (int l = 0; l < 8; ++l) {
        const auto& ls = st.lanes[l];
        int ly = lane_box_y0 + 36 + l * 19;
        double lmean = (ls.timed_hits > 0) ? (ls.sum_ms / static_cast<double>(ls.timed_hits)) : 0.0;
        char lbuf[160];
        snprintf(lbuf, sizeof(lbuf), "%-5s | Notes:%4u/%4u | SC:%4u | CR:%3u(%u/%u) | NR:%3u(%u/%u) | ER:%2u | %+.1fms",
                 lane_name(l), ls.judged, ls.total, ls.s_crit,
                 ls.crit_early + ls.crit_late, ls.crit_early, ls.crit_late,
                 ls.near_early + ls.near_late, ls.near_early, ls.near_late,
                 ls.errors, lmean);
        img.draw_text(lane_box_x0 + 12, ly, lbuf, IM_COL32(215, 230, 245, 255), 1);
    }

    int hx0 = lane_box_x0 + 16, hy0 = lane_box_y0 + 200, hx1 = lane_box_x1 - 16, hy1 = lane_box_y1 - 20;
    img.fill_rect(hx0, hy0, hx1, hy1, IM_COL32(10, 13, 20, 255));
    float hbw = static_cast<float>(hx1 - hx0) / static_cast<float>(SummaryStats::HIST_BINS);
    for (int b = 0; b < SummaryStats::HIST_BINS; ++b) {
        uint32_t cnt = st.hist[b];
        if (!cnt) continue;
        float ratio = static_cast<float>(cnt) / static_cast<float>(std::max<uint32_t>(1, st.hist_max_count));
        int bh = static_cast<int>(ratio * static_cast<float>(hy1 - hy0 - 16));
        int bx = hx0 + static_cast<int>(b * hbw);
        float bin_ms = SummaryStats::HIST_MIN_MS + (b + 0.5f) * 3.0f;
        ImU32 bcol = IM_COL32(225, 250, 255, 255);
        if (std::fabs(bin_ms) > 33.3f) bcol = (bin_ms < 0) ? IM_COL32(255, 75, 100, 255) : IM_COL32(55, 155, 255, 255);
        else if (std::fabs(bin_ms) > 16.67f) bcol = IM_COL32(255, 218, 45, 255);
        img.fill_rect(bx + 1, hy1 - bh, bx + std::max(2, static_cast<int>(hbw) - 1), hy1, bcol);
    }

    std::vector<float> strip_centers;
    strip_centers.push_back(std::clamp(g_ui.preview_center_sec, 1.5f, std::max(2.0f, g_state.chart_end_sec - 1.5f)));
    for (const auto& tk : g_state.ticks) {
        if (strip_centers.size() >= 4) break;
        if (tk.grade == 1 || tk.grade == 9 || tk.grade == 10 || tk.grade == 2 || tk.grade == 8) {
            bool dup = false;
            for (float c : strip_centers) {
                if (std::fabs(c - tk.target_time) < 2.2f) { dup = true; break; }
            }
            if (!dup) strip_centers.push_back(tk.target_time);
        }
    }
    while (strip_centers.size() < 4) {
        float fallback_t = (static_cast<float>(strip_centers.size()) + 0.5f) * (song_dur / 4.5f);
        strip_centers.push_back(fallback_t);
    }

    int strip_y0 = 774, strip_h = H - strip_y0 - 16;
    int strip_w = (W - 32 - 3 * 12) / 4;
    for (int s = 0; s < 4; ++s) {
        int sx = 16 + s * (strip_w + 12);
        float csec = strip_centers[s];
        float s0 = std::max(0.0f, csec - 1.5f);
        float s1 = s0 + 3.0f;
        int m0 = get_measure_at_time(g_state.vox, s0);
        int m1 = get_measure_at_time(g_state.vox, s1);
        char stitle[96];
        char tc0[16], tc1[16];
        format_time_mmss(s0, tc0, sizeof(tc0));
        format_time_mmss(s1, tc1, sizeof(tc1));
        snprintf(stitle, sizeof(stitle), "CHART M%d-M%d (%s-%s)", m0, m1, tc0, tc1);
        render_chart_strip_to_soft_canvas(img, sx, strip_y0, strip_w, strip_h, s0, s1, stitle);
    }

    return img.save_png(out_path);
}

static bool is_mistake_tick(const TrackedTick& tk, int mistake_filter) {
    if (tk.grade == 0) return false;
    if (mistake_filter == 0) {
        return tk.grade == 1 || tk.grade == 2 || tk.grade == 8 || tk.grade == 9 || tk.grade == 10;
    }
    return tk.grade != 4 && tk.grade != 5 && tk.grade != 6;
}

static void draw_chart_preview_canvas(const char* id, ImVec2 size) {
    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImVec2 p0 = ImGui::GetCursorScreenPos();
    ImVec2 p1 = ImVec2(p0.x + size.x, p0.y + size.y);

    ImGui::InvisibleButton(id, size);
    bool hovered = ImGui::IsItemHovered();
    bool clicked = ImGui::IsItemClicked(ImGuiMouseButton_Left);
    ImGuiIO& io = ImGui::GetIO();
    ImVec2 mouse = io.MousePos;

    if (hovered && std::fabs(io.MouseWheel) > 0.01f) {
        float step = g_ui.preview_window_sec * 0.15f;
        g_ui.preview_center_sec = std::clamp(g_ui.preview_center_sec + io.MouseWheel * step,
                                             0.0f, std::max(1.0f, g_state.chart_end_sec));
    }
    if (hovered && ImGui::IsMouseDragging(ImGuiMouseButton_Left, 2.0f)) {
        float sec_per_px = g_ui.preview_window_sec / std::max(40.0f, size.y);
        g_ui.preview_center_sec = std::clamp(g_ui.preview_center_sec + io.MouseDelta.y * sec_per_px,
                                             0.0f, std::max(1.0f, g_state.chart_end_sec));
    }

    dl->AddRectFilled(p0, p1, IM_COL32(10, 13, 20, 245), 6.0f);
    dl->AddRect(p0, p1, IM_COL32(60, 80, 110, 190), 6.0f);

    float half_win = std::max(0.4f, g_ui.preview_window_sec * 0.5f);
    float view_start = g_ui.preview_center_sec - half_win;
    float view_end   = g_ui.preview_center_sec + half_win;
    float duration   = std::max(0.2f, view_end - view_start);

    float hw_top = p0.y + 10.0f;
    float hw_bot = p1.y - 10.0f;
    float hw_h   = std::max(40.0f, hw_bot - hw_top);

    float hw_w = std::clamp(size.x * 0.52f, 180.0f, 340.0f);
    float hw_x0 = p0.x + (size.x - hw_w) * 0.5f;
    float hw_x1 = hw_x0 + hw_w;

    dl->AddRectFilled(ImVec2(hw_x0, hw_top), ImVec2(hw_x1, hw_bot), IM_COL32(16, 20, 30, 255));
    dl->AddRect(ImVec2(hw_x0, hw_top), ImVec2(hw_x1, hw_bot), IM_COL32(80, 100, 135, 200), 0.0f, 0, 1.5f);

    for (int c = 1; c < 4; ++c) {
        float lx = hw_x0 + (hw_w * c) / 4.0f;
        dl->AddLine(ImVec2(lx, hw_top), ImVec2(lx, hw_bot),
                    (c == 2) ? IM_COL32(85, 105, 140, 140) : IM_COL32(55, 68, 90, 95), 1.0f);
    }

    static const char* const col_hdr[4] = {"BT-A", "BT-B", "BT-C", "BT-D"};
    for (int c = 0; c < 4; ++c) {
        float cx = hw_x0 + (hw_w * (c + 0.5f)) / 4.0f - 14.0f;
        dl->AddText(ImVec2(cx, hw_bot - 16.0f), IM_COL32(160, 185, 220, 150), col_hdr[c]);
    }

    auto time_to_y = [&](float t) -> float {
        float norm = (t - view_start) / duration;
        return hw_bot - norm * hw_h;
    };

    float focus_y = time_to_y(g_ui.preview_center_sec);
    dl->AddLine(ImVec2(p0.x + 6.0f, focus_y), ImVec2(p1.x - 6.0f, focus_y),
                IM_COL32(255, 70, 95, 150), 1.5f);

    const auto& m_times = g_state.vox.measure_times;
    for (size_t i = 0; i < m_times.size(); ++i) {
        float mt = m_times[i];
        if (i + 1 < m_times.size()) {
            float next_mt = m_times[i + 1];
            if (next_mt >= view_start && mt <= view_end) {
                for (int b = 1; b < 4; ++b) {
                    float bt = mt + (next_mt - mt) * (static_cast<float>(b) / 4.0f);
                    if (bt >= view_start && bt <= view_end) {
                        float by = time_to_y(bt);
                        dl->AddLine(ImVec2(hw_x0 + 1.0f, by), ImVec2(hw_x1 - 1.0f, by),
                                    IM_COL32(50, 60, 80, 65), 1.0f);
                    }
                }
            }
        }
        if (mt < view_start || mt > view_end) continue;
        float my = time_to_y(mt);
        dl->AddLine(ImVec2(hw_x0, my), ImVec2(hw_x1, my), IM_COL32(130, 155, 195, 165), 1.5f);

        char mbuf[32], tbuf[24];
        format_time_mmss(mt, tbuf, sizeof(tbuf));
        snprintf(mbuf, sizeof(mbuf), "M%zu (%s)", i + 1, tbuf);
        dl->AddText(ImVec2(p0.x + 10.0f, my - 7.0f), IM_COL32(185, 210, 240, 220), mbuf);
    }

    for (const auto& hspan : g_state.vox.holds) {
        if (hspan.end_sec < view_start || hspan.start_sec > view_end) continue;
        float s0 = std::max(view_start, hspan.start_sec);
        float s1 = std::min(view_end, hspan.end_sec);
        float y0 = time_to_y(s1);
        float y1 = time_to_y(s0);

        if (hspan.lane >= 0 && hspan.lane <= 3) {
            float x0 = hw_x0 + (hw_w * hspan.lane) / 4.0f + 8.0f;
            float x1 = hw_x0 + (hw_w * (hspan.lane + 1)) / 4.0f - 8.0f;
            dl->AddRectFilled(ImVec2(x0, y0), ImVec2(x1, y1), IM_COL32(200, 225, 255, 90), 2.0f);
            dl->AddRect(ImVec2(x0, y0), ImVec2(x1, y1), IM_COL32(220, 240, 255, 140), 2.0f);
        } else if (hspan.lane == 4 || hspan.lane == 5) {
            float x0 = (hspan.lane == 4) ? (hw_x0 + 3.0f) : (hw_x0 + hw_w * 0.5f + 3.0f);
            float x1 = (hspan.lane == 4) ? (hw_x0 + hw_w * 0.5f - 3.0f) : (hw_x1 - 3.0f);
            dl->AddRectFilled(ImVec2(x0, y0), ImVec2(x1, y1), IM_COL32(255, 150, 35, 80), 2.0f);
            dl->AddRect(ImVec2(x0, y0), ImVec2(x1, y1), IM_COL32(255, 180, 70, 140), 2.0f);
        }
    }

    for (const auto& lseg : g_state.vox.lasers) {
        if (lseg.end_sec < view_start || lseg.start_sec > view_end) continue;
        float y0 = time_to_y(lseg.start_sec);
        float y1 = time_to_y(lseg.end_sec);
        float x0 = hw_x0 + lseg.start_pos * hw_w;
        float x1 = hw_x0 + lseg.end_pos * hw_w;
        ImU32 lcol = (lseg.laser_idx == 0) ? IM_COL32(0, 205, 255, 150) : IM_COL32(255, 60, 185, 150);
        ImU32 lbrd = (lseg.laser_idx == 0) ? IM_COL32(80, 240, 255, 220) : IM_COL32(255, 130, 215, 220);
        float rib_w = 10.0f;
        if (std::fabs(y1 - y0) < 2.5f && std::fabs(x1 - x0) > 8.0f) {
            float sx0 = std::min(x0, x1);
            float sx1 = std::max(x0, x1);
            dl->AddRectFilled(ImVec2(sx0, y0 - 5.0f), ImVec2(sx1, y0 + 5.0f), lcol, 2.0f);
            dl->AddRect(ImVec2(sx0, y0 - 5.0f), ImVec2(sx1, y0 + 5.0f), lbrd, 2.0f);
        } else {
            dl->AddQuadFilled(ImVec2(x0 - rib_w, y0), ImVec2(x0 + rib_w, y0),
                              ImVec2(x1 + rib_w, y1), ImVec2(x1 - rib_w, y1), lcol);
            dl->AddLine(ImVec2(x0, y0), ImVec2(x1, y1), lbrd, 2.2f);
        }
    }

    int hovered_tick_idx = -1;
    float best_dist_sq = 256.0f;

    for (size_t idx = 0; idx < g_state.ticks.size(); ++idx) {
        const auto& tk = g_state.ticks[idx];
        if (tk.target_time < view_start || tk.target_time > view_end) continue;

        float ny = time_to_y(tk.target_time);
        int ul = tk.unified_lane();
        bool judged = (tk.grade != 0);
        ImU32 col = judged ? color_for_grade(tk.grade, 245) : IM_COL32(150, 165, 185, 190);
        float nx_center = hw_x0 + hw_w * 0.5f;

        if (ul >= 0 && ul <= 3) {
            float x0 = hw_x0 + (hw_w * ul) / 4.0f + 4.0f;
            float x1 = hw_x0 + (hw_w * (ul + 1)) / 4.0f - 4.0f;
            nx_center = (x0 + x1) * 0.5f;
            if (tk.is_chip()) {
                dl->AddRectFilled(ImVec2(x0, ny - 5.0f), ImVec2(x1, ny + 5.0f), col, 2.5f);
                dl->AddRect(ImVec2(x0, ny - 5.0f), ImVec2(x1, ny + 5.0f), IM_COL32(255, 255, 255, 210), 2.5f);
            } else {
                dl->AddCircleFilled(ImVec2(nx_center, ny), 3.5f, col);
            }
        } else if (ul == 4 || ul == 5) {
            float x0 = (ul == 4) ? (hw_x0 + 3.0f) : (hw_x0 + hw_w * 0.5f + 3.0f);
            float x1 = (ul == 4) ? (hw_x0 + hw_w * 0.5f - 3.0f) : (hw_x1 - 3.0f);
            nx_center = (x0 + x1) * 0.5f;
            if (tk.is_chip()) {
                dl->AddRectFilled(ImVec2(x0, ny - 6.0f), ImVec2(x1, ny + 6.0f), col, 3.0f);
                dl->AddRect(ImVec2(x0, ny - 6.0f), ImVec2(x1, ny + 6.0f), IM_COL32(255, 240, 190, 230), 3.0f, 0, 1.5f);
            } else {
                dl->AddCircleFilled(ImVec2(nx_center, ny), 3.5f, col);
            }
        } else {
            float lpos = get_laser_pos_at_time(g_state.vox, ul - 6, tk.target_time);
            nx_center = hw_x0 + lpos * hw_w;
            float rad = (tk.grade == 1 || tk.grade == 9 || tk.grade == 10) ? 5.5f : 4.0f;
            dl->AddCircleFilled(ImVec2(nx_center, ny), rad, col);
            dl->AddCircle(ImVec2(nx_center, ny), rad + 1.0f, IM_COL32(255, 255, 255, 190));
        }

        if (judged && (tk.is_chip() || tk.grade != 5)) {
            char jlbl[40];
            if (tk.has_timing_offset()) {
                snprintf(jlbl, sizeof(jlbl), "%s %+.1fms", short_name_for_grade(tk.grade), tk.delta_ms);
            } else {
                snprintf(jlbl, sizeof(jlbl), "%s", short_name_for_grade(tk.grade));
            }
            if (tk.grade != 4 && tk.grade != 5 && tk.grade != 6) {
                dl->AddText(ImVec2(hw_x1 + 8.0f, ny - 7.0f), col, jlbl);
            } else if (tk.is_chip()) {
                dl->AddText(ImVec2(nx_center - 16.0f, ny - 16.0f), IM_COL32(200, 250, 255, 175), jlbl);
            }
        }

        if (static_cast<int>(idx) == g_ui.selected_tick_idx) {
            dl->AddRect(ImVec2(hw_x0 - 4.0f, ny - 9.0f), ImVec2(hw_x1 + 4.0f, ny + 9.0f),
                        IM_COL32(255, 255, 100, 245), 3.0f, 0, 2.2f);
            dl->AddCircle(ImVec2(nx_center, ny), 9.0f, IM_COL32(255, 255, 255, 255), 16, 2.2f);
        }

        if (hovered) {
            float dx = mouse.x - nx_center;
            float dy = mouse.y - ny;
            float d2 = dx * dx + dy * dy;
            if (d2 < best_dist_sq) {
                best_dist_sq = d2;
                hovered_tick_idx = static_cast<int>(idx);
            }
        }
    }

    if (hovered && hovered_tick_idx >= 0) {
        const auto& tk = g_state.ticks[hovered_tick_idx];
        char tbuf[24];
        format_time_mmss(tk.target_time, tbuf, sizeof(tbuf));
        ImGui::BeginTooltip();
        ImGui::TextColored(ImColor(color_for_grade(tk.grade)), "%s", name_for_grade(tk.grade));
        ImGui::Text("Measure: M%d  |  Time: %s  |  Lane: %s", tk.measure, tbuf, lane_name(tk.unified_lane()));
        if (tk.has_timing_offset()) {
            ImGui::Text("Timing Offset: %+.2f ms (%s)", tk.delta_ms, tk.delta_ms < 0.0f ? "EARLY" : "LATE");
        }
        ImGui::TextDisabled("Click to select & lock onto this note");
        ImGui::EndTooltip();

        if (clicked) {
            g_ui.selected_tick_idx = hovered_tick_idx;
            g_ui.preview_center_sec = tk.target_time;
        }
    }
}

static void render_chart_preview_tab() {
    float total_w = ImGui::GetContentRegionAvail().x;
    float left_w  = std::clamp(total_w * 0.38f, 280.0f, 430.0f);

    std::vector<int> mistakes;
    mistakes.reserve(256);
    for (size_t i = 0; i < g_state.ticks.size(); ++i) {
        if (is_mistake_tick(g_state.ticks[i], g_ui.mistake_filter)) {
            mistakes.push_back(static_cast<int>(i));
        }
    }

    ImGui::BeginChild("##ChartPreviewLeft", ImVec2(left_w, 0), true);
    ImGui::TextColored(ImVec4(0.3f, 0.95f, 1.0f, 1.0f), "Chart Navigation & Mistake Finder");

    float max_sec = std::max(1.0f, g_state.chart_end_sec);
    int cur_m = get_measure_at_time(g_state.vox, g_ui.preview_center_sec);
    char t_str[24];
    format_time_mmss(g_ui.preview_center_sec, t_str, sizeof(t_str));
    ImGui::Text("Position: Measure M%d / M%d  (%s)", cur_m, g_state.vox.end_measure, t_str);

    ImGui::SetNextItemWidth(-1.0f);
    ImGui::SliderFloat("##PreviewScrub", &g_ui.preview_center_sec, 0.0f, max_sec, "Time: %.2f s");

    if (ImGui::SmallButton("<< -4M")) {
        int nm = std::max(1, cur_m - 4);
        if (nm - 1 < static_cast<int>(g_state.vox.measure_times.size()))
            g_ui.preview_center_sec = g_state.vox.measure_times[nm - 1];
    }
    ImGui::SameLine();
    if (ImGui::SmallButton("< -1M")) {
        int nm = std::max(1, cur_m - 1);
        if (nm - 1 < static_cast<int>(g_state.vox.measure_times.size()))
            g_ui.preview_center_sec = g_state.vox.measure_times[nm - 1];
    }
    ImGui::SameLine();
    if (ImGui::SmallButton("+1M >")) {
        int nm = std::min(g_state.vox.end_measure, cur_m + 1);
        if (nm - 1 < static_cast<int>(g_state.vox.measure_times.size()))
            g_ui.preview_center_sec = g_state.vox.measure_times[nm - 1];
    }
    ImGui::SameLine();
    if (ImGui::SmallButton("+4M >>")) {
        int nm = std::min(g_state.vox.end_measure, cur_m + 4);
        if (nm - 1 < static_cast<int>(g_state.vox.measure_times.size()))
            g_ui.preview_center_sec = g_state.vox.measure_times[nm - 1];
    }
    ImGui::SameLine();
    ImGui::Text("| Zoom:");
    ImGui::SameLine();
    if (ImGui::SmallButton("1.5s")) g_ui.preview_window_sec = 1.5f;
    ImGui::SameLine();
    if (ImGui::SmallButton("3.0s")) g_ui.preview_window_sec = 3.0f;
    ImGui::SameLine();
    if (ImGui::SmallButton("5.0s")) g_ui.preview_window_sec = 5.0f;

    ImGui::Separator();
    ImGui::Text("Mistake Filter:");
    ImGui::SameLine();
    ImGui::RadioButton("Errors & Nears", &g_ui.mistake_filter, 0);
    ImGui::SameLine();
    ImGui::RadioButton("All Non-SCrit", &g_ui.mistake_filter, 1);

    if (ImGui::Button("< Prev Mistake", ImVec2(left_w * 0.46f, 0))) {
        int chosen = -1;
        for (int idx : mistakes) {
            if (g_state.ticks[idx].target_time < g_ui.preview_center_sec - 0.01f) {
                chosen = idx;
            } else {
                break;
            }
        }
        if (chosen < 0 && !mistakes.empty()) chosen = mistakes.back();
        if (chosen >= 0) {
            g_ui.selected_tick_idx = chosen;
            g_ui.preview_center_sec = g_state.ticks[chosen].target_time;
        }
    }
    ImGui::SameLine();
    if (ImGui::Button("Next Mistake >", ImVec2(left_w * 0.46f, 0))) {
        int chosen = -1;
        for (int idx : mistakes) {
            if (g_state.ticks[idx].target_time > g_ui.preview_center_sec + 0.01f) {
                chosen = idx;
                break;
            }
        }
        if (chosen < 0 && !mistakes.empty()) chosen = mistakes.front();
        if (chosen >= 0) {
            g_ui.selected_tick_idx = chosen;
            g_ui.preview_center_sec = g_state.ticks[chosen].target_time;
        }
    }

    if (g_ui.selected_tick_idx >= 0 && g_ui.selected_tick_idx < static_cast<int>(g_state.ticks.size())) {
        const auto& stk = g_state.ticks[g_ui.selected_tick_idx];
        char stbuf[24];
        format_time_mmss(stk.target_time, stbuf, sizeof(stbuf));
        ImGui::Separator();
        ImGui::TextColored(ImColor(color_for_grade(stk.grade)), "Selected Note: %s", name_for_grade(stk.grade));
        ImGui::Text("Measure: M%d (%s)  |  Lane: %s (%s)",
                    stk.measure, stbuf, lane_name(stk.unified_lane()),
                    stk.is_chip() ? "Chip" : "Hold/Laser");
        if (stk.has_timing_offset()) {
            ImGui::Text("Exact Offset: %+.2f ms (%s)", stk.delta_ms, stk.delta_ms < 0.0f ? "EARLY" : "LATE");
        }
    }

    ImGui::Separator();
    ImGui::Text("Mistakes List (%zu found - Click any row to jump):", mistakes.size());
    ImGui::BeginChild("##MistakesListChild", ImVec2(0, 0), false);
    if (ImGui::BeginTable("##MistakesTable", 5,
                          ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
                          ImGuiTableFlags_ScrollY | ImGuiTableFlags_SizingStretchProp)) {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("M#", ImGuiTableColumnFlags_WidthFixed, 42.0f);
        ImGui::TableSetupColumn("Time", ImGuiTableColumnFlags_WidthFixed, 56.0f);
        ImGui::TableSetupColumn("Lane", ImGuiTableColumnFlags_WidthFixed, 48.0f);
        ImGui::TableSetupColumn("Judgement", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableSetupColumn("Offset", ImGuiTableColumnFlags_WidthFixed, 62.0f);
        ImGui::TableHeadersRow();

        for (int idx : mistakes) {
            const auto& tk = g_state.ticks[idx];
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);
            char mlbl[32];
            snprintf(mlbl, sizeof(mlbl), "M%d##row%d", tk.measure, idx);
            bool is_sel = (g_ui.selected_tick_idx == idx);
            if (ImGui::Selectable(mlbl, is_sel, ImGuiSelectableFlags_SpanAllColumns)) {
                g_ui.selected_tick_idx = idx;
                g_ui.preview_center_sec = tk.target_time;
            }
            ImGui::TableSetColumnIndex(1);
            char tb[24];
            format_time_mmss(tk.target_time, tb, sizeof(tb));
            ImGui::Text("%s", tb);
            ImGui::TableSetColumnIndex(2);
            ImGui::Text("%s", lane_name(tk.unified_lane()));
            ImGui::TableSetColumnIndex(3);
            ImGui::TextColored(ImColor(color_for_grade(tk.grade)), "%s", short_name_for_grade(tk.grade));
            ImGui::TableSetColumnIndex(4);
            if (tk.has_timing_offset()) {
                ImGui::Text("%+.1fms", tk.delta_ms);
            } else {
                ImGui::TextDisabled("-");
            }
        }
        ImGui::EndTable();
    }
    ImGui::EndChild();
    ImGui::EndChild();

    ImGui::SameLine();

    ImGui::BeginChild("##ChartPreviewRight", ImVec2(0, 0), false,
                      ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);
    ImGui::TextColored(ImVec4(0.75f, 0.85f, 1.0f, 1.0f),
                       "2D SDVX Chart Preview (Mouse Wheel or Drag to scroll freely, Click any note to inspect):");
    ImVec2 csize = ImGui::GetContentRegionAvail();
    draw_chart_preview_canvas("##SdvxChartPreviewCanvas", ImVec2(std::max(120.0f, csize.x), std::max(120.0f, csize.y)));
    ImGui::EndChild();
}

static void render_live_gameplay_hud() {
    ImGuiIO& io = ImGui::GetIO();
    ImGui::SetNextWindowPos(ImVec2(io.DisplaySize.x * 0.5f, 14.0f), ImGuiCond_FirstUseEver, ImVec2(0.5f, 0.0f));
    ImGui::SetNextWindowSize(ImVec2(std::min(780.0f, io.DisplaySize.x - 30.0f), 175.0f), ImGuiCond_FirstUseEver);
    ImGui::SetNextWindowBgAlpha(0.84f);

    ImGuiWindowFlags flags = ImGuiWindowFlags_NoCollapse;
    if (g_ui.lock_live_hud) {
        flags |= ImGuiWindowFlags_NoInputs | ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove;
    }

    char win_title[128];
    snprintf(win_title, sizeof(win_title),
             "SDVX Accuracy Timeline (Live)  [%s: Report | %s: Hide]###SdvxLiveHud",
             key_name_for_vk(g_ui.vk_toggle_report),
             key_name_for_vk(g_ui.vk_toggle_live_hud));

    if (!ImGui::Begin(win_title, nullptr, flags)) {
        ImGui::End();
        return;
    }

    const auto& st = g_state.stats;
    int cur_m = get_measure_at_time(g_state.vox, g_state.current_time_sec);
    float cur_bpm = get_bpm_at_time(g_state.vox, g_state.current_time_sec);
    char t_cur[24], t_end[24];
    format_time_mmss(g_state.current_time_sec, t_cur, sizeof(t_cur));
    format_time_mmss(g_state.chart_end_sec, t_end, sizeof(t_end));

    ImGui::TextColored(ImVec4(0.3f, 0.95f, 1.0f, 1.0f), "%s [%s]",
                       g_state.vox.song_code.empty() ? "SDVX" : g_state.vox.song_code.c_str(),
                       g_state.vox.diff_label.c_str());
    ImGui::SameLine();
    ImGui::Text("| M%d/%d (%s / %s) %.0f BPM |", cur_m, g_state.vox.end_measure, t_cur, t_end, cur_bpm);
    ImGui::SameLine();
    ImGui::TextColored(ImColor(rainbow_scrit_color(0.0f)), "S-CRIT:%u", st.s_crit_chip + st.s_crit_hold);
    ImGui::SameLine();
    ImGui::TextColored(ImVec4(1.0f, 0.86f, 0.18f, 1.0f), "CRIT:%u (E:%u/L:%u)", st.crit_early + st.crit_late, st.crit_early, st.crit_late);
    ImGui::SameLine();
    ImGui::TextColored(ImVec4(1.0f, 0.30f, 0.40f, 1.0f), "NEAR-E:%u", st.near_early);
    ImGui::SameLine();
    ImGui::TextColored(ImVec4(0.24f, 0.62f, 1.0f, 1.0f), "NEAR-L:%u", st.near_late);
    ImGui::SameLine();
    ImGui::TextColored(ImVec4(1.0f, 0.12f, 0.20f, 1.0f), "ERR:%u", st.error_early + st.error_late + st.error_miss);
    ImGui::SameLine();
    ImGui::Text("| Mean: %+.1fms (SD %.1fms)", st.mean_ms, st.stddev_ms);

    float avail_w = ImGui::GetContentRegionAvail().x;
    float avail_h = std::max(68.0f, ImGui::GetContentRegionAvail().y - (g_ui.show_live_recent_strip ? 38.0f : 4.0f));
    draw_accuracy_timeline_canvas("##LiveFullTimeline", ImVec2(avail_w, avail_h),
                                  0.0f, std::max(10.0f, g_state.chart_end_sec), false);

    if (g_ui.show_live_recent_strip) {
        float win_end = std::max(8.0f, g_state.current_time_sec + 0.5f);
        float win_start = win_end - 8.0f;
        draw_accuracy_timeline_canvas("##LiveRollingStrip", ImVec2(avail_w, 34.0f),
                                      win_start, win_end, false);
    }

    ImGui::End();
}

static void render_score_screen_report() {
    ImGuiIO& io = ImGui::GetIO();
    ImGui::SetNextWindowPos(ImVec2(io.DisplaySize.x * 0.5f, io.DisplaySize.y * 0.5f),
                            ImGuiCond_FirstUseEver, ImVec2(0.5f, 0.5f));
    ImGui::SetNextWindowSize(ImVec2(std::min(1020.0f, io.DisplaySize.x - 40.0f),
                                    std::min(720.0f, io.DisplaySize.y - 40.0f)),
                             ImGuiCond_FirstUseEver);
    ImGui::SetNextWindowBgAlpha(0.94f);

    bool open = true;
    char title[160];
    snprintf(title, sizeof(title),
             "SDVX Accuracy Timeline - %s (%s to toggle)###SdvxScoreReport",
             g_state.in_result_scene ? "Score Screen Report" : "Chart Analyzer",
             key_name_for_vk(g_ui.vk_toggle_report));

    if (!ImGui::Begin(title, &open, ImGuiWindowFlags_NoCollapse)) {
        ImGui::End();
        if (!open) g_ui.manual_report_open = false;
        return;
    }
    if (!open) {
        g_ui.manual_report_open = false;
        if (g_state.in_result_scene) g_ui.auto_show_on_result = false;
        ImGui::End();
        return;
    }

    const auto& st = g_state.stats;
    uint32_t total_errors = st.error_early + st.error_late + st.error_miss;
    uint32_t total_nears  = st.near_early + st.near_late;
    uint32_t total_crits  = st.crit_early + st.crit_late;
    uint32_t total_scrits = st.s_crit_chip + st.s_crit_hold;

    ImGui::TextColored(ImVec4(0.25f, 0.95f, 1.0f, 1.0f), "Song: %s  [%s]",
                       g_state.vox.song_code.empty() ? "N/A" : g_state.vox.song_code.c_str(),
                       g_state.vox.diff_label.c_str());
    ImGui::SameLine(0.0f, 18.0f);
    ImGui::Text("Measures: %d  |  BPM: %.0f - %.0f  |  Judged: %u / %u (Chips: %u / %u)",
                g_state.vox.end_measure, g_state.vox.min_bpm, g_state.vox.max_bpm,
                st.judged_ticks, st.total_ticks, st.judged_chips, st.total_chips);
    ImGui::SameLine(0.0f, 18.0f);
    if (ImGui::SmallButton("Export PNG")) {
        std::string out_p;
        if (export_analysis_png(out_p)) {
            g_ui.last_export_status = "Saved PNG: " + out_p;
        } else {
            g_ui.last_export_status = "Failed to save PNG";
        }
    }
    ImGui::SameLine();
    if (ImGui::SmallButton("Export CSV")) {
        std::string out_p;
        if (export_analysis_csv(out_p)) {
            g_ui.last_export_status = "Saved CSV: " + out_p;
        } else {
            g_ui.last_export_status = "Failed to save CSV";
        }
    }
    if (!g_ui.last_export_status.empty()) {
        ImGui::TextColored(ImVec4(0.35f, 1.0f, 0.55f, 1.0f), "%s", g_ui.last_export_status.c_str());
    }

    ImGui::Separator();

    ImGui::TextColored(ImColor(rainbow_scrit_color(0.0f)), "S-CRITICAL: %u (Chip: %u, Hold/Laser: %u)",
                       total_scrits, st.s_crit_chip, st.s_crit_hold);
    ImGui::SameLine(0.0f, 18.0f);
    ImGui::TextColored(ImVec4(1.0f, 0.86f, 0.18f, 1.0f), "CRITICAL: %u (Early: %u | Late: %u)",
                       total_crits, st.crit_early, st.crit_late);
    ImGui::SameLine(0.0f, 18.0f);
    ImGui::TextColored(ImVec4(1.0f, 0.30f, 0.40f, 1.0f), "NEAR EARLY: %u", st.near_early);
    ImGui::SameLine(0.0f, 12.0f);
    ImGui::TextColored(ImVec4(0.24f, 0.62f, 1.0f, 1.0f), "NEAR LATE: %u", st.near_late);
    ImGui::SameLine(0.0f, 18.0f);
    ImGui::TextColored(ImVec4(1.0f, 0.12f, 0.20f, 1.0f), "ERROR: %u (Early: %u | Late: %u | Miss: %u)",
                       total_errors, st.error_early, st.error_late, st.error_miss);

    ImGui::Text("Early / Late Ratio (Chips): ");
    ImGui::SameLine();
    ImGui::TextColored(ImVec4(1.0f, 0.30f, 0.40f, 1.0f), "%u EARLY", st.total_early);
    ImGui::SameLine();
    ImGui::Text(" vs ");
    ImGui::SameLine();
    ImGui::TextColored(ImVec4(0.24f, 0.62f, 1.0f, 1.0f), "%u LATE", st.total_late);
    ImGui::SameLine(0.0f, 20.0f);
    ImGui::Text("Mean Offset: %+.2f ms  |  Std Dev: %.2f ms  |  Range: [%.1f ms .. %+.1f ms]",
                st.mean_ms, st.stddev_ms, st.min_ms, st.max_ms);

    ImGui::Spacing();
    ImGui::Text("Filter:");
    ImGui::SameLine();
    ImGui::RadioButton("Chips + Errors", &g_ui.filter_mode, 0);
    ImGui::SameLine();
    ImGui::RadioButton("All (+Holds)", &g_ui.filter_mode, 1);
    ImGui::SameLine();
    ImGui::RadioButton("Near & Errors Only", &g_ui.filter_mode, 2);
    ImGui::SameLine();
    ImGui::RadioButton("Errors Only", &g_ui.filter_mode, 3);
    ImGui::SameLine(0.0f, 20.0f);
    ImGui::Text("Section Size:");
    ImGui::SameLine();
    if (ImGui::SmallButton("4M")) { g_state.measures_per_section = 4; rebuild_sections_locked(); recompute_stats_locked(); }
    ImGui::SameLine();
    if (ImGui::SmallButton("8M")) { g_state.measures_per_section = 8; rebuild_sections_locked(); recompute_stats_locked(); }
    ImGui::SameLine();
    if (ImGui::SmallButton("16M")) { g_state.measures_per_section = 16; rebuild_sections_locked(); recompute_stats_locked(); }
    ImGui::SameLine();
    if (ImGui::Checkbox("Split on BPM change", &g_state.split_on_bpm_change)) {
        rebuild_sections_locked();
        recompute_stats_locked();
    }

    float avail_w = ImGui::GetContentRegionAvail().x;
    ImGui::TextColored(ImVec4(0.75f, 0.85f, 1.0f, 1.0f),
                       "Full Song Timeline (Hover for note details, click any bottom section bar to zoom):");
    draw_accuracy_timeline_canvas("##ResultFullTimeline", ImVec2(avail_w, 155.0f),
                                  0.0f, std::max(10.0f, g_state.chart_end_sec), true);

    if (g_ui.selected_section >= 0 && g_ui.selected_section < static_cast<int>(g_state.sections.size())) {
        const auto& zsec = g_state.sections[g_ui.selected_section];
        ImGui::TextColored(ImVec4(0.3f, 1.0f, 0.85f, 1.0f),
                           "Zoomed Section #%d (%s, %.0f BPM):", zsec.index + 1, zsec.label.c_str(), zsec.bpm);
        ImGui::SameLine();
        if (ImGui::SmallButton("Reset Zoom")) {
            g_ui.selected_section = -1;
        } else {
            draw_accuracy_timeline_canvas("##ResultZoomTimeline", ImVec2(avail_w, 110.0f),
                                          zsec.start_time, std::max(zsec.start_time + 0.5f, zsec.end_time), false);
        }
    }

    ImGui::Spacing();

    if (ImGui::BeginTabBar("##SdvxAccTabs")) {
        ImGuiTabItemFlags preview_flags = g_ui.request_preview_tab ? ImGuiTabItemFlags_SetSelected : 0;
        g_ui.request_preview_tab = false;
        if (ImGui::BeginTabItem("Chart Preview & Mistake Inspector", nullptr, preview_flags)) {
            render_chart_preview_tab();
            ImGui::EndTabItem();
        }

        if (ImGui::BeginTabItem("Section Breakdown")) {
            ImGui::BeginChild("##SectionsTableChild", ImVec2(0, 0), false);
            if (ImGui::BeginTable("##SectionsTable", 9,
                                  ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
                                  ImGuiTableFlags_ScrollY | ImGuiTableFlags_SizingStretchProp)) {
                ImGui::TableSetupScrollFreeze(0, 1);
                ImGui::TableSetupColumn("Section", ImGuiTableColumnFlags_WidthFixed, 95.0f);
                ImGui::TableSetupColumn("Time / BPM", ImGuiTableColumnFlags_WidthFixed, 120.0f);
                ImGui::TableSetupColumn("Accuracy Distribution (S-Crit / Crit E-L / Near E-L / Err)", ImGuiTableColumnFlags_WidthStretch);
                ImGui::TableSetupColumn("S-CRIT", ImGuiTableColumnFlags_WidthFixed, 60.0f);
                ImGui::TableSetupColumn("CRIT (E/L)", ImGuiTableColumnFlags_WidthFixed, 85.0f);
                ImGui::TableSetupColumn("NEAR (E/L)", ImGuiTableColumnFlags_WidthFixed, 85.0f);
                ImGui::TableSetupColumn("ERROR", ImGuiTableColumnFlags_WidthFixed, 55.0f);
                ImGui::TableSetupColumn("Mean ms", ImGuiTableColumnFlags_WidthFixed, 75.0f);
                ImGui::TableSetupColumn("Status", ImGuiTableColumnFlags_WidthFixed, 95.0f);
                ImGui::TableHeadersRow();

                for (const auto& sec : g_state.sections) {
                    if (sec.total_ticks == 0) continue;
                    ImGui::TableNextRow();

                    ImGui::TableSetColumnIndex(0);
                    char sel_lbl[64];
                    snprintf(sel_lbl, sizeof(sel_lbl), "#%d (%s)", sec.index + 1, sec.label.c_str());
                    bool is_sel = (g_ui.selected_section == sec.index);
                    if (ImGui::Selectable(sel_lbl, is_sel, ImGuiSelectableFlags_SpanAllColumns)) {
                        g_ui.selected_section = is_sel ? -1 : sec.index;
                        g_ui.preview_center_sec = (sec.start_time + sec.end_time) * 0.5f;
                    }

                    ImGui::TableSetColumnIndex(1);
                    char t0[16], t1[16];
                    format_time_mmss(sec.start_time, t0, sizeof(t0));
                    format_time_mmss(sec.end_time, t1, sizeof(t1));
                    ImGui::Text("%s-%s (%.0f)", t0, t1, sec.bpm);

                    ImGui::TableSetColumnIndex(2);
                    {
                        ImVec2 bp0 = ImGui::GetCursorScreenPos();
                        float bw = std::max(40.0f, ImGui::GetContentRegionAvail().x);
                        float bh = 15.0f;
                        ImDrawList* bdl = ImGui::GetWindowDrawList();
                        bdl->AddRectFilled(bp0, ImVec2(bp0.x + bw, bp0.y + bh), IM_COL32(30, 35, 45, 255), 2.0f);

                        uint32_t denom = std::max<uint32_t>(1, sec.judged_ticks);
                        float cx = bp0.x;
                        auto draw_seg = [&](uint32_t cnt, ImU32 col) {
                            if (cnt == 0) return;
                            float sw = (static_cast<float>(cnt) / static_cast<float>(denom)) * bw;
                            bdl->AddRectFilled(ImVec2(cx, bp0.y), ImVec2(cx + sw, bp0.y + bh), col);
                            cx += sw;
                        };
                        uint32_t sc_cnt = sec.s_crit + sec.hold_crit;
                        if (sc_cnt > 0) {
                            float sw = (static_cast<float>(sc_cnt) / static_cast<float>(denom)) * bw;
                            bdl->AddRectFilledMultiColor(ImVec2(cx, bp0.y), ImVec2(cx + sw, bp0.y + bh),
                                                         IM_COL32(0, 240, 255, 235),
                                                         IM_COL32(255, 110, 245, 235),
                                                         IM_COL32(255, 230, 80, 235),
                                                         IM_COL32(80, 255, 185, 235));
                            cx += sw;
                        }
                        draw_seg(sec.crit_early + sec.crit_late, IM_COL32(255, 218, 45, 235));
                        draw_seg(sec.near_early, IM_COL32(255, 75, 100, 240));
                        draw_seg(sec.near_late,  IM_COL32(55, 155, 255, 240));
                        draw_seg(sec.error_early + sec.error_late + sec.error_miss, IM_COL32(255, 25, 40, 255));
                        ImGui::Dummy(ImVec2(bw, bh));
                    }

                    ImGui::TableSetColumnIndex(3);
                    ImGui::TextColored(ImColor(rainbow_scrit_color(sec.start_time)), "%u", sec.s_crit + sec.hold_crit);

                    ImGui::TableSetColumnIndex(4);
                    ImGui::TextColored(ImVec4(1.0f, 0.86f, 0.18f, 1.0f), "%u (%u/%u)",
                                       sec.crit_early + sec.crit_late, sec.crit_early, sec.crit_late);

                    ImGui::TableSetColumnIndex(5);
                    if (sec.near_early + sec.near_late > 0) {
                        ImVec4 ncol = (sec.near_early >= sec.near_late)
                                          ? ImVec4(1.0f, 0.30f, 0.40f, 1.0f)
                                          : ImVec4(0.24f, 0.62f, 1.0f, 1.0f);
                        ImGui::TextColored(ncol, "%u (%u/%u)",
                                           sec.near_early + sec.near_late, sec.near_early, sec.near_late);
                    } else {
                        ImGui::TextDisabled("0");
                    }

                    ImGui::TableSetColumnIndex(6);
                    uint32_t sec_errs = sec.error_early + sec.error_late + sec.error_miss;
                    if (sec_errs > 0) {
                        ImGui::TextColored(ImVec4(1.0f, 0.12f, 0.20f, 1.0f), "%u", sec_errs);
                    } else {
                        ImGui::TextDisabled("0");
                    }

                    ImGui::TableSetColumnIndex(7);
                    if (sec.timed_hits > 0) {
                        double avg = sec.sum_delta_ms / static_cast<double>(sec.timed_hits);
                        ImVec4 mcol = (avg < -4.0) ? ImVec4(1.0f, 0.35f, 0.45f, 1.0f)
                                                   : ((avg > 4.0) ? ImVec4(0.30f, 0.65f, 1.0f, 1.0f)
                                                                  : ImVec4(0.75f, 0.95f, 0.8f, 1.0f));
                        ImGui::TextColored(mcol, "%+.1f ms", avg);
                    } else {
                        ImGui::TextDisabled("-");
                    }

                    ImGui::TableSetColumnIndex(8);
                    if (sec.judged_ticks == 0) {
                        ImGui::TextDisabled("Unplayed");
                    } else if (sec_errs > 0) {
                        ImGui::TextColored(ImVec4(1.0f, 0.12f, 0.20f, 1.0f), "ERRORS");
                    } else if (sec.near_early + sec.near_late > 0) {
                        ImGui::TextColored(sec.near_early >= sec.near_late
                                               ? ImVec4(1.0f, 0.30f, 0.40f, 1.0f)
                                               : ImVec4(0.24f, 0.62f, 1.0f, 1.0f),
                                           sec.near_early >= sec.near_late ? "NEAR (EARLY)" : "NEAR (LATE)");
                    } else if (sec.crit_early + sec.crit_late > 0) {
                        ImGui::TextColored(ImVec4(1.0f, 0.86f, 0.18f, 1.0f),
                                           sec.crit_early >= sec.crit_late ? "UC (EARLY)" : "UC (LATE)");
                    } else {
                        ImGui::TextColored(ImColor(rainbow_scrit_color(sec.start_time)), "ALL S-CRIT");
                    }
                }
                ImGui::EndTable();
            }
            ImGui::EndChild();
            ImGui::EndTabItem();
        }

        if (ImGui::BeginTabItem("Per-Lane Accuracy & Histogram")) {
            float half_w = ImGui::GetContentRegionAvail().x * 0.54f;
            ImGui::BeginChild("##LaneTableChild", ImVec2(half_w, 0), false);
            ImGui::TextColored(ImVec4(0.4f, 0.9f, 1.0f, 1.0f), "Per-Lane Breakdown (BT-A..D, FX-L/R, VOL-L/R):");
            if (ImGui::BeginTable("##LaneTable", 7, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg)) {
                ImGui::TableSetupColumn("Lane");
                ImGui::TableSetupColumn("Notes");
                ImGui::TableSetupColumn("S-CRIT");
                ImGui::TableSetupColumn("CRIT (E/L)");
                ImGui::TableSetupColumn("NEAR (E/L)");
                ImGui::TableSetupColumn("ERROR");
                ImGui::TableSetupColumn("Mean ms");
                ImGui::TableHeadersRow();

                for (int l = 0; l < 8; ++l) {
                    const auto& ls = st.lanes[l];
                    ImGui::TableNextRow();
                    ImGui::TableSetColumnIndex(0);
                    ImGui::Text("%s", lane_name(l));
                    ImGui::TableSetColumnIndex(1);
                    ImGui::Text("%u / %u", ls.judged, ls.total);
                    ImGui::TableSetColumnIndex(2);
                    ImGui::TextColored(ImVec4(0.0f, 0.95f, 1.0f, 1.0f), "%u", ls.s_crit);
                    ImGui::TableSetColumnIndex(3);
                    ImGui::Text("%u (%u/%u)", ls.crit_early + ls.crit_late, ls.crit_early, ls.crit_late);
                    ImGui::TableSetColumnIndex(4);
                    ImGui::Text("%u (%u/%u)", ls.near_early + ls.near_late, ls.near_early, ls.near_late);
                    ImGui::TableSetColumnIndex(5);
                    if (ls.errors > 0) ImGui::TextColored(ImVec4(1.0f, 0.25f, 0.35f, 1.0f), "%u", ls.errors);
                    else ImGui::TextDisabled("0");
                    ImGui::TableSetColumnIndex(6);
                    if (ls.timed_hits > 0) {
                        ImGui::Text("%+.1f ms", ls.sum_ms / static_cast<double>(ls.timed_hits));
                    } else {
                        ImGui::TextDisabled("-");
                    }
                }
                ImGui::EndTable();
            }
            ImGui::EndChild();

            ImGui::SameLine();

            ImGui::BeginChild("##HistogramChild", ImVec2(0, 0), false);
            ImGui::TextColored(ImVec4(0.4f, 0.9f, 1.0f, 1.0f), "Timing Offset Histogram (-60ms EARLY to +60ms LATE):");
            ImVec2 hp0 = ImGui::GetCursorScreenPos();
            ImVec2 hsize = ImGui::GetContentRegionAvail();
            hsize.y = std::max(140.0f, hsize.y - 10.0f);
            ImDrawList* hdl = ImGui::GetWindowDrawList();
            hdl->AddRectFilled(hp0, ImVec2(hp0.x + hsize.x, hp0.y + hsize.y), IM_COL32(15, 19, 28, 240), 4.0f);
            hdl->AddRect(hp0, ImVec2(hp0.x + hsize.x, hp0.y + hsize.y), IM_COL32(65, 80, 105, 180), 4.0f);

            float bar_w = (hsize.x - 16.0f) / static_cast<float>(SummaryStats::HIST_BINS);
            float max_h = hsize.y - 28.0f;
            for (int b = 0; b < SummaryStats::HIST_BINS; ++b) {
                uint32_t cnt = st.hist[b];
                float bin_ms = SummaryStats::HIST_MIN_MS + (b + 0.5f) * 3.0f;
                float ratio = static_cast<float>(cnt) / static_cast<float>(std::max<uint32_t>(1, st.hist_max_count));
                float bh = ratio * max_h;
                float bx0 = hp0.x + 8.0f + b * bar_w;
                float by1 = hp0.y + hsize.y - 18.0f;
                float by0 = by1 - bh;

                ImU32 bcol = IM_COL32(225, 250, 255, 235);
                float abs_ms = std::fabs(bin_ms);
                if (abs_ms > 33.3f) bcol = (bin_ms < 0) ? IM_COL32(255, 75, 100, 235) : IM_COL32(55, 155, 255, 235);
                else if (abs_ms > 16.67f) bcol = IM_COL32(255, 218, 45, 235);

                if (cnt > 0) {
                    hdl->AddRectFilled(ImVec2(bx0 + 1.0f, by0), ImVec2(bx0 + bar_w - 1.0f, by1), bcol, 1.5f);
                }
            }
            float zero_x = hp0.x + 8.0f + (SummaryStats::HIST_BINS * 0.5f) * bar_w;
            hdl->AddLine(ImVec2(zero_x, hp0.y + 4.0f), ImVec2(zero_x, hp0.y + hsize.y - 18.0f),
                         IM_COL32(255, 255, 255, 130), 1.0f);
            hdl->AddText(ImVec2(hp0.x + 10.0f, hp0.y + hsize.y - 16.0f), IM_COL32(255, 85, 110, 220), "-60ms (EARLY)");
            hdl->AddText(ImVec2(zero_x - 12.0f, hp0.y + hsize.y - 16.0f), IM_COL32(220, 230, 240, 200), "0ms");
            hdl->AddText(ImVec2(hp0.x + hsize.x - 88.0f, hp0.y + hsize.y - 16.0f), IM_COL32(70, 165, 255, 220), "+60ms (LATE)");
            ImGui::Dummy(hsize);
            ImGui::EndChild();

            ImGui::EndTabItem();
        }

        if (ImGui::BeginTabItem("Settings & Keybinds")) {
            bool changed = false;
            changed |= ImGui::Checkbox("Show live timeline HUD during gameplay", &g_ui.show_live_hud);
            changed |= ImGui::Checkbox("Show recent 8-second zoom strip during gameplay", &g_ui.show_live_recent_strip);
            changed |= ImGui::Checkbox("Lock live HUD position (disable mouse interaction)", &g_ui.lock_live_hud);
            changed |= ImGui::Checkbox("Automatically open report on Score Screen", &g_ui.auto_show_on_result);
            changed |= ImGui::Checkbox("Show Hold / Laser ticks in default filter mode", &g_ui.show_hold_ticks_on_timeline);
            changed |= ImGui::Checkbox("Invert vertical axis (EARLY bottom / LATE top)", &g_ui.invert_early_late_axis);
            changed |= ImGui::SliderFloat("Timeline vertical range (ms)", &g_ui.timeline_range_ms, 25.0f, 100.0f, "%.0f ms");

            ImGui::Separator();
            ImGui::TextColored(ImVec4(0.4f, 0.9f, 1.0f, 1.0f), "Hotkeys:");

            ImGui::Text("Toggle Full Report Window: [%s]", key_name_for_vk(g_ui.vk_toggle_report));
            ImGui::SameLine();
            if (g_ui.rebind_target == 1) {
                ImGui::Button("Press any key... (ESC to cancel)##Rebind1");
            } else if (ImGui::Button("Rebind##BtnRebind1")) {
                g_ui.rebind_target = 1;
            }

            ImGui::Text("Toggle Live Gameplay HUD:  [%s]", key_name_for_vk(g_ui.vk_toggle_live_hud));
            ImGui::SameLine();
            if (g_ui.rebind_target == 2) {
                ImGui::Button("Press any key... (ESC to cancel)##Rebind2");
            } else if (ImGui::Button("Rebind##BtnRebind2")) {
                g_ui.rebind_target = 2;
            }

            if (changed) {
                save_config();
            }
            ImGui::EndTabItem();
        }

        ImGui::EndTabBar();
    }

    ImGui::End();
}

static ImGuiContext* g_imgui_ctx = nullptr;
static bool          g_imgui_initialized = false;
static std::chrono::steady_clock::time_point g_prev_frame_time;
static bool          g_prev_report_key_down = false;
static bool          g_prev_hud_key_down = false;

static void update_imgui_input(const SPICE_SDK_D3D9_FRAME& frame) {
    ImGuiIO& io = ImGui::GetIO();
    HWND window = static_cast<HWND>(frame.window);
    const bool focused = window &&
        (GetAncestor(GetForegroundWindow(), GA_ROOT) == GetAncestor(window, GA_ROOT));
    io.AddFocusEvent(focused);

    if (focused && g_ui.rebind_target != 0) {
        if ((GetAsyncKeyState(VK_ESCAPE) & 0x8000) != 0) {
            g_ui.rebind_target = 0;
        } else {
            for (int vk = 0x08; vk <= 0xFE; ++vk) {
                if (vk == VK_LBUTTON || vk == VK_RBUTTON || vk == VK_MBUTTON ||
                    vk == VK_SHIFT || vk == VK_LSHIFT || vk == VK_RSHIFT ||
                    vk == VK_CONTROL || vk == VK_LCONTROL || vk == VK_RCONTROL ||
                    vk == VK_MENU || vk == VK_LMENU || vk == VK_RMENU || vk == VK_ESCAPE) {
                    continue;
                }
                if ((GetAsyncKeyState(vk) & 0x8000) != 0) {
                    if (g_ui.rebind_target == 1) g_ui.vk_toggle_report = vk;
                    else if (g_ui.rebind_target == 2) g_ui.vk_toggle_live_hud = vk;
                    g_ui.rebind_target = 0;
                    g_prev_report_key_down = true;
                    g_prev_hud_key_down = true;
                    save_config();
                    break;
                }
            }
        }
    } else {
        bool rep_down = focused && ((GetAsyncKeyState(g_ui.vk_toggle_report) & 0x8000) != 0);
        if (rep_down && !g_prev_report_key_down) {
            g_ui.manual_report_open = !g_ui.manual_report_open;
            if (g_state.in_result_scene) {
                g_ui.auto_show_on_result = g_ui.manual_report_open;
            }
        }
        g_prev_report_key_down = rep_down;

        bool hud_down = focused && ((GetAsyncKeyState(g_ui.vk_toggle_live_hud) & 0x8000) != 0);
        if (hud_down && !g_prev_hud_key_down) {
            g_ui.show_live_hud = !g_ui.show_live_hud;
            save_config();
        }
        g_prev_hud_key_down = hud_down;
    }

    POINT position{};
    RECT client{};
    const bool mouse_available =
        focused &&
        GetCursorPos(&position) &&
        ScreenToClient(window, &position) &&
        GetClientRect(window, &client) &&
        client.right > 0 &&
        client.bottom > 0;

    if (mouse_available) {
        io.AddMousePosEvent(
            static_cast<float>(position.x) * static_cast<float>(frame.width) / static_cast<float>(client.right),
            static_cast<float>(position.y) * static_cast<float>(frame.height) / static_cast<float>(client.bottom));
    } else {
        io.AddMousePosEvent(-FLT_MAX, -FLT_MAX);
    }

    const bool swapped = GetSystemMetrics(SM_SWAPBUTTON) != 0;
    io.AddMouseButtonEvent(0, mouse_available &&
        ((GetAsyncKeyState(swapped ? VK_RBUTTON : VK_LBUTTON) & 0x8000) != 0));
    io.AddMouseButtonEvent(1, mouse_available &&
        ((GetAsyncKeyState(swapped ? VK_LBUTTON : VK_RBUTTON) & 0x8000) != 0));
}

static void apply_sdvx_style() {
    ImGuiStyle& style = ImGui::GetStyle();
    style.WindowRounding    = 6.0f;
    style.FrameRounding     = 4.0f;
    style.GrabRounding      = 3.0f;
    style.TabRounding       = 4.0f;
    style.WindowBorderSize  = 1.0f;
    style.FramePadding      = ImVec2(6.0f, 4.0f);
    style.ItemSpacing       = ImVec2(8.0f, 5.0f);

    ImVec4* colors = style.Colors;
    colors[ImGuiCol_WindowBg]         = ImVec4(0.06f, 0.08f, 0.12f, 0.94f);
    colors[ImGuiCol_TitleBg]          = ImVec4(0.08f, 0.12f, 0.19f, 1.00f);
    colors[ImGuiCol_TitleBgActive]    = ImVec4(0.00f, 0.36f, 0.52f, 1.00f);
    colors[ImGuiCol_Border]           = ImVec4(0.20f, 0.38f, 0.55f, 0.65f);
    colors[ImGuiCol_FrameBg]          = ImVec4(0.12f, 0.16f, 0.22f, 0.90f);
    colors[ImGuiCol_FrameBgHovered]   = ImVec4(0.18f, 0.26f, 0.36f, 0.90f);
    colors[ImGuiCol_Button]           = ImVec4(0.00f, 0.44f, 0.64f, 0.85f);
    colors[ImGuiCol_ButtonHovered]    = ImVec4(0.00f, 0.58f, 0.82f, 0.95f);
    colors[ImGuiCol_ButtonActive]     = ImVec4(0.00f, 0.70f, 0.95f, 1.00f);
    colors[ImGuiCol_Header]           = ImVec4(0.00f, 0.42f, 0.60f, 0.65f);
    colors[ImGuiCol_HeaderHovered]    = ImVec4(0.00f, 0.55f, 0.78f, 0.80f);
    colors[ImGuiCol_HeaderActive]     = ImVec4(0.00f, 0.65f, 0.90f, 1.00f);
    colors[ImGuiCol_Tab]              = ImVec4(0.10f, 0.18f, 0.28f, 0.90f);
    colors[ImGuiCol_TabHovered]       = ImVec4(0.00f, 0.55f, 0.78f, 0.90f);
    colors[ImGuiCol_TabSelected]      = ImVec4(0.00f, 0.46f, 0.68f, 1.00f);
}

static void __cdecl d3d9_callback(
    SPICE_SDK_D3D9_EVENT event,
    const SPICE_SDK_D3D9_FRAME* frame,
    void*)
{
    try_install_hooks();
    ImGuiContext* prev_ctx = ImGui::GetCurrentContext();

    if (event == SPICE_SDK_D3D9_READY && !g_imgui_ctx) {
        ImGui::SetAllocatorFunctions(
            [](size_t size, void*) -> void* { return std::malloc(size); },
            [](void* memory, void*) { std::free(memory); });
        IMGUI_CHECKVERSION();
        g_imgui_ctx = ImGui::CreateContext();
        ImGui::SetCurrentContext(g_imgui_ctx);

        ImGuiIO& io = ImGui::GetIO();
        io.IniFilename = "sdvx_accuracy.ini";
        io.LogFilename = nullptr;
        apply_sdvx_style();

        g_imgui_initialized = ImGui_ImplDX9_Init(static_cast<IDirect3DDevice9*>(frame->device));
        g_prev_frame_time = std::chrono::steady_clock::now();
        log_msg("ImGui D3D9 initialized (hwnd=%p, %ux%u, ok=%d)",
                frame->window, frame->width, frame->height, g_imgui_initialized ? 1 : 0);
    }

    if (g_imgui_ctx) {
        ImGui::SetCurrentContext(g_imgui_ctx);
        switch (event) {
            case SPICE_SDK_D3D9_READY:
                g_prev_frame_time = std::chrono::steady_clock::now();
                if (g_imgui_initialized) {
                    ImGui_ImplDX9_CreateDeviceObjects();
                }
                break;

            case SPICE_SDK_D3D9_DRAW: {
                if (!g_imgui_initialized || !frame) break;
                const auto now = std::chrono::steady_clock::now();
                const float dt = std::chrono::duration<float>(now - g_prev_frame_time).count();
                g_prev_frame_time = now;

                ImGuiIO& io = ImGui::GetIO();
                io.DisplaySize = ImVec2(static_cast<float>(frame->width), static_cast<float>(frame->height));
                io.DeltaTime = (dt > 0.0f && dt < 1.0f) ? dt : (1.0f / 60.0f);

                update_imgui_input(*frame);

                ImGui_ImplDX9_NewFrame();
                ImGui::NewFrame();

                {
                    std::lock_guard<std::mutex> lock(g_state.mutex);
                    uint64_t now_tick = GetTickCount64();
                    bool active_play = g_state.in_gameplay &&
                                       (now_tick - g_state.last_world_update_tick < 1500) &&
                                       !g_state.ticks.empty();

                    if (active_play && g_ui.show_live_hud) {
                        render_live_gameplay_hud();
                    }

                    bool show_report = g_ui.manual_report_open ||
                                       (g_state.in_result_scene && g_ui.auto_show_on_result && !g_state.ticks.empty());
                    io.MouseDrawCursor = show_report && !active_play;
                    if (show_report) {
                        render_score_screen_report();
                    }
                }

                ImGui::EndFrame();
                ImGui::Render();
                ImGui_ImplDX9_RenderDrawData(ImGui::GetDrawData());
                break;
            }

            case SPICE_SDK_D3D9_INVALIDATE:
                if (g_imgui_initialized) {
                    ImGui_ImplDX9_InvalidateDeviceObjects();
                }
                break;

            case SPICE_SDK_D3D9_DESTROY:
                if (g_imgui_initialized) {
                    ImGui_ImplDX9_Shutdown();
                }
                ImGui::DestroyContext(g_imgui_ctx);
                g_imgui_ctx = nullptr;
                g_imgui_initialized = false;
                break;
        }
    }

    ImGui::SetCurrentContext(prev_ctx);
}

static void __cdecl sdk_destroy_callback(void) {
    log_msg("Spice2x SDK destroy callback invoked.");
}

}

static SPICE_SDK_V0 g_spice_sdk = {};

SPICE_SDK_ENTRY_POINT spice_sdk_entry_point(spice_sdk_init_func* init) {
    sdvx_acc::load_config();
    sdvx_acc::log_msg("spice_sdk_entry_point invoked.");
    g_spice_sdk = {};
    g_spice_sdk.size = sizeof(g_spice_sdk);

    SPICE_SDK_STATUS_CODE status = init(0, &sdvx_acc::sdk_destroy_callback, &g_spice_sdk);
    if (status != SPICE_SDK_STATUS_SUCCESS) {
        sdvx_acc::log_msg("ERROR: spice_sdk_init_func failed with status %d", static_cast<int>(status));
        return 0;
    }

    if (g_spice_sdk.register_d3d9) {
        status = g_spice_sdk.register_d3d9(&sdvx_acc::d3d9_callback, nullptr);
        sdvx_acc::log_msg("register_d3d9 returned status %d", static_cast<int>(status));
    }

    if (g_spice_sdk.add_toast) {
        char msg[128];
        snprintf(msg, sizeof(msg), "SDVX Accuracy Timeline loaded (%s: Live HUD | %s: Report)",
                 sdvx_acc::key_name_for_vk(sdvx_acc::g_ui.vk_toggle_live_hud),
                 sdvx_acc::key_name_for_vk(sdvx_acc::g_ui.vk_toggle_report));
        g_spice_sdk.add_toast(SPICE_SDK_TOAST_LEVEL_INFO, msg);
    }

    return 1;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hinstDLL);
        HANDLE hThread = CreateThread(nullptr, 0, &sdvx_acc::init_thread_proc, nullptr, 0, nullptr);
        if (hThread) CloseHandle(hThread);
    }
    return TRUE;
}
