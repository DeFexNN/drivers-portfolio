#pragma once
// firebase_auth.hpp  -  MidnightSoftware Loader Firebase Key Validator
//
// Validates a MIDNIGHT-GAME-XXXXXXXXXX key against Firestore REST API via WinHTTP.
// Checks: key exists, not banned, not expired, HWID matches (or binds it).
// On first use: automatically binds the machine HWID to the key.
// Writes an auth_logs entry on every attempt.
//
// Usage (from a background thread):
//   auto res = fb_auth::validate(key, fb_auth::get_hwid());
//   if (res.code != fb_auth::Code::OK) { /* handle */ }

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>
#include <winhttp.h>
#include <string>
#include <vector>
#pragma comment(lib, "winhttp.lib")

namespace fb_auth {

// --- config ------------------------------------------------------------------
static const char* const FB_PROJECT = "admin-panel-2d070";
static const char* const FB_APIKEY  = "AIzaSyAM2U16cKvk8jsIBreepnDsRkDiExg2tJ0";

// --- result ------------------------------------------------------------------
enum class Code : int {
    OK            = 0,
    INVALID_KEY   = 1,
    BANNED        = 2,
    EXPIRED       = 3,
    HWID_MISMATCH = 4,
    NETWORK_ERROR = 5,
    PARSE_ERROR   = 6
};

struct Result {
    Code        code;
    std::string reason;
    uint64_t    expires_at_unix = 0;  // Unix seconds parsed from Firestore
                                      // 0 = lifetime or unparseable
};

// --- HWID (explicit ANSI version to avoid Unicode/ANSI mismatch) -------------
inline std::string get_hwid()
{
    HW_PROFILE_INFOA info{};
    if (!GetCurrentHwProfileA(&info)) return "HWID_UNKNOWN";
    std::string raw = info.szHwProfileGuid;
    std::string out;
    out.reserve(raw.size());
    for (char c : raw)
        if (c != '{' && c != '}' && c != '-') out += c;
    return out;
}

namespace detail {

inline std::wstring to_wide(const std::string& s)
{
    if (s.empty()) return {};
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
    std::wstring w(static_cast<size_t>(n > 0 ? n : 1), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, &w[0], n);
    if (!w.empty() && w.back() == L'\0') w.pop_back();
    return w;
}

inline std::string utc_now_iso()
{
    SYSTEMTIME st{};
    GetSystemTime(&st);
    char buf[32];
    wsprintfA(buf, "%04d-%02d-%02dT%02d:%02d:%02dZ",
        (int)st.wYear,  (int)st.wMonth,  (int)st.wDay,
        (int)st.wHour,  (int)st.wMinute, (int)st.wSecond);
    return buf;
}

// --- HTTP wrapper ------------------------------------------------------------
struct HttpResp {
    int status;
    std::string body;
    HttpResp() : status(0) {}
};

inline HttpResp http(const wchar_t* method, const std::wstring& path,
                     const std::string& body_json = "")
{
    HttpResp r;

    HINTERNET sess = WinHttpOpen(L"MidnightLoader/1.0",
        WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!sess) { r.status = -1; return r; }

    HINTERNET conn = WinHttpConnect(sess, L"firestore.googleapis.com",
        INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (!conn) { WinHttpCloseHandle(sess); r.status = -1; return r; }

    HINTERNET req = WinHttpOpenRequest(conn, method, path.c_str(),
        nullptr, WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    if (!req) {
        WinHttpCloseHandle(conn);
        WinHttpCloseHandle(sess);
        r.status = -1;
        return r;
    }

#ifdef _DEBUG
    DWORD secf = SECURITY_FLAG_IGNORE_UNKNOWN_CA
               | SECURITY_FLAG_IGNORE_CERT_CN_INVALID
               | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID
               | SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
    WinHttpSetOption(req, WINHTTP_OPTION_SECURITY_FLAGS, &secf, sizeof(secf));
#endif

    DWORD to = 8000;
    WinHttpSetOption(req, WINHTTP_OPTION_CONNECT_TIMEOUT,    &to, sizeof(to));
    WinHttpSetOption(req, WINHTTP_OPTION_SEND_TIMEOUT,       &to, sizeof(to));
    WinHttpSetOption(req, WINHTTP_OPTION_RECEIVE_TIMEOUT,    &to, sizeof(to));

    const wchar_t* hdrs =
        L"Content-Type: application/json\r\nAccept: application/json";
    LPVOID body_ptr = body_json.empty() ? WINHTTP_NO_REQUEST_DATA
                                        : (LPVOID)body_json.c_str();
    DWORD body_len = (DWORD)body_json.size();

    BOOL ok = WinHttpSendRequest(req, hdrs, (DWORD)-1,
                                 body_ptr, body_len, body_len, 0);

    if (!ok || !WinHttpReceiveResponse(req, nullptr)) {
        r.status = -1;
    } else {
        DWORD sc = 0, sc_sz = sizeof(sc);
        WinHttpQueryHeaders(req,
            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            nullptr, &sc, &sc_sz, nullptr);
        r.status = (int)sc;

        DWORD avail = 0;
        while (WinHttpQueryDataAvailable(req, &avail) && avail > 0) {
            std::vector<char> buf(avail + 1, 0);
            DWORD nread = 0;
            WinHttpReadData(req, buf.data(), avail, &nread);
            r.body.append(buf.data(), nread);
        }
    }

    WinHttpCloseHandle(req);
    WinHttpCloseHandle(conn);
    WinHttpCloseHandle(sess);
    return r;
}

// --- Firestore JSON field extractor ------------------------------------------
inline std::string field(const std::string& json, const std::string& name)
{
    std::string key = "\"" + name + "\":{";
    size_t p = json.find(key);
    if (p == std::string::npos) return {};
    std::string sub = json.substr(p + key.size());

    // stringValue and timestampValue
    const char* sv_types[2] = { "stringValue", "timestampValue" };
    for (int i = 0; i < 2; ++i) {
        std::string k2 = std::string("\"") + sv_types[i] + "\":\"";
        size_t vp = sub.find(k2);
        if (vp != std::string::npos && vp < 80) {
            vp += k2.size();
            size_t ep = sub.find('"', vp);
            if (ep != std::string::npos) return sub.substr(vp, ep - vp);
        }
    }
    // integerValue
    {
        const char* k2 = "\"integerValue\":\"";
        size_t vp = sub.find(k2);
        if (vp != std::string::npos && vp < 80) {
            vp += ::strlen(k2);
            size_t ep = sub.find('"', vp);
            if (ep != std::string::npos) return sub.substr(vp, ep - vp);
        }
    }
    // booleanValue
    {
        const char* k2 = "\"booleanValue\":";
        size_t vp = sub.find(k2);
        if (vp != std::string::npos && vp < 80) {
            vp += ::strlen(k2);
            if (sub.compare(vp, 4, "true")  == 0) return "true";
            if (sub.compare(vp, 5, "false") == 0) return "false";
        }
    }
    return {};
}

// --- URL / request helpers ---------------------------------------------------
inline std::string doc_path(const std::string& coll, const std::string& doc_id)
{
    return std::string("/v1/projects/") + FB_PROJECT +
           "/databases/(default)/documents/" + coll + "/" + doc_id +
           "?key=" + FB_APIKEY;
}

inline bool patch_doc(const std::string& coll, const std::string& doc_id,
                      const std::string& fields_json,
                      const std::string& mask_params)
{
    std::string url = std::string("/v1/projects/") + FB_PROJECT +
        "/databases/(default)/documents/" + coll + "/" + doc_id +
        "?" + mask_params + "&key=" + FB_APIKEY;
    return http(L"PATCH", to_wide(url), fields_json).status == 200;
}

inline bool post_doc(const std::string& coll, const std::string& body_json)
{
    std::string url = std::string("/v1/projects/") + FB_PROJECT +
        "/databases/(default)/documents/" + coll + "?key=" + FB_APIKEY;
    int s = http(L"POST", to_wide(url), body_json).status;
    return (s >= 200 && s < 300);
}

// --- Firestore write operations ----------------------------------------------
inline bool bind_hwid(const std::string& key_id, const std::string& hwid)
{
    std::string body = "{\"fields\":{\"hwid\":{\"stringValue\":\""
                       + hwid + "\"}}}";
    return patch_doc("keys", key_id, body, "updateMask.fieldPaths=hwid");
}

inline void update_stats(const std::string& key_id, int prev_count)
{
    std::string now = utc_now_iso();
    char cnt[16];
    wsprintfA(cnt, "%d", prev_count + 1);
    std::string body =
        std::string("{\"fields\":{"
                    "\"auth_count\":{\"integerValue\":\"") + cnt + "\"},"
                    "\"last_auth\":{\"timestampValue\":\"" + now + "\"}}}";
    patch_doc("keys", key_id, body,
              "updateMask.fieldPaths=auth_count&updateMask.fieldPaths=last_auth");
}

inline void write_log(const std::string& key_id, const std::string& game,
                      const std::string& hwid, bool success,
                      const std::string& reason)
{
    std::string now = utc_now_iso();
    std::string suc = success ? "true" : "false";
    std::string body =
        std::string("{\"fields\":{"
                    "\"key\":{\"stringValue\":\"")           + key_id + "\"},"
                    "\"game\":{\"stringValue\":\""             + game   + "\"},"
                    "\"hwid\":{\"stringValue\":\""             + hwid   + "\"},"
                    "\"ip\":{\"stringValue\":\"n/a\"},"
                    "\"success\":{\"booleanValue\":"           + suc    + "},"
                    "\"reason\":{\"stringValue\":\""           + reason + "\"},"
                    "\"timestamp\":{\"timestampValue\":\"" + now + "\"}}}";
    post_doc("auth_logs", body);
}

inline bool is_expired(const std::string& expires_at)
{
    if (expires_at.empty()) return false;
    return utc_now_iso() > expires_at;
}

// Parse ISO 8601 timestamp "YYYY-MM-DDTHH:MM:SSZ" (or variants) to Unix
// seconds using the Win32 SystemTimeToFileTime path.  Returns 0 on failure.
inline uint64_t parse_iso8601_unix(const std::string& s)
{
    if (s.size() < 19) return 0;
    // sscanf is simplest; all fields are guaranteed ASCII digits in Firestore.
    int Y = 0, Mo = 0, D = 0, H = 0, Mi = 0, Se = 0;
    if (sscanf_s(s.c_str(), "%d-%d-%dT%d:%d:%d", &Y, &Mo, &D, &H, &Mi, &Se) < 6)
        return 0;
    SYSTEMTIME st{};
    st.wYear   = (WORD)Y;
    st.wMonth  = (WORD)Mo;
    st.wDay    = (WORD)D;
    st.wHour   = (WORD)H;
    st.wMinute = (WORD)Mi;
    st.wSecond = (WORD)Se;
    FILETIME ft{};
    if (!::SystemTimeToFileTime(&st, &ft)) return 0;
    uint64_t v = ((uint64_t)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
    if (v < 116444736000000000ULL) return 0;
    return (v - 116444736000000000ULL) / 10000000ULL;
}

inline std::string game_from_key(const std::string& key)
{
    size_t a = key.find('-');
    if (a == std::string::npos) return "UNKNOWN";
    size_t b = key.find('-', a + 1);
    if (b == std::string::npos) return "UNKNOWN";
    return key.substr(a + 1, b - a - 1);
}

} // namespace detail

// ============================================================================
//  validate()  --  run from a background thread
// ============================================================================
inline Result validate(const std::string& key_str, const std::string& hwid)
{
    Result r;

    if (key_str.empty()) {
        r.code = Code::INVALID_KEY; r.reason = "Empty key"; return r;
    }

    // 1. GET key document from Firestore
    detail::HttpResp resp = detail::http(L"GET",
        detail::to_wide(detail::doc_path("keys", key_str)));

    if (resp.status == -1) {
        r.code = Code::NETWORK_ERROR; r.reason = "Network unreachable"; return r;
    }
    if (resp.status == 404 ||
        resp.body.find("NOT_FOUND") != std::string::npos) {
        r.code = Code::INVALID_KEY; r.reason = "Key not found"; return r;
    }
    if (resp.status != 200) {
        r.code = Code::PARSE_ERROR;
        r.reason = "Firebase HTTP " + std::to_string(resp.status); return r;
    }

    // 2. Parse document fields
    std::string status    = detail::field(resp.body, "status");
    std::string stored_hw = detail::field(resp.body, "hwid");
    std::string expires   = detail::field(resp.body, "expires_at");
    std::string game      = detail::field(resp.body, "game");
    std::string cnt_str   = detail::field(resp.body, "auth_count");
    int auth_count        = cnt_str.empty() ? 0 : ::atoi(cnt_str.c_str());

    if (game.empty()) game = detail::game_from_key(key_str);

    // 3. Banned?
    if (status == "banned") {
        detail::write_log(key_str, game, hwid, false, "BANNED");
        r.code = Code::BANNED; r.reason = "Key is banned"; return r;
    }

    // 4. Expired?
    if (detail::is_expired(expires)) {
        detail::write_log(key_str, game, hwid, false, "EXPIRED");
        r.code = Code::EXPIRED; r.reason = "Key has expired"; return r;
    }

    // 5. HWID: bind on first use, verify on subsequent uses
    if (stored_hw.empty()) {
        detail::bind_hwid(key_str, hwid);
    } else if (stored_hw != hwid) {
        detail::write_log(key_str, game, hwid, false, "HWID_MISMATCH");
        r.code = Code::HWID_MISMATCH; r.reason = "HWID mismatch"; return r;
    }

    // 6. All checks passed
    detail::update_stats(key_str, auth_count);
    detail::write_log(key_str, game, hwid, true, "OK");
    r.code             = Code::OK;
    r.reason           = "OK";
    r.expires_at_unix  = detail::parse_iso8601_unix(expires);  // 0 if lifetime
    return r;
}

// Human-readable string for ImGui error display
inline const char* code_to_str(Code c)
{
    switch (c) {
        case Code::OK:            return "OK";
        case Code::INVALID_KEY:   return "Key not found.";
        case Code::BANNED:        return "Key is banned.";
        case Code::EXPIRED:       return "Key has expired.";
        case Code::HWID_MISMATCH: return "HWID mismatch. Contact support to reset.";
        case Code::NETWORK_ERROR: return "Network error. Check your connection.";
        default:                  return "Unknown error. Check the log.";
    }
}

} // namespace fb_auth
