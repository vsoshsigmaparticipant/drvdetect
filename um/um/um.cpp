#include <winsock2.h>
#include <ws2tcpip.h>

#include "framework.h"
#include "shared.h"

#include <d3d11.h>
#include <wincrypt.h>
#include <algorithm>
#include <cstdlib>
#include <cwchar>
#include <deque>
#include <shellapi.h>
#include <vector>
#include <winsvc.h>
#include <string>
#include <utility>

#include "vendor/imgui/imgui.h"
#include "vendor/imgui/backends/imgui_impl_dx11.h"
#include "vendor/imgui/backends/imgui_impl_win32.h"

#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "dxgi.lib")
#pragma comment(lib, "Shell32.lib")
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Advapi32.lib")

struct UiAlert
{
    std::string TimeText;
    std::string TypeText;
    unsigned long ProcessId;
    std::string Message;
    std::string Summary;
    std::string ProcessPath;
    std::string DriverPath;
    std::string RegistryPath;
    std::string ValueText;
    bool Blocked = false;
};

struct InsightState
{
    bool LastThreatBlocked = false;
    bool HasThreat = false;
};

struct AppState
{
    HANDLE Device = INVALID_HANDLE_VALUE;
    DRVDETECT_STATE DriverState = { DRVDETECT_STATE_VERSION, DrvDetectBlockingOn };
    std::deque<UiAlert> Alerts;
    std::deque<std::string> InstallerLog;
    InsightState Insight = {};
    std::wstring StatusLine = L"Disconnected";
    ULONGLONG LastConnectTick = 0;
    ULONGLONG LastInstallAttemptTick = 0;
    ULONGLONG LastStatePollTick = 0;
    bool AutoScroll = true;
    int SelectedAlertVisibleIndex = -1;
    bool ShowingAlertDetails = false;
};

static ID3D11Device* g_D3dDevice = nullptr;
static ID3D11DeviceContext* g_D3dContext = nullptr;
static IDXGISwapChain* g_SwapChain = nullptr;
static ID3D11RenderTargetView* g_RenderTargetView = nullptr;
static ImFont* g_HeaderFont = nullptr;
static ImFont* g_BodyFont = nullptr;
static AppState g_App;
static const wchar_t* g_ServiceName = L"DrvDetect";
static constexpr float kPanelPadding = 20.0f;
static bool g_WebShutdownRequested = false;
static constexpr unsigned short kDefaultWebPort = 8080;
static unsigned short g_WebPort = kDefaultWebPort;
static std::string g_WebAuthToken;

// SHA-256 hash of the trusted km.sys binary. Update this after each driver build.
static const char* kExpectedDriverHash = "0000000000000000000000000000000000000000000000000000000000000000";

static std::wstring GetExecutableDirectory();
static std::wstring JoinPath(const std::wstring& base, const wchar_t* name);
static std::string WideToUtf8(const wchar_t* text);
static void AppendInstallerLog(const std::wstring& message);
static void DisconnectDevice(const wchar_t* reason);
static bool QueryDriverState(bool updateStatusOnError);
static bool SetBlockingState(unsigned long blockingState);
static void PumpDriver();
static int CountThreatAlerts();
static const char* GetAlertKindLabel(const UiAlert& alert);

static bool TryParsePort(const wchar_t* text, unsigned short* portOut)
{
    if (text == nullptr || *text == L'\0' || portOut == nullptr)
    {
        return false;
    }

    wchar_t* end = nullptr;
    const unsigned long value = wcstoul(text, &end, 10);
    if (end == text || *end != L'\0' || value == 0 || value > 65535)
    {
        return false;
    }

    *portOut = static_cast<unsigned short>(value);
    return true;
}

static bool TryGetWebModePort(PWSTR commandLine, unsigned short* portOut)
{
    UNREFERENCED_PARAMETER(commandLine);

    int argc = 0;
    wchar_t** argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    if (argv == nullptr)
    {
        return false;
    }

    bool webMode = false;
    unsigned short selectedPort = kDefaultWebPort;

    for (int i = 1; i < argc; ++i)
    {
        const wchar_t* argument = argv[i];
        if (_wcsicmp(argument, L"--web") == 0)
        {
            webMode = true;
            continue;
        }

        if (_wcsicmp(argument, L"--browser") == 0)
        {
            webMode = true;
            continue;
        }

        if (_wcsnicmp(argument, L"--port=", 7) == 0)
        {
            unsigned short parsedPort = 0;
            if (TryParsePort(argument + 7, &parsedPort))
            {
                selectedPort = parsedPort;
            }
            continue;
        }

        if (_wcsicmp(argument, L"--port") == 0 && (i + 1) < argc)
        {
            unsigned short parsedPort = 0;
            if (TryParsePort(argv[i + 1], &parsedPort))
            {
                selectedPort = parsedPort;
            }
            ++i;
        }
    }

    LocalFree(argv);

    if (!webMode || portOut == nullptr)
    {
        return webMode;
    }

    *portOut = selectedPort;
    return true;
}

static std::string JsonEscape(const std::string& value)
{
    std::string escaped;
    escaped.reserve(value.size() + 16);

    for (unsigned char ch : value)
    {
        switch (ch)
        {
        case '"':
            escaped += "\\\"";
            break;
        case '\\':
            escaped += "\\\\";
            break;
        case '\b':
            escaped += "\\b";
            break;
        case '\f':
            escaped += "\\f";
            break;
        case '\n':
            escaped += "\\n";
            break;
        case '\r':
            escaped += "\\r";
            break;
        case '\t':
            escaped += "\\t";
            break;
        default:
            if (ch < 0x20)
            {
                char buffer[7] = {};
                sprintf_s(buffer, "\\u%04x", ch);
                escaped += buffer;
            }
            else
            {
                escaped.push_back(static_cast<char>(ch));
            }
            break;
        }
    }

    return escaped;
}

static void AppendJsonString(std::string& output, const std::string& value)
{
    output.push_back('"');
    output += JsonEscape(value);
    output.push_back('"');
}

static void AppendJsonBool(std::string& output, bool value)
{
    output += value ? "true" : "false";
}

static std::string BuildAlertJson(const UiAlert& alert)
{
    std::string json;
    json.reserve(512);
    json += "{";
    json += "\"time\":";
    AppendJsonString(json, alert.TimeText);
    json += ",\"type\":";
    AppendJsonString(json, alert.TypeText);
    json += ",\"processId\":" + std::to_string(alert.ProcessId);
    json += ",\"message\":";
    AppendJsonString(json, alert.Message);
    json += ",\"summary\":";
    AppendJsonString(json, alert.Summary);
    json += ",\"processPath\":";
    AppendJsonString(json, alert.ProcessPath);
    json += ",\"driverPath\":";
    AppendJsonString(json, alert.DriverPath);
    json += ",\"registryPath\":";
    AppendJsonString(json, alert.RegistryPath);
    json += ",\"value\":";
    AppendJsonString(json, alert.ValueText);
    json += ",\"blocked\":";
    AppendJsonBool(json, alert.Blocked);
    json += ",\"kind\":";
    AppendJsonString(json, GetAlertKindLabel(alert));
    json += "}";
    return json;
}

static std::string BuildStateJson()
{
    std::string json;
    json += "{";
    json += "\"connected\":";
    AppendJsonBool(json, g_App.Device != INVALID_HANDLE_VALUE);
    json += ",\"status\":";
    AppendJsonString(json, WideToUtf8(g_App.StatusLine.c_str()));
    json += ",\"blockingEnabled\":";
    AppendJsonBool(json, g_App.DriverState.BlockingState == DrvDetectBlockingOn);
    json += ",\"pendingAlerts\":" + std::to_string(g_App.DriverState.PendingAlerts);
    json += ",\"threatCount\":" + std::to_string(CountThreatAlerts());
    json += ",\"hasThreat\":";
    AppendJsonBool(json, g_App.Insight.HasThreat);
    json += ",\"lastThreatBlocked\":";
    AppendJsonBool(json, g_App.Insight.LastThreatBlocked);
    json += "}";
    return json;
}

static std::string BuildAlertsJson()
{
    std::string json = "[";
    bool first = true;
    for (const UiAlert& alert : g_App.Alerts)
    {
        if (!first)
        {
            json += ",";
        }

        first = false;
        json += BuildAlertJson(alert);
    }

    json += "]";
    return json;
}

static std::string BuildSnapshotJson()
{
    std::string json = BuildStateJson();
    json.pop_back();
    json += ",\"alerts\":";
    json += BuildAlertsJson();
    json += ",\"installerLog\":[";

    bool first = true;
    for (const std::string& line : g_App.InstallerLog)
    {
        if (!first)
        {
            json += ",";
        }

        first = false;
        AppendJsonString(json, line);
    }

    json += "]}";
    return json;
}

static bool SendAll(SOCKET socketHandle, const char* data, int length)
{
    int sent = 0;
    while (sent < length)
    {
        const int chunk = send(socketHandle, data + sent, length - sent, 0);
        if (chunk == SOCKET_ERROR)
        {
            return false;
        }

        sent += chunk;
    }

    return true;
}

static void SendHttpResponse(SOCKET socketHandle, const char* status, const char* contentType, const std::string& body)
{
    std::string headers = "HTTP/1.1 ";
    headers += status;
    headers += "\r\nContent-Type: ";
    headers += contentType;
    headers += "\r\nContent-Length: ";
    headers += std::to_string(body.size());
    headers += "\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n";

    SendAll(socketHandle, headers.c_str(), static_cast<int>(headers.size()));
    SendAll(socketHandle, body.c_str(), static_cast<int>(body.size()));
}

static std::string GetQueryValue(const std::string& query, const char* key)
{
    const std::string prefix = std::string(key) + "=";
    size_t searchStart = 0;
    while (searchStart < query.size())
    {
        const size_t end = query.find('&', searchStart);
        const std::string part = query.substr(searchStart, end == std::string::npos ? std::string::npos : end - searchStart);
        if (part.compare(0, prefix.size(), prefix) == 0)
        {
            return part.substr(prefix.size());
        }

        if (end == std::string::npos)
        {
            break;
        }

        searchStart = end + 1;
    }

    return {};
}

static std::string BuildWebPage(unsigned short port)
{
    std::string page = R"HTML(<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>DrvDetect Web Console</title>
<style>
:root{color-scheme:dark;font-family:Segoe UI,Arial,sans-serif;background:#070b12;color:#edf2ff}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at top,#15233a 0,#070b12 52%,#04060a 100%)}
.shell{max-width:1400px;margin:0 auto;padding:24px}.hero{display:grid;gap:16px;grid-template-columns:2fr 1fr;align-items:stretch}
.panel{background:rgba(15,21,34,.88);border:1px solid rgba(123,154,255,.12);border-radius:24px;padding:20px;box-shadow:0 18px 60px rgba(0,0,0,.28)}
.title{font-size:14px;text-transform:uppercase;letter-spacing:.16em;color:#8ca0d7;margin-bottom:10px}.headline{font-size:36px;font-weight:700;margin:0 0 8px}
.sub{color:#b5c0dd;line-height:1.5}.stats{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:16px;margin-top:16px}
.stat{padding:16px;border-radius:18px;background:#101827;border:1px solid rgba(255,255,255,.05)}.stat strong{display:block;font-size:26px;margin-top:8px}
.status{display:flex;align-items:center;gap:10px;font-size:14px;color:#b7c3e4}.dot{width:12px;height:12px;border-radius:50%;background:#e46d51;box-shadow:0 0 18px rgba(228,109,81,.65)}
.dot.ok{background:#34d399;box-shadow:0 0 18px rgba(52,211,153,.65)}.controls{display:flex;flex-wrap:wrap;gap:12px;margin-top:18px}
button{border:0;border-radius:999px;padding:12px 18px;font-weight:700;cursor:pointer;color:#06111f;background:linear-gradient(135deg,#79f2c0,#34d399)}
button.alt{background:linear-gradient(135deg,#ffd67d,#f59e0b)}button.stop{background:linear-gradient(135deg,#ff8a8a,#ef4444);color:#fff}
.layout{display:grid;grid-template-columns:1.4fr .8fr;gap:16px;margin-top:16px}.list{display:grid;gap:12px;max-height:70vh;overflow:auto;padding-right:4px}
.alert{padding:16px;border-radius:20px;background:#0f1725;border:1px solid rgba(255,255,255,.05)}.alert.blocked{border-color:rgba(52,211,153,.35)}.alert.detected{border-color:rgba(245,158,11,.35)}
.meta{display:flex;gap:12px;flex-wrap:wrap;color:#8ea0cc;font-size:13px;margin-bottom:8px}.summary{font-size:20px;font-weight:700;margin-bottom:8px}.path{word-break:break-word;color:#d4def7}
.pill{display:inline-flex;align-items:center;padding:5px 10px;border-radius:999px;font-size:12px;font-weight:700;text-transform:uppercase;letter-spacing:.08em}
.pill.blocked{background:rgba(52,211,153,.16);color:#7bf0c0}.pill.detected{background:rgba(245,158,11,.16);color:#ffd07a}.stack{display:grid;gap:10px}
.logline{font-family:Consolas,monospace;font-size:13px;color:#c7d4f7;background:#0e1521;padding:10px 12px;border-radius:14px}.empty{color:#8ea0cc;padding:18px;border:1px dashed rgba(255,255,255,.1);border-radius:18px}
@media (max-width:980px){.hero,.layout,.stats{grid-template-columns:1fr}.headline{font-size:30px}.shell{padding:16px}}
</style>
</head>
<body>
<div class="shell">
  <div class="hero">
    <section class="panel">
      <div class="title">DrvDetect</div>
      <h1 class="headline">Browser dashboard for the usermode monitor</h1>
      <div class="sub">This page talks to the local DrvDetect usermode process on <strong>127.0.0.1:)HTML";
    page += std::to_string(port);
    page += R"HTML(</strong> and shows live state, alerts, and bootstrap logs.</div>
      <div class="stats">
        <div class="stat"><div>Threat alerts</div><strong id="threatCount">0</strong></div>
        <div class="stat"><div>Pending in driver</div><strong id="pendingAlerts">0</strong></div>
        <div class="stat"><div>Blocking mode</div><strong id="blockingState">Off</strong></div>
        <div class="stat"><div>Last verdict</div><strong id="lastVerdict">None</strong></div>
      </div>
      <div class="controls">
        <button id="enableBtn">Enable blocking</button>
        <button id="disableBtn" class="alt">Disable blocking</button>
        <button id="refreshBtn" class="alt">Refresh now</button>
        <button id="shutdownBtn" class="stop">Stop web mode</button>
      </div>
    </section>
    <aside class="panel">
      <div class="title">Connection</div>
      <div class="status"><span id="statusDot" class="dot"></span><span id="statusLine">Starting...</span></div>
      <div class="sub" style="margin-top:14px">The web UI is read-only except for blocking toggles and server shutdown. The driver/device path stays in the native usermode process.</div>
    </aside>
  </div>
  <div class="layout">
    <section class="panel">
      <div class="title">Alerts</div>
      <div id="alerts" class="list"></div>
    </section>
    <aside class="panel">
      <div class="title">Bootstrap Log</div>
      <div id="log" class="stack"></div>
    </aside>
  </div>
</div>
<script>
const els={
  threatCount:document.getElementById('threatCount'),pendingAlerts:document.getElementById('pendingAlerts'),blockingState:document.getElementById('blockingState'),
  lastVerdict:document.getElementById('lastVerdict'),statusDot:document.getElementById('statusDot'),statusLine:document.getElementById('statusLine'),
  alerts:document.getElementById('alerts'),log:document.getElementById('log')
};
function esc(value){return String(value??'').replace(/[&<>"']/g,ch=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch]));}
function renderAlerts(alerts){
  if(!alerts.length){els.alerts.innerHTML='<div class="empty">No alerts yet.</div>';return;}
  els.alerts.innerHTML=alerts.map(alert=>{
    const verdict=alert.blocked?'THREAT BLOCKED':'THREAT DETECTED';
    const cardClass=alert.blocked?'blocked':'detected';
    const detail=alert.processPath||alert.driverPath||alert.registryPath||alert.message;
    return `<article class="alert ${cardClass}"><div class="meta"><span>${esc(alert.time)}</span><span>${esc(alert.type)}</span><span>PID ${esc(alert.processId)}</span><span class="pill ${cardClass}">${verdict}</span></div><div class="summary">${esc(alert.summary||alert.type)}</div><div class="path">${esc(detail)}</div><div class="sub" style="margin-top:10px">${esc(alert.message)}</div></article>`;
  }).join('');
}
function renderLog(lines){
  if(!lines.length){els.log.innerHTML='<div class="empty">No bootstrap activity logged yet.</div>';return;}
  els.log.innerHTML=lines.map(line=>`<div class="logline">${esc(line)}</div>`).join('');
}
function render(snapshot){
  els.threatCount.textContent=snapshot.threatCount;
  els.pendingAlerts.textContent=snapshot.pendingAlerts;
  els.blockingState.textContent=snapshot.blockingEnabled?'On':'Off';
  els.lastVerdict.textContent=snapshot.hasThreat?(snapshot.lastThreatBlocked?'Blocked':'Detected'):'None';
  els.statusLine.textContent=snapshot.status;
  els.statusDot.className='dot'+(snapshot.connected?' ok':'');
  renderAlerts(snapshot.alerts||[]);
  renderLog(snapshot.installerLog||[]);
}
async function refresh(){
  try{
    const response=await fetch('/api/snapshot',{cache:'no-store'});
    render(await response.json());
  }catch(error){
    els.statusLine.textContent='Web UI lost contact with the local process';
    els.statusDot.className='dot';
  }
}
async function setBlocking(enabled){
  await fetch(`/api/blocking?enabled=${enabled?1:0}`,{method:'POST',headers:{'X-Auth-Token':window.__TOKEN}});
  await refresh();
}
document.getElementById('enableBtn').addEventListener('click',()=>setBlocking(true));
document.getElementById('disableBtn').addEventListener('click',()=>setBlocking(false));
document.getElementById('refreshBtn').addEventListener('click',refresh);
document.getElementById('shutdownBtn').addEventListener('click',async()=>{
  if(!confirm('Stop the DrvDetect web server?')){return;}
  await fetch('/api/shutdown',{method:'POST',headers:{'X-Auth-Token':window.__TOKEN}});
  els.statusLine.textContent='Shutdown requested';
});
refresh();
setInterval(refresh,1000);
</script>
</body>
</html>)HTML";

    page.insert(page.find("<script>") + 8, "\nwindow.__TOKEN='" + g_WebAuthToken + "';\n");
    return page;
}

static std::string GenerateAuthToken()
{
    HCRYPTPROV hProv = 0;
    BYTE randomBytes[32] = {};
    std::string token;
    token.reserve(64);

    if (CryptAcquireContextW(&hProv, nullptr, nullptr, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
    {
        CryptGenRandom(hProv, sizeof(randomBytes), randomBytes);
        CryptReleaseContext(hProv, 0);
    }
    else
    {
        LARGE_INTEGER counter = {};
        QueryPerformanceCounter(&counter);
        DWORD pid = GetCurrentProcessId();
        DWORD tick = GetTickCount();
        memcpy(randomBytes, &counter, sizeof(counter));
        memcpy(randomBytes + 8, &pid, sizeof(pid));
        memcpy(randomBytes + 12, &tick, sizeof(tick));
    }

    const char hex[] = "0123456789abcdef";
    for (int i = 0; i < 32; ++i)
    {
        token.push_back(hex[(randomBytes[i] >> 4) & 0x0F]);
        token.push_back(hex[randomBytes[i] & 0x0F]);
    }

    return token;
}

static bool RequestHasValidToken(const std::string& request)
{
    const std::string headerName = "X-Auth-Token: ";
    size_t pos = request.find(headerName);
    if (pos == std::string::npos)
    {
        return false;
    }

    size_t valueStart = pos + headerName.size();
    size_t valueEnd = request.find("\r\n", valueStart);
    if (valueEnd == std::string::npos)
    {
        valueEnd = request.size();
    }

    std::string providedToken = request.substr(valueStart, valueEnd - valueStart);
    return providedToken == g_WebAuthToken;
}

static void HandleHttpRequest(SOCKET clientSocket)
{
    char buffer[16384] = {};
    const int received = recv(clientSocket, buffer, static_cast<int>(sizeof(buffer) - 1), 0);
    if (received <= 0)
    {
        return;
    }

    buffer[received] = '\0';
    std::string request(buffer, received);
    const size_t lineEnd = request.find("\r\n");
    if (lineEnd == std::string::npos)
    {
        SendHttpResponse(clientSocket, "400 Bad Request", "text/plain; charset=utf-8", "Malformed request");
        return;
    }

    const std::string requestLine = request.substr(0, lineEnd);
    const size_t firstSpace = requestLine.find(' ');
    const size_t secondSpace = requestLine.find(' ', firstSpace == std::string::npos ? firstSpace : firstSpace + 1);
    if (firstSpace == std::string::npos || secondSpace == std::string::npos)
    {
        SendHttpResponse(clientSocket, "400 Bad Request", "text/plain; charset=utf-8", "Malformed request line");
        return;
    }

    const std::string method = requestLine.substr(0, firstSpace);
    const std::string target = requestLine.substr(firstSpace + 1, secondSpace - firstSpace - 1);
    const size_t queryPos = target.find('?');
    const std::string path = queryPos == std::string::npos ? target : target.substr(0, queryPos);
    const std::string query = queryPos == std::string::npos ? std::string() : target.substr(queryPos + 1);

    PumpDriver();

    if (method == "GET" && path == "/")
    {
        SendHttpResponse(clientSocket, "200 OK", "text/html; charset=utf-8", BuildWebPage(g_WebPort));
        return;
    }

    if (method == "GET" && path == "/favicon.ico")
    {
        SendHttpResponse(clientSocket, "204 No Content", "text/plain; charset=utf-8", "");
        return;
    }

    if (method == "GET" && path == "/api/state")
    {
        SendHttpResponse(clientSocket, "200 OK", "application/json; charset=utf-8", BuildStateJson());
        return;
    }

    if (method == "GET" && path == "/api/alerts")
    {
        SendHttpResponse(clientSocket, "200 OK", "application/json; charset=utf-8", BuildAlertsJson());
        return;
    }

    if (method == "GET" && path == "/api/snapshot")
    {
        SendHttpResponse(clientSocket, "200 OK", "application/json; charset=utf-8", BuildSnapshotJson());
        return;
    }

    if (method == "POST" && path == "/api/blocking")
    {
        if (!RequestHasValidToken(request))
        {
            SendHttpResponse(clientSocket, "403 Forbidden", "application/json; charset=utf-8", "{\"error\":\"invalid token\"}");
            return;
        }

        const std::string enabledValue = GetQueryValue(query, "enabled");
        const unsigned long blockingState = enabledValue == "1" || enabledValue == "true" ? DrvDetectBlockingOn : DrvDetectBlockingOff;
        if (!SetBlockingState(blockingState))
        {
            SendHttpResponse(clientSocket, "503 Service Unavailable", "application/json; charset=utf-8", BuildStateJson());
            return;
        }

        QueryDriverState(false);
        SendHttpResponse(clientSocket, "200 OK", "application/json; charset=utf-8", BuildStateJson());
        return;
    }

    if (method == "POST" && path == "/api/shutdown")
    {
        if (!RequestHasValidToken(request))
        {
            SendHttpResponse(clientSocket, "403 Forbidden", "application/json; charset=utf-8", "{\"error\":\"invalid token\"}");
            return;
        }

        g_WebShutdownRequested = true;
        SendHttpResponse(clientSocket, "200 OK", "application/json; charset=utf-8", "{\"ok\":true}");
        return;
    }

    SendHttpResponse(clientSocket, "404 Not Found", "text/plain; charset=utf-8", "Not found");
}

static int RunWebServer(unsigned short port)
{
    g_WebPort = port;
    g_WebAuthToken = GenerateAuthToken();

    WSADATA wsaData = {};
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
    {
        MessageBoxW(nullptr, L"WSAStartup failed.", L"DrvDetect", MB_ICONERROR | MB_OK);
        return 1;
    }

    SOCKET listenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listenSocket == INVALID_SOCKET)
    {
        WSACleanup();
        MessageBoxW(nullptr, L"Could not create the web server socket.", L"DrvDetect", MB_ICONERROR | MB_OK);
        return 1;
    }

    sockaddr_in address = {};
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    if (bind(listenSocket, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) == SOCKET_ERROR ||
        listen(listenSocket, SOMAXCONN) == SOCKET_ERROR)
    {
        closesocket(listenSocket);
        WSACleanup();
        MessageBoxW(nullptr, L"Could not bind the web server to 127.0.0.1.", L"DrvDetect", MB_ICONERROR | MB_OK);
        return 1;
    }

    u_long nonBlocking = 1;
    ioctlsocket(listenSocket, FIONBIO, &nonBlocking);

    wchar_t urlBuffer[128] = {};
    swprintf_s(urlBuffer, L"http://127.0.0.1:%u/", port);
    g_App.StatusLine = L"Web dashboard ready";
    AppendInstallerLog(L"Web dashboard listening on " + std::wstring(urlBuffer));
    ShellExecuteW(nullptr, L"open", urlBuffer, nullptr, nullptr, SW_SHOWNORMAL);

    g_WebShutdownRequested = false;
    while (!g_WebShutdownRequested)
    {
        PumpDriver();

        fd_set readSet = {};
        FD_ZERO(&readSet);
        FD_SET(listenSocket, &readSet);

        TIMEVAL timeout = {};
        timeout.tv_sec = 0;
        timeout.tv_usec = 200000;

        const int ready = select(0, &readSet, nullptr, nullptr, &timeout);
        if (ready > 0 && FD_ISSET(listenSocket, &readSet))
        {
            SOCKET clientSocket = accept(listenSocket, nullptr, nullptr);
            if (clientSocket != INVALID_SOCKET)
            {
                u_long clientBlocking = 0;
                ioctlsocket(clientSocket, FIONBIO, &clientBlocking);
                HandleHttpRequest(clientSocket);
                closesocket(clientSocket);
            }
        }
    }

    DisconnectDevice(L"Web mode stopped");
    closesocket(listenSocket);
    WSACleanup();
    return 0;
}

static const wchar_t* AlertTypeToText(unsigned long type)
{
    switch (type)
    {
    case AlertTypeProcessBlocked:
        return L"PROCESS_BLOCKED";
    case AlertTypeKernelImageSuspicious:
        return L"KERNEL_IMAGE_SUSPICIOUS";
    default:
        return L"UNKNOWN";
    }
}

static std::string WideToUtf8(const wchar_t* text)
{
    if (text == nullptr || *text == L'\0')
    {
        return {};
    }

    const int sourceLength = static_cast<int>(wcslen(text));
    const int required = WideCharToMultiByte(CP_UTF8, 0, text, sourceLength, nullptr, 0, nullptr, nullptr);
    if (required <= 0)
    {
        return {};
    }

    std::string result(static_cast<size_t>(required), '\0');
    WideCharToMultiByte(CP_UTF8, 0, text, sourceLength, &result[0], required, nullptr, nullptr);
    return result;
}

static std::wstring Utf8ToWide(const std::string& text)
{
    if (text.empty())
    {
        return {};
    }

    const int required = MultiByteToWideChar(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()), nullptr, 0);
    if (required <= 0)
    {
        return {};
    }

    std::wstring result(static_cast<size_t>(required), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, text.c_str(), static_cast<int>(text.size()), &result[0], required);
    return result;
}

static void AppendInstallerLog(const std::wstring& message)
{
    SYSTEMTIME now = {};
    GetLocalTime(&now);

    wchar_t prefix[32] = {};
    swprintf_s(prefix, L"%02u:%02u:%02u ", now.wHour, now.wMinute, now.wSecond);

    const std::wstring line = prefix + message;
    g_App.InstallerLog.push_front(WideToUtf8(line.c_str()));
    while (g_App.InstallerLog.size() > 24)
    {
        g_App.InstallerLog.pop_back();
    }

    const std::wstring logPath = JoinPath(GetExecutableDirectory(), L"drvdetect-bootstrap.log");
    HANDLE file = CreateFileW(
        logPath.c_str(),
        FILE_APPEND_DATA,
        FILE_SHARE_READ,
        nullptr,
        OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);

    if (file == INVALID_HANDLE_VALUE)
    {
        return;
    }

    std::string utf8Line = WideToUtf8(line.c_str());
    utf8Line.append("\r\n");
    DWORD written = 0;
    WriteFile(file, utf8Line.data(), static_cast<DWORD>(utf8Line.size()), &written, nullptr);
    CloseHandle(file);
}

static std::string FormatTimestamp(const LARGE_INTEGER& timestamp)
{
    FILETIME fileTime = {};
    SYSTEMTIME systemTime = {};
    wchar_t buffer[64] = {};

    fileTime.dwLowDateTime = timestamp.LowPart;
    fileTime.dwHighDateTime = timestamp.HighPart;

    if (!FileTimeToSystemTime(&fileTime, &systemTime))
    {
        return "--:--:--";
    }

    swprintf_s(
        buffer,
        L"%02u:%02u:%02u.%03u",
        systemTime.wHour,
        systemTime.wMinute,
        systemTime.wSecond,
        systemTime.wMilliseconds);

    return WideToUtf8(buffer);
}

static bool StartsWith(const std::string& value, const char* prefix)
{
    const size_t length = strlen(prefix);
    return value.size() >= length && value.compare(0, length, prefix) == 0;
}

static std::string Trim(const std::string& value)
{
    size_t start = 0;
    size_t end = value.size();

    while (start < end && (value[start] == ' ' || value[start] == '\t'))
    {
        ++start;
    }

    while (end > start && (value[end - 1] == ' ' || value[end - 1] == '\t'))
    {
        --end;
    }

    return value.substr(start, end - start);
}

static std::string ExtractAfter(const std::string& value, const char* marker)
{
    const size_t position = value.find(marker);
    if (position == std::string::npos)
    {
        return {};
    }

    return Trim(value.substr(position + strlen(marker)));
}

static std::string ExtractBetween(const std::string& value, const char* startMarker, const char* endMarker)
{
    const size_t start = value.find(startMarker);
    if (start == std::string::npos)
    {
        return {};
    }

    const size_t contentStart = start + strlen(startMarker);
    const size_t end = value.find(endMarker, contentStart);
    if (end == std::string::npos || end <= contentStart)
    {
        return Trim(value.substr(contentStart));
    }

    return Trim(value.substr(contentStart, end - contentStart));
}

static std::string ExtractLastPathLikeToken(const std::string& value)
{
    size_t best = std::string::npos;
    const char* markers[] = { "\\??\\", "\\Device\\", "C:\\", "D:\\", "E:\\" };

    for (const char* marker : markers)
    {
        const size_t pos = value.find(marker);
        if (pos != std::string::npos && (best == std::string::npos || pos < best))
        {
            best = pos;
        }
    }

    if (best == std::string::npos)
    {
        return {};
    }

    return Trim(value.substr(best));
}

static void ParseAlert(UiAlert& alert)
{
    alert.Blocked = alert.TypeText == "PROCESS_BLOCKED" || StartsWith(alert.Message, "Blocked ");
    alert.Summary = alert.Message;

    if (StartsWith(alert.Message, "Blocked known mapper process: ") ||
        StartsWith(alert.Message, "Observed known mapper process while blocking is off: "))
    {
        alert.ProcessPath = ExtractBetween(alert.Message, ": ", " (pid=");
        alert.Summary = alert.Blocked ? "Known mapper launch blocked" : "Known mapper launch observed";
    }
    else if (StartsWith(alert.Message, "Legacy callback matched mapper path: ") ||
             StartsWith(alert.Message, "Legacy callback observed mapper path while blocking is off: "))
    {
        alert.ProcessPath = ExtractAfter(alert.Message, ": ");
        alert.Summary = alert.Blocked ? "Legacy mapper process hit" : "Legacy mapper process observed";
    }
    else if (StartsWith(alert.Message, "Blocked suspicious ImagePath write before service resolution: ") ||
             StartsWith(alert.Message, "Observed suspicious ImagePath write while blocking is off: "))
    {
        alert.DriverPath = ExtractAfter(alert.Message, ": ");
        alert.Summary = alert.Blocked ? "Suspicious driver path write blocked" : "Suspicious driver path write observed";
    }
    else if (StartsWith(alert.Message, "Blocked kdmapper-like vulnerable-driver staging: ") ||
             StartsWith(alert.Message, "Observed kdmapper-like vulnerable-driver staging while blocking is off: "))
    {
        alert.RegistryPath = ExtractBetween(alert.Message, "key=", " img=");
        alert.DriverPath = ExtractAfter(alert.Message, "img=");
        alert.Summary = alert.Blocked ? "Driver staging blocked" : "Driver staging observed";
    }
    else if (StartsWith(alert.Message, "Observed ImagePath: "))
    {
        alert.DriverPath = ExtractAfter(alert.Message, ": ");
        alert.Summary = "Driver image path observed";
    }
    else if (StartsWith(alert.Message, "Registry write key="))
    {
        alert.RegistryPath = ExtractBetween(alert.Message, "key=", " value=");
        alert.ValueText = ExtractAfter(alert.Message, "value=");
        alert.DriverPath = ExtractLastPathLikeToken(alert.Message);
        alert.Summary = "Registry write observed";
    }
    else if (StartsWith(alert.Message, "Known vulnerable helper driver loaded: "))
    {
        alert.DriverPath = ExtractAfter(alert.Message, ": ");
        alert.Summary = "Known vulnerable helper driver loaded";
    }
    else if (StartsWith(alert.Message, "Suspicious kernel image load: "))
    {
        alert.DriverPath = ExtractBetween(alert.Message, "path=", " sigLevel=");
        alert.Summary = "Kernel image load looks suspicious";
    }
    else if (StartsWith(alert.Message, "Blocked attempt to disable VulnerableDriverBlocklistEnable.") ||
             StartsWith(alert.Message, "Observed attempt to disable VulnerableDriverBlocklistEnable while blocking is off."))
    {
        alert.Summary = alert.Blocked ? "Vulnerable driver blocklist tamper blocked" : "Vulnerable driver blocklist tamper observed";
    }
    else if (StartsWith(alert.Message, "Usermode switched driver blocking state to "))
    {
        alert.Summary = ExtractAfter(alert.Message, "Usermode ");
    }
    else if (StartsWith(alert.Message, "DrvDetect loaded. "))
    {
        alert.Summary = "Driver initialized";
    }
}

static void UpdateInsights(const UiAlert& alert)
{
    if (alert.TypeText == "PROCESS_BLOCKED" || alert.TypeText == "KERNEL_IMAGE_SUSPICIOUS")
    {
        g_App.Insight.HasThreat = true;
        g_App.Insight.LastThreatBlocked = alert.Blocked;
    }
}

static bool IsThreatAlert(const UiAlert& alert)
{
    if (alert.TypeText != "PROCESS_BLOCKED" && alert.TypeText != "KERNEL_IMAGE_SUSPICIOUS")
    {
        return false;
    }

    return !StartsWith(alert.Message, "Usermode switched driver blocking state to ");
}

static int CountThreatAlerts()
{
    int count = 0;
    for (const UiAlert& alert : g_App.Alerts)
    {
        if (IsThreatAlert(alert))
        {
            ++count;
        }
    }

    return count;
}

static const UiAlert* GetThreatAlertByVisibleIndex(int visibleIndex)
{
    if (visibleIndex < 0)
    {
        return nullptr;
    }

    int currentIndex = 0;
    for (const UiAlert& alert : g_App.Alerts)
    {
        if (!IsThreatAlert(alert))
        {
            continue;
        }

        if (currentIndex == visibleIndex)
        {
            return &alert;
        }

        ++currentIndex;
    }

    return nullptr;
}

static void EnsureSelectionIsValid()
{
    const int threatCount = CountThreatAlerts();
    if (threatCount == 0)
    {
        g_App.SelectedAlertVisibleIndex = -1;
        g_App.ShowingAlertDetails = false;
        return;
    }

    if (g_App.SelectedAlertVisibleIndex < 0 || g_App.SelectedAlertVisibleIndex >= threatCount)
    {
        g_App.SelectedAlertVisibleIndex = 0;
    }
}

static void PushAlert(const DRVDETECT_ALERT& alert)
{
    UiAlert row = {};
    row.TimeText = FormatTimestamp(alert.Timestamp);
    row.TypeText = WideToUtf8(AlertTypeToText(alert.Type));
    row.ProcessId = alert.ProcessId;
    row.Message = WideToUtf8(alert.Message);
    ParseAlert(row);
    UpdateInsights(row);

    g_App.Alerts.push_front(std::move(row));
    while (g_App.Alerts.size() > 512)
    {
        g_App.Alerts.pop_back();
    }

    EnsureSelectionIsValid();
}

static void DisconnectDevice(const wchar_t* reason)
{
    if (g_App.Device != INVALID_HANDLE_VALUE)
    {
        CloseHandle(g_App.Device);
        g_App.Device = INVALID_HANDLE_VALUE;
    }

    g_App.StatusLine = reason;
}

static std::wstring GetExecutableDirectory()
{
    std::vector<wchar_t> buffer(1024, L'\0');
    const DWORD length = GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
    if (length == 0 || length >= buffer.size())
    {
        return {};
    }

    std::wstring path(buffer.data(), length);
    const size_t slash = path.find_last_of(L"\\/");
    if (slash == std::wstring::npos)
    {
        return {};
    }

    return path.substr(0, slash);
}

static std::wstring JoinPath(const std::wstring& base, const wchar_t* name)
{
    if (base.empty())
    {
        return {};
    }

    return base + L"\\" + name;
}

static bool ServiceBinaryMatches(const wchar_t* currentPath, const wchar_t* expectedPath)
{
    if (currentPath == nullptr || expectedPath == nullptr)
    {
        return false;
    }

    return _wcsicmp(currentPath, expectedPath) == 0;
}

static bool FileExists(const std::wstring& path)
{
    const DWORD attributes = GetFileAttributesW(path.c_str());
    return attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_DIRECTORY) == 0;
}

static bool VerifyFileSha256(const std::wstring& filePath, const char* expectedHexHash)
{
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    HANDLE hFile = INVALID_HANDLE_VALUE;
    BYTE fileBuffer[4096];
    BYTE hashValue[32];
    DWORD hashLen = 32;
    DWORD bytesRead = 0;
    bool result = false;

    hFile = CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        return false;
    }

    if (!CryptAcquireContextW(&hProv, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
    {
        CloseHandle(hFile);
        return false;
    }

    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash))
    {
        CryptReleaseContext(hProv, 0);
        CloseHandle(hFile);
        return false;
    }

    while (ReadFile(hFile, fileBuffer, sizeof(fileBuffer), &bytesRead, nullptr) && bytesRead > 0)
    {
        if (!CryptHashData(hHash, fileBuffer, bytesRead, 0))
        {
            goto cleanup;
        }
    }

    if (!CryptGetHashParam(hHash, HP_HASHVAL, hashValue, &hashLen, 0) || hashLen != 32)
    {
        goto cleanup;
    }

    {
        char computedHex[65] = {};
        const char hex[] = "0123456789abcdef";
        for (DWORD i = 0; i < 32; ++i)
        {
            computedHex[i * 2] = hex[(hashValue[i] >> 4) & 0x0F];
            computedHex[i * 2 + 1] = hex[hashValue[i] & 0x0F];
        }
        computedHex[64] = '\0';
        result = _stricmp(computedHex, expectedHexHash) == 0;
    }

cleanup:
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    CloseHandle(hFile);
    return result;
}

static bool RunProcessAndWait(const std::wstring& commandLine, DWORD* exitCodeOut = nullptr)
{
    STARTUPINFOW startupInfo = {};
    PROCESS_INFORMATION processInfo = {};
    std::vector<wchar_t> mutableCommand(commandLine.begin(), commandLine.end());

    mutableCommand.push_back(L'\0');
    startupInfo.cb = sizeof(startupInfo);

    if (!CreateProcessW(
            nullptr,
            mutableCommand.data(),
            nullptr,
            nullptr,
            FALSE,
            CREATE_NO_WINDOW,
            nullptr,
            nullptr,
            &startupInfo,
            &processInfo))
    {
        AppendInstallerLog(L"CreateProcess failed: " + commandLine);
        return false;
    }

    WaitForSingleObject(processInfo.hProcess, INFINITE);

    DWORD exitCode = ERROR_GEN_FAILURE;
    GetExitCodeProcess(processInfo.hProcess, &exitCode);
    CloseHandle(processInfo.hThread);
    CloseHandle(processInfo.hProcess);
    if (exitCodeOut != nullptr)
    {
        *exitCodeOut = exitCode;
    }

    wchar_t result[192] = {};
    swprintf_s(result, L"Process exit %lu: %ls", exitCode, commandLine.c_str());
    AppendInstallerLog(result);
    return exitCode == 0;
}

static bool EnsureDriverInstalledAndRunning()
{
    const ULONGLONG now = GetTickCount64();
    if ((now - g_App.LastInstallAttemptTick) < 3000)
    {
        return false;
    }

    g_App.LastInstallAttemptTick = now;

    const std::wstring baseDir = GetExecutableDirectory();
    const std::wstring infPath = JoinPath(baseDir, L"km.inf");
    const std::wstring sysPath = JoinPath(baseDir, L"km.sys");
    const std::wstring certPath = JoinPath(baseDir, L"DrvDetectTest.cer");

    if (!FileExists(infPath) || !FileExists(sysPath))
    {
        g_App.StatusLine = L"Driver files were not found next to um.exe";
        AppendInstallerLog(g_App.StatusLine);
        return false;
    }

    if (strcmp(kExpectedDriverHash, "0000000000000000000000000000000000000000000000000000000000000000") != 0)
    {
        if (!VerifyFileSha256(sysPath, kExpectedDriverHash))
        {
            g_App.StatusLine = L"Driver binary hash mismatch - possible tampering";
            AppendInstallerLog(g_App.StatusLine);
            return false;
        }
        AppendInstallerLog(L"Driver hash verified");
    }

    AppendInstallerLog(L"Bootstrap started");
    AppendInstallerLog(L"Bundle directory: " + baseDir);

    if (FileExists(certPath))
    {
        AppendInstallerLog(L"Importing test certificate");
        RunProcessAndWait(L"certutil -addstore -f Root \"" + certPath + L"\"");
        RunProcessAndWait(L"certutil -addstore -f TrustedPublisher \"" + certPath + L"\"");
    }
    else
    {
        AppendInstallerLog(L"Certificate file not found, skipping import");
    }

    DWORD pnputilExitCode = ERROR_GEN_FAILURE;
    const bool packageAdded =
        RunProcessAndWait(L"pnputil /add-driver \"" + infPath + L"\" /install", &pnputilExitCode);
    {
        wchar_t message[160] = {};
        swprintf_s(message, L"pnputil result=%lu", pnputilExitCode);
        AppendInstallerLog(message);
    }

    SC_HANDLE manager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE);
    if (manager == nullptr)
    {
        g_App.StatusLine = L"OpenSCManager failed";
        AppendInstallerLog(g_App.StatusLine);
        return false;
    }

    SC_HANDLE service = OpenServiceW(
        manager,
        g_ServiceName,
        SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS | SERVICE_START | SERVICE_CHANGE_CONFIG);

    const wchar_t* installedBinaryPath = sysPath.c_str();

    if (service == nullptr)
    {
        AppendInstallerLog(L"Service not found, creating DrvDetect");
        service = CreateServiceW(
            manager,
            g_ServiceName,
            g_ServiceName,
            SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS | SERVICE_START | SERVICE_CHANGE_CONFIG,
            SERVICE_KERNEL_DRIVER,
            SERVICE_DEMAND_START,
            SERVICE_ERROR_NORMAL,
            installedBinaryPath,
            nullptr,
            nullptr,
            nullptr,
            nullptr,
            nullptr);

        if (service == nullptr)
        {
            CloseServiceHandle(manager);
            g_App.StatusLine = L"Driver service could not be created";
            AppendInstallerLog(g_App.StatusLine);
            return false;
        }
    }
    else
    {
        AppendInstallerLog(L"Opened existing DrvDetect service");
    }

    DWORD bytesNeeded = 0;
    QueryServiceConfigW(service, nullptr, 0, &bytesNeeded);
    if (GetLastError() == ERROR_INSUFFICIENT_BUFFER && bytesNeeded >= sizeof(QUERY_SERVICE_CONFIGW))
    {
        std::vector<BYTE> configBuffer(bytesNeeded);
        auto* config = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(configBuffer.data());
        if (QueryServiceConfigW(service, config, bytesNeeded, &bytesNeeded) &&
            !ServiceBinaryMatches(config->lpBinaryPathName, installedBinaryPath) &&
            !ChangeServiceConfigW(
                service,
                SERVICE_NO_CHANGE,
                SERVICE_DEMAND_START,
                SERVICE_NO_CHANGE,
                installedBinaryPath,
                nullptr,
                nullptr,
                nullptr,
                nullptr,
                nullptr,
                g_ServiceName))
        {
            g_App.StatusLine = L"Driver service path update failed";
            AppendInstallerLog(g_App.StatusLine);
        }
        else if (QueryServiceConfigW(service, config, bytesNeeded, &bytesNeeded))
        {
            AppendInstallerLog(L"Service binary path checked: " + std::wstring(installedBinaryPath));
        }
    }

    SERVICE_STATUS status = {};
    bool started = false;
    if (QueryServiceStatus(service, &status))
    {
        wchar_t currentState[96] = {};
        swprintf_s(currentState, L"Service state before start=%lu", status.dwCurrentState);
        AppendInstallerLog(currentState);
        if (status.dwCurrentState == SERVICE_RUNNING)
        {
            started = true;
        }
        else
        {
            const BOOL startIssued = StartServiceW(service, 0, nullptr);
            const DWORD startError = startIssued ? ERROR_SUCCESS : GetLastError();
            Sleep(700);
            if (QueryServiceStatus(service, &status))
            {
                started = status.dwCurrentState == SERVICE_RUNNING;
            }
            if (!started && !startIssued)
            {
                wchar_t buffer[160] = {};
                swprintf_s(buffer, L"Driver start failed: GLE=%lu", startError);
                g_App.StatusLine = buffer;
                AppendInstallerLog(g_App.StatusLine);
            }
        }
    }

    CloseServiceHandle(service);
    CloseServiceHandle(manager);

    if (!started)
    {
        if (g_App.StatusLine.empty() || g_App.StatusLine == L"Disconnected")
        {
            wchar_t buffer[192] = {};
            swprintf_s(
                buffer,
                L"Driver service is not running (pnputil=%lu)",
                pnputilExitCode);
            g_App.StatusLine = buffer;
        }
        AppendInstallerLog(g_App.StatusLine);
    }
    else if (packageAdded)
    {
        g_App.StatusLine = L"Driver package installed";
        AppendInstallerLog(L"Driver service is running");
    }

    return started;
}

static bool EnsureDeviceConnection()
{
    const ULONGLONG now = GetTickCount64();

    if (g_App.Device != INVALID_HANDLE_VALUE)
    {
        return true;
    }

    if ((now - g_App.LastConnectTick) < 1000)
    {
        return false;
    }

    g_App.LastConnectTick = now;
    EnsureDriverInstalledAndRunning();

    g_App.Device = CreateFileW(
        DRVDETECT_USER_SYMLINK,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);

    if (g_App.Device == INVALID_HANDLE_VALUE)
    {
        wchar_t buffer[96] = {};
        swprintf_s(buffer, L"Device open failed: GLE=%lu", GetLastError());
        g_App.StatusLine = buffer;
        AppendInstallerLog(g_App.StatusLine);
        return false;
    }

    g_App.StatusLine = L"Connected";
    AppendInstallerLog(L"Device handle opened successfully");
    g_App.LastStatePollTick = 0;
    return true;
}

static bool QueryDriverState(bool updateStatusOnError)
{
    DRVDETECT_STATE state = {};
    DWORD bytesReturned = 0;

    if (!EnsureDeviceConnection())
    {
        return false;
    }

    if (!DeviceIoControl(
            g_App.Device,
            IOCTL_DRVDETECT_GET_STATE,
            nullptr,
            0,
            &state,
            static_cast<DWORD>(sizeof(state)),
            &bytesReturned,
            nullptr))
    {
        const DWORD gle = GetLastError();
        if (updateStatusOnError)
        {
            wchar_t buffer[96] = {};
            swprintf_s(buffer, L"State query failed: GLE=%lu", gle);
            DisconnectDevice(buffer);
        }
        return false;
    }

    if (bytesReturned >= sizeof(state) && state.Version == DRVDETECT_STATE_VERSION)
    {
        g_App.DriverState = state;
        return true;
    }

    if (updateStatusOnError)
    {
        DisconnectDevice(L"State query returned invalid payload");
    }

    return false;
}

static bool SetBlockingState(unsigned long blockingState)
{
    DRVDETECT_STATE request = {};
    DRVDETECT_STATE response = {};
    DWORD bytesReturned = 0;

    if (!EnsureDeviceConnection())
    {
        return false;
    }

    request.Version = DRVDETECT_STATE_VERSION;
    request.BlockingState = blockingState;

    if (!DeviceIoControl(
            g_App.Device,
            IOCTL_DRVDETECT_SET_STATE,
            &request,
            static_cast<DWORD>(sizeof(request)),
            &response,
            static_cast<DWORD>(sizeof(response)),
            &bytesReturned,
            nullptr))
    {
        wchar_t buffer[96] = {};
        swprintf_s(buffer, L"State switch failed: GLE=%lu", GetLastError());
        DisconnectDevice(buffer);
        return false;
    }

    if (bytesReturned >= sizeof(response) && response.Version == DRVDETECT_STATE_VERSION)
    {
        g_App.DriverState = response;
    }
    else
    {
        g_App.DriverState.BlockingState = blockingState;
    }

    g_App.StatusLine = blockingState == DrvDetectBlockingOn ? L"Blocking enabled" : L"Blocking disabled";
    return true;
}

static void PollAlerts()
{
    for (int i = 0; i < 32; ++i)
    {
        DRVDETECT_ALERT alert = {};
        DWORD bytesReturned = 0;

        if (!EnsureDeviceConnection())
        {
            return;
        }

        if (!DeviceIoControl(
                g_App.Device,
                IOCTL_DRVDETECT_GET_ALERT,
                nullptr,
                0,
                &alert,
                static_cast<DWORD>(sizeof(alert)),
                &bytesReturned,
                nullptr))
        {
            const DWORD gle = GetLastError();
            if (gle == ERROR_NO_MORE_ITEMS || gle == ERROR_NOT_FOUND)
            {
                break;
            }

            wchar_t buffer[96] = {};
            swprintf_s(buffer, L"Alert poll failed: GLE=%lu", gle);
            DisconnectDevice(buffer);
            return;
        }

        if (bytesReturned >= sizeof(alert) && alert.Version == DRVDETECT_ALERT_VERSION)
        {
            PushAlert(alert);
        }
    }
}

static void PumpDriver()
{
    const ULONGLONG now = GetTickCount64();

    if (!EnsureDeviceConnection())
    {
        return;
    }

    if ((now - g_App.LastStatePollTick) >= 500)
    {
        QueryDriverState(true);
        g_App.LastStatePollTick = now;
    }

    PollAlerts();
}

static void CreateRenderTarget()
{
    ID3D11Texture2D* backBuffer = nullptr;
    if (SUCCEEDED(g_SwapChain->GetBuffer(0, IID_PPV_ARGS(&backBuffer))))
    {
        g_D3dDevice->CreateRenderTargetView(backBuffer, nullptr, &g_RenderTargetView);
        backBuffer->Release();
    }
}

static void CleanupRenderTarget()
{
    if (g_RenderTargetView != nullptr)
    {
        g_RenderTargetView->Release();
        g_RenderTargetView = nullptr;
    }
}

static bool CreateDeviceD3D(HWND window)
{
    DXGI_SWAP_CHAIN_DESC swapChainDesc = {};
    D3D_FEATURE_LEVEL featureLevel = D3D_FEATURE_LEVEL_11_0;
    const D3D_FEATURE_LEVEL featureLevelArray[2] = { D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_0 };

    swapChainDesc.BufferCount = 2;
    swapChainDesc.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    swapChainDesc.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    swapChainDesc.OutputWindow = window;
    swapChainDesc.SampleDesc.Count = 1;
    swapChainDesc.Windowed = TRUE;
    swapChainDesc.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;

    if (D3D11CreateDeviceAndSwapChain(
            nullptr,
            D3D_DRIVER_TYPE_HARDWARE,
            nullptr,
            0,
            featureLevelArray,
            ARRAYSIZE(featureLevelArray),
            D3D11_SDK_VERSION,
            &swapChainDesc,
            &g_SwapChain,
            &g_D3dDevice,
            &featureLevel,
            &g_D3dContext) != S_OK)
    {
        return false;
    }

    CreateRenderTarget();
    return true;
}

static void CleanupDeviceD3D()
{
    CleanupRenderTarget();

    if (g_SwapChain != nullptr)
    {
        g_SwapChain->Release();
        g_SwapChain = nullptr;
    }

    if (g_D3dContext != nullptr)
    {
        g_D3dContext->Release();
        g_D3dContext = nullptr;
    }

    if (g_D3dDevice != nullptr)
    {
        g_D3dDevice->Release();
        g_D3dDevice = nullptr;
    }
}

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND, UINT, WPARAM, LPARAM);

static LRESULT WINAPI WindowProc(HWND window, UINT message, WPARAM wParam, LPARAM lParam)
{
    if (ImGui_ImplWin32_WndProcHandler(window, message, wParam, lParam))
    {
        return TRUE;
    }

    switch (message)
    {
    case WM_SIZE:
        if (g_D3dDevice != nullptr && wParam != SIZE_MINIMIZED)
        {
            CleanupRenderTarget();
            g_SwapChain->ResizeBuffers(0, static_cast<UINT>(LOWORD(lParam)), static_cast<UINT>(HIWORD(lParam)), DXGI_FORMAT_UNKNOWN, 0);
            CreateRenderTarget();
        }
        return 0;
    case WM_SYSCOMMAND:
        if ((wParam & 0xfff0) == SC_KEYMENU)
        {
            return 0;
        }
        break;
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }

    return DefWindowProcW(window, message, wParam, lParam);
}

static void SetupImGuiStyle()
{
    ImGuiStyle& style = ImGui::GetStyle();
    style.WindowRounding = 0.0f;
    style.ChildRounding = 18.0f;
    style.FrameRounding = 14.0f;
    style.PopupRounding = 14.0f;
    style.GrabRounding = 14.0f;
    style.TabRounding = 14.0f;
    style.ScrollbarRounding = 14.0f;
    style.WindowBorderSize = 0.0f;
    style.ChildBorderSize = 0.0f;
    style.FrameBorderSize = 0.0f;
    style.PopupBorderSize = 0.0f;
    style.TabBorderSize = 0.0f;
    style.WindowPadding = ImVec2(22.0f, 22.0f);
    style.FramePadding = ImVec2(14.0f, 11.0f);
    style.ItemSpacing = ImVec2(16.0f, 16.0f);
    style.ItemInnerSpacing = ImVec2(10.0f, 8.0f);
    style.CellPadding = ImVec2(10.0f, 8.0f);

    style.Colors[ImGuiCol_WindowBg] = ImVec4(0.06f, 0.07f, 0.09f, 1.0f);
    style.Colors[ImGuiCol_ChildBg] = ImVec4(0.11f, 0.12f, 0.15f, 1.0f);
    style.Colors[ImGuiCol_FrameBg] = ImVec4(0.15f, 0.16f, 0.20f, 1.0f);
    style.Colors[ImGuiCol_FrameBgHovered] = ImVec4(0.20f, 0.22f, 0.27f, 1.0f);
    style.Colors[ImGuiCol_FrameBgActive] = ImVec4(0.24f, 0.26f, 0.31f, 1.0f);
    style.Colors[ImGuiCol_Button] = ImVec4(0.22f, 0.73f, 0.48f, 1.0f);
    style.Colors[ImGuiCol_ButtonHovered] = ImVec4(0.27f, 0.81f, 0.54f, 1.0f);
    style.Colors[ImGuiCol_ButtonActive] = ImVec4(0.18f, 0.62f, 0.41f, 1.0f);
    style.Colors[ImGuiCol_CheckMark] = ImVec4(0.88f, 0.92f, 0.97f, 1.0f);
    style.Colors[ImGuiCol_Header] = ImVec4(0.18f, 0.20f, 0.25f, 1.0f);
    style.Colors[ImGuiCol_HeaderHovered] = ImVec4(0.22f, 0.25f, 0.31f, 1.0f);
    style.Colors[ImGuiCol_HeaderActive] = ImVec4(0.26f, 0.29f, 0.35f, 1.0f);
    style.Colors[ImGuiCol_Separator] = ImVec4(0.22f, 0.24f, 0.30f, 1.0f);
    style.Colors[ImGuiCol_Border] = ImVec4(0.00f, 0.00f, 0.00f, 0.00f);
    style.Colors[ImGuiCol_ScrollbarBg] = ImVec4(0.09f, 0.10f, 0.12f, 0.0f);
    style.Colors[ImGuiCol_ScrollbarGrab] = ImVec4(0.24f, 0.27f, 0.34f, 1.0f);
    style.Colors[ImGuiCol_ScrollbarGrabHovered] = ImVec4(0.31f, 0.35f, 0.42f, 1.0f);
    style.Colors[ImGuiCol_ScrollbarGrabActive] = ImVec4(0.38f, 0.42f, 0.50f, 1.0f);
    style.Colors[ImGuiCol_Text] = ImVec4(0.93f, 0.95f, 0.98f, 1.0f);
    style.Colors[ImGuiCol_TextDisabled] = ImVec4(0.58f, 0.62f, 0.70f, 1.0f);
}

static void SetupFonts()
{
    ImGuiIO& io = ImGui::GetIO();
    const char* bodyFontPath = "C:\\Windows\\Fonts\\segoeui.ttf";
    const char* headerFontPath = "C:\\Windows\\Fonts\\bahnschrift.ttf";

    g_BodyFont = io.Fonts->AddFontFromFileTTF(bodyFontPath, 18.0f);
    g_HeaderFont = io.Fonts->AddFontFromFileTTF(headerFontPath, 30.0f);

    if (g_BodyFont == nullptr)
    {
        g_BodyFont = io.Fonts->AddFontDefault();
    }

    if (g_HeaderFont == nullptr)
    {
        g_HeaderFont = g_BodyFont;
    }
}

static ImVec4 GetAlertAccent(const UiAlert& alert)
{
    return alert.Blocked ? ImVec4(0.20f, 0.70f, 0.46f, 1.0f) : ImVec4(0.96f, 0.68f, 0.18f, 1.0f);
}

static const char* GetAlertStateTitle(const UiAlert& alert)
{
    return alert.Blocked ? "THREAT BLOCKED" : "THREAT DETECTED";
}

static std::string GetAlertPrimaryLine(const UiAlert& alert)
{
    if (!alert.ProcessPath.empty())
    {
        return alert.ProcessPath;
    }

    if (!alert.DriverPath.empty())
    {
        return alert.DriverPath;
    }

    if (!alert.RegistryPath.empty())
    {
        return alert.RegistryPath;
    }

    if (!alert.Summary.empty())
    {
        return alert.Summary;
    }

    return alert.TypeText;
}

static const char* GetAlertKindLabel(const UiAlert& alert)
{
    if (!alert.ProcessPath.empty())
    {
        return "process";
    }

    if (!alert.DriverPath.empty())
    {
        return "driver";
    }

    if (!alert.RegistryPath.empty())
    {
        return "registry";
    }

    return "event";
}

static std::string GetAlertDetailTitle(const UiAlert& alert)
{
    if (!alert.Summary.empty())
    {
        return alert.Summary;
    }

    return alert.Blocked ? "Threat blocked before execution completed" : "Threat observed while blocking was unavailable";
}

static void RenderKeyValueRow(const char* label, const std::string& value)
{
    if (value.empty())
    {
        return;
    }

    ImGui::TextDisabled("%s", label);
    ImGui::TextWrapped("%s", value.c_str());
    ImGui::Spacing();
}

static void BeginPanelInset()
{
    const ImVec2 start = ImGui::GetCursorPos();
    ImGui::SetCursorPos(ImVec2(start.x + kPanelPadding, start.y + kPanelPadding));
    ImGui::BeginGroup();
    ImGui::PushTextWrapPos(ImGui::GetCursorPosX() + ImGui::GetContentRegionAvail().x - kPanelPadding);
}

static void EndPanelInset()
{
    ImGui::PopTextWrapPos();
    ImGui::EndGroup();
}

static float GetInsetButtonWidth()
{
    return (std::max)(0.0f, ImGui::GetContentRegionAvail().x - kPanelPadding);
}

static bool RenderAlertCard(const UiAlert& alert, int index)
{
    const bool selected = g_App.SelectedAlertVisibleIndex == index;
    const ImVec4 accent = GetAlertAccent(alert);
    const ImVec4 bg = selected
        ? ImVec4(accent.x * 0.26f + 0.14f, accent.y * 0.26f + 0.14f, accent.z * 0.26f + 0.14f, 1.0f)
        : ImVec4(accent.x * 0.18f, accent.y * 0.18f, accent.z * 0.18f, 1.0f);
    const char* cardId = "alert_card";

    ImGui::PushID(index);
    ImGui::PushStyleColor(ImGuiCol_ChildBg, bg);
    ImGui::BeginChild(cardId, ImVec2(0.0f, 122.0f), false, ImGuiWindowFlags_NoScrollbar);
    BeginPanelInset();
    ImGui::TextColored(accent, "%s", GetAlertStateTitle(alert));
    ImGui::SameLine();
    ImGui::TextDisabled("%s", alert.TimeText.c_str());
    ImGui::TextUnformatted(GetAlertDetailTitle(alert).c_str());
    ImGui::TextDisabled("%s", GetAlertKindLabel(alert));
    ImGui::SameLine();
    ImGui::TextUnformatted(GetAlertPrimaryLine(alert).c_str());
    EndPanelInset();
    ImGui::EndChild();
    const bool clicked = ImGui::IsItemHovered() && ImGui::IsMouseReleased(ImGuiMouseButton_Left);
    ImGui::PopStyleColor();
    ImGui::PopID();
    return clicked;
}

static void RenderSidebar()
{
    const bool connected = g_App.Device != INVALID_HANDLE_VALUE;
    const bool blockingEnabled = g_App.DriverState.BlockingState == DrvDetectBlockingOn;
    const ImVec4 statusColor = blockingEnabled ? ImVec4(0.25f, 0.88f, 0.52f, 1.0f) : ImVec4(0.95f, 0.62f, 0.21f, 1.0f);
    const ImVec4 sidebarPanel = ImVec4(0.10f, 0.11f, 0.14f, 1.0f);
    const ImVec4 buttonBase = blockingEnabled ? ImVec4(0.24f, 0.82f, 0.50f, 1.0f) : ImVec4(0.92f, 0.58f, 0.18f, 1.0f);
    const ImVec4 buttonHover = blockingEnabled ? ImVec4(0.29f, 0.88f, 0.56f, 1.0f) : ImVec4(0.97f, 0.65f, 0.24f, 1.0f);
    const ImVec4 buttonActive = blockingEnabled ? ImVec4(0.19f, 0.68f, 0.42f, 1.0f) : ImVec4(0.83f, 0.50f, 0.14f, 1.0f);

    ImGui::BeginChild("sidebar", ImVec2(292.0f, 0.0f), false, ImGuiWindowFlags_NoScrollbar);

    ImGui::PushStyleColor(ImGuiCol_ChildBg, sidebarPanel);
    ImGui::BeginChild("sidebar_top", ImVec2(0.0f, 272.0f), false, ImGuiWindowFlags_NoScrollbar);
    BeginPanelInset();
    ImGui::PushFont(g_HeaderFont);
    ImGui::TextUnformatted("DrvDetect");
    ImGui::PopFont();
    ImGui::TextDisabled("%s", connected ? "connected" : "disconnected");
    ImGui::Spacing();
    ImGui::TextColored(statusColor, "●");
    ImGui::SameLine(0.0f, 8.0f);
    ImGui::Text("status %s", blockingEnabled ? "blocked" : "watching");
    ImGui::TextDisabled("%s", blockingEnabled ? "driver blocking is active" : "alerts are observed only");

    ImGui::SetCursorPosY(ImGui::GetCursorPosY() + 10.0f);
    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(0.04f, 0.05f, 0.06f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_Button, buttonBase);
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, buttonHover);
    ImGui::PushStyleColor(ImGuiCol_ButtonActive, buttonActive);
    ImGui::BeginDisabled(!connected);
    if (ImGui::Button(blockingEnabled ? "UNBLOCK" : "ENABLE BLOCKING", ImVec2(GetInsetButtonWidth(), 66.0f)))
    {
        SetBlockingState(blockingEnabled ? DrvDetectBlockingOff : DrvDetectBlockingOn);
    }
    ImGui::EndDisabled();
    ImGui::PopStyleColor(4);
    EndPanelInset();
    ImGui::EndChild();
    ImGui::PopStyleColor();

    ImGui::SetCursorPosY(ImGui::GetCursorPosY() + 16.0f);

    ImGui::PushStyleColor(ImGuiCol_ChildBg, sidebarPanel);
    ImGui::BeginChild("sidebar_bottom", ImVec2(0.0f, 0.0f), false, ImGuiWindowFlags_NoScrollbar);
    BeginPanelInset();
    ImGui::TextUnformatted("Control");
    ImGui::Spacing();
    ImGui::TextDisabled("device");
    ImGui::Text("%s", connected ? "online" : "offline");
    ImGui::TextDisabled("state");
    ImGui::TextWrapped("%s", WideToUtf8(g_App.StatusLine.c_str()).c_str());
    ImGui::TextDisabled("pending alerts");
    ImGui::Text("%lu", g_App.DriverState.PendingAlerts);
    ImGui::Checkbox("auto scroll", &g_App.AutoScroll);
    if (ImGui::Button("reconnect", ImVec2(GetInsetButtonWidth(), 0.0f)))
    {
        DisconnectDevice(L"Reconnect requested");
        EnsureDeviceConnection();
        QueryDriverState(false);
    }
    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();
    ImGui::TextUnformatted("Installer log");
    ImGui::BeginChild("installer_log", ImVec2(0.0f, 220.0f), false, ImGuiWindowFlags_NoScrollbar);
    if (g_App.InstallerLog.empty())
    {
        ImGui::TextDisabled("No bootstrap activity yet.");
    }
    else
    {
        for (const std::string& line : g_App.InstallerLog)
        {
            ImGui::TextWrapped("%s", line.c_str());
        }
    }
    ImGui::EndChild();
    EndPanelInset();
    ImGui::EndChild();
    ImGui::PopStyleColor();
    ImGui::EndChild();
}

static void RenderThreatFeed()
{
    EnsureSelectionIsValid();

    ImGui::BeginChild("feed_panel", ImVec2(0.0f, 0.0f), false);
    BeginPanelInset();
    ImGui::PushFont(g_HeaderFont);
    ImGui::TextUnformatted("Threat Feed");
    ImGui::PopFont();
    ImGui::TextDisabled("Recent detections and blocks");
    ImGui::Spacing();
    if (CountThreatAlerts() == 0)
    {
        ImGui::TextDisabled("No threat events yet.");
    }
    else
    {
        int index = 0;
        for (const UiAlert& alert : g_App.Alerts)
        {
            if (!IsThreatAlert(alert))
            {
                continue;
            }

            if (RenderAlertCard(alert, index))
            {
                g_App.SelectedAlertVisibleIndex = index;
                g_App.ShowingAlertDetails = true;
            }

            ++index;
        }
    }

    EndPanelInset();
    ImGui::EndChild();
}

static void RenderMainLayout()
{
    ImGui::BeginChild("layout", ImVec2(0.0f, 0.0f), false, ImGuiWindowFlags_NoScrollbar);
    RenderSidebar();
    ImGui::SameLine();

    ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0.10f, 0.11f, 0.14f, 1.0f));
    ImGui::BeginChild("feed_column", ImVec2(0.0f, 0.0f), false);
    RenderThreatFeed();
    ImGui::EndChild();
    ImGui::PopStyleColor();
    ImGui::EndChild();
}

static void RenderAlertDetails()
{
    EnsureSelectionIsValid();
    const UiAlert* selectedAlert = GetThreatAlertByVisibleIndex(g_App.SelectedAlertVisibleIndex);
    if (selectedAlert == nullptr)
    {
        g_App.ShowingAlertDetails = false;
        RenderMainLayout();
        return;
    }

    const ImVec4 accent = GetAlertAccent(*selectedAlert);
    const ImVec4 panelBg = ImVec4(0.10f, 0.11f, 0.14f, 1.0f);
    const ImVec4 summaryBg = ImVec4(accent.x * 0.20f, accent.y * 0.20f, accent.z * 0.20f, 1.0f);

    ImGui::PushStyleColor(ImGuiCol_ChildBg, panelBg);
    ImGui::BeginChild("details_root", ImVec2(0.0f, 0.0f), false);
    BeginPanelInset();
    if (ImGui::Button("< back"))
    {
        g_App.ShowingAlertDetails = false;
    }
    ImGui::Spacing();

    ImGui::PushStyleColor(ImGuiCol_ChildBg, summaryBg);
    ImGui::BeginChild("details_card", ImVec2(0.0f, 320.0f), false, ImGuiWindowFlags_NoScrollbar);
    BeginPanelInset();
    ImGui::PushFont(g_HeaderFont);
    ImGui::TextUnformatted(GetAlertDetailTitle(*selectedAlert).c_str());
    ImGui::PopFont();
    ImGui::TextColored(accent, "%s", GetAlertStateTitle(*selectedAlert));
    ImGui::SameLine();
    ImGui::TextDisabled("type %s", selectedAlert->TypeText.c_str());
    ImGui::Spacing();
    ImGui::PushTextWrapPos();
    ImGui::TextWrapped("%s", selectedAlert->Message.c_str());
    ImGui::PopTextWrapPos();
    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();
    ImGui::TextDisabled("time");
    ImGui::Text("%s", selectedAlert->TimeText.c_str());
    if (selectedAlert->ProcessId != 0)
    {
        ImGui::SameLine(220.0f);
        ImGui::TextDisabled("pid");
        ImGui::SameLine();
        ImGui::Text("%lu", selectedAlert->ProcessId);
    }
    EndPanelInset();
    ImGui::EndChild();
    ImGui::PopStyleColor();

    ImGui::PushStyleColor(ImGuiCol_ChildBg, panelBg);
    ImGui::BeginChild("details_meta", ImVec2(0.0f, 0.0f), false);
    BeginPanelInset();
    ImGui::PushFont(g_HeaderFont);
    ImGui::TextUnformatted("Details");
    ImGui::PopFont();
    ImGui::TextDisabled("Expanded event context");
    ImGui::Spacing();
    RenderKeyValueRow("summary", selectedAlert->Summary);
    RenderKeyValueRow("kind", GetAlertKindLabel(*selectedAlert));
    RenderKeyValueRow("process", selectedAlert->ProcessPath);
    RenderKeyValueRow("driver", selectedAlert->DriverPath);
    RenderKeyValueRow("registry path", selectedAlert->RegistryPath);
    RenderKeyValueRow("value", selectedAlert->ValueText);
    ImGui::TextDisabled("raw message");
    ImGui::TextWrapped("%s", selectedAlert->Message.c_str());
    EndPanelInset();
    ImGui::EndChild();
    ImGui::PopStyleColor();
    EndPanelInset();
    ImGui::EndChild();
    ImGui::PopStyleColor();
}

static void RenderUi()
{
    ImGui::SetNextWindowPos(ImVec2(0.0f, 0.0f), ImGuiCond_Always);
    ImGui::SetNextWindowSize(ImGui::GetIO().DisplaySize, ImGuiCond_Always);

    ImGui::Begin(
        "DrvDetect",
        nullptr,
        ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoSavedSettings);

    if (g_App.ShowingAlertDetails)
    {
        RenderAlertDetails();
    }
    else
    {
        RenderMainLayout();
    }

    ImGui::End();
}

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE, PWSTR, int)
{
    unsigned short webPort = 0;
    if (TryGetWebModePort(GetCommandLineW(), &webPort))
    {
        return RunWebServer(webPort == 0 ? kDefaultWebPort : webPort);
    }

    WNDCLASSEXW windowClass = {
        sizeof(windowClass), CS_CLASSDC, WindowProc, 0L, 0L, instance, nullptr, nullptr, nullptr, nullptr, L"DrvDetectGui", nullptr
    };

    RegisterClassExW(&windowClass);
    HWND window = CreateWindowW(
        windowClass.lpszClassName,
        L"DrvDetect",
        WS_OVERLAPPEDWINDOW,
        100,
        100,
        1360,
        860,
        nullptr,
        nullptr,
        windowClass.hInstance,
        nullptr);

    if (!CreateDeviceD3D(window))
    {
        CleanupDeviceD3D();
        UnregisterClassW(windowClass.lpszClassName, windowClass.hInstance);
        return 1;
    }

    ShowWindow(window, SW_SHOWDEFAULT);
    UpdateWindow(window);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.IniFilename = "imgui.ini";
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;

    ImGui::StyleColorsDark();
    SetupFonts();
    SetupImGuiStyle();

    ImGui_ImplWin32_Init(window);
    ImGui_ImplDX11_Init(g_D3dDevice, g_D3dContext);

    QueryDriverState(false);

    MSG message = {};
    while (message.message != WM_QUIT)
    {
        if (PeekMessageW(&message, nullptr, 0U, 0U, PM_REMOVE))
        {
            TranslateMessage(&message);
            DispatchMessageW(&message);
            continue;
        }

        PumpDriver();

        ImGui_ImplDX11_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();

        RenderUi();

        ImGui::Render();
        const float clearColor[4] = { 0.03f, 0.03f, 0.05f, 1.0f };
        g_D3dContext->OMSetRenderTargets(1, &g_RenderTargetView, nullptr);
        g_D3dContext->ClearRenderTargetView(g_RenderTargetView, clearColor);
        ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());

        g_SwapChain->Present(1, 0);
    }

    DisconnectDevice(L"Closed");
    ImGui_ImplDX11_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();
    CleanupDeviceD3D();
    DestroyWindow(window);
    UnregisterClassW(windowClass.lpszClassName, windowClass.hInstance);
    return 0;
}
