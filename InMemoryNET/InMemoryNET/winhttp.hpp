#include <Windows.h>
#include <winhttp.h>
#include <string>
#include <vector>

#pragma comment(lib, "winhttp")

namespace zzWinHttp
{
    typedef struct _request_data
    {
        std::wstring pwsServerName;
        INTERNET_PORT nServerPort;
        std::wstring pwsVerb;
        std::wstring pwsObjectName;
        std::wstring pwsUserAgent;
        std::wstring pwszVersion;
        std::wstring pwszReferrer;
        std::wstring ppwszAcceptTypes;
        std::wstring lpszHeaders;
        std::wstring lpwsData;
        BOOL bSSL;
        BOOL bAutoProxy;
    } request_data;

    class Request
    {
    public:
        Request(_request_data rd)
        {
            _pwsServerName = rd.pwsServerName;
            _nServerPort = rd.nServerPort;
            _pwsVerb = rd.pwsVerb;
            _pwsObjectName = rd.pwsObjectName;
            _pwsUserAgent = rd.pwsUserAgent;
            _pwszVersion = rd.pwszVersion;
            _pwszReferrer = rd.pwszReferrer;
            _ppwszAcceptTypes = rd.ppwszAcceptTypes;
            _lpszHeaders = rd.lpszHeaders;
            _lpwsData = rd.lpwsData;
            _bSSL = rd.bSSL;
            _bAutoProxy = rd.bAutoProxy;
        }

        ~Request()
        {
            return;
        }

        BOOL send(std::vector<unsigned char>& data)
        {
            /* STATUS */
            BOOL bStatus = TRUE;

            /* Used Variables */
            std::vector<char> buf;
            DWORD dwSz = 0;
            DWORD dwDownloaded = 0;
            DWORD dwTotalRead = 0;
            long lpBuffer = -1;
            DWORD lpdwBufferLength = sizeof(lpBuffer);
            BOOL bSetOptions = FALSE;


            DWORD dwFlagsWinHttpOpenRequest = 0;
            DWORD dwAllowBadCerts = 0;

            /* Logic */

            if (_bSSL)
            {
                dwFlagsWinHttpOpenRequest = WINHTTP_FLAG_SECURE;
                dwAllowBadCerts = SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID | SECURITY_FLAG_IGNORE_CERT_CN_INVALID | SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
            }

            HINTERNET hSession = WinHttpOpen(_pwsUserAgent.c_str(), WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
            if (hSession == nullptr)
            {
                printf("[!] WinHttpOpen: %ld\n", GetLastError());
                return FALSE;
            }

            HINTERNET hConnect = WinHttpConnect(hSession, _pwsServerName.c_str(), _nServerPort, 0);
            if (hConnect == nullptr)
            {
                printf("[!] WinHttpConnect: %ld\n", GetLastError());
                return FALSE;
            }
            printf("[+] Opened connection to %ws!\n", _pwsServerName.c_str());

            HINTERNET hRequest = WinHttpOpenRequest(hConnect, _pwsVerb.c_str(), _pwsObjectName.c_str(), _pwszVersion.c_str(), _pwszReferrer.c_str(), NULL, dwFlagsWinHttpOpenRequest);
            if (hRequest == nullptr)
            {
                printf("[!] WinHttpOpenRequest: %ld\n", GetLastError());
                return FALSE;
            }
            printf("[+] Sent %ws to %ws!\n", _pwsVerb.c_str(), _pwsObjectName.c_str());

            if (_bSSL)
            {
                bSetOptions = WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &dwAllowBadCerts, sizeof(dwAllowBadCerts));
                if (bSetOptions == FALSE)
                {
                    printf("[!] WinHttpSetOption: %ld\n", GetLastError());
                    return FALSE;
                }
            }

            BOOL bSentRequest = FALSE;

            if (_lpwsData.empty())
            {
                bSentRequest = WinHttpSendRequest(hRequest, _lpszHeaders.c_str(), _lpszHeaders.size(), WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
            }
            else
            {
                std::string tmp(_lpwsData.begin(), _lpwsData.end());
                bSentRequest = WinHttpSendRequest(hRequest, _lpszHeaders.c_str(), _lpszHeaders.size(), (LPVOID)tmp.c_str(), tmp.size(), tmp.size(), 0);
                tmp.erase();
            }
            if (bSentRequest == FALSE)
            {
                printf("[!] WinHttpSendRequest: %ld\n", GetLastError());
                return FALSE;
            }

            BOOL bReceieveRequest = WinHttpReceiveResponse(hRequest, NULL);

            if (bReceieveRequest == FALSE)
            {
                printf("[!] WinHttpReceiveResponse: %ld\n", GetLastError());
                return FALSE;
            }

            if (_bAutoProxy)
            {
                WINHTTP_AUTOPROXY_OPTIONS autoProxyOptions;
                WINHTTP_PROXY_INFO proxyInfo;
                DWORD dwProxyInfoSz = sizeof(proxyInfo);

                memset(&autoProxyOptions, 0, sizeof(autoProxyOptions));
                memset(&proxyInfo, 0, sizeof(proxyInfo));

                autoProxyOptions.dwFlags = WINHTTP_AUTOPROXY_AUTO_DETECT;
                autoProxyOptions.dwAutoDetectFlags = WINHTTP_AUTO_DETECT_TYPE_DHCP | WINHTTP_AUTO_DETECT_TYPE_DNS_A;
                autoProxyOptions.fAutoLogonIfChallenged = TRUE;
                bSetOptions = WinHttpSetOption(hRequest, WINHTTP_OPTION_PROXY, &proxyInfo, dwProxyInfoSz);

                if (proxyInfo.lpszProxy) GlobalFree(proxyInfo.lpszProxy);
                if (proxyInfo.lpszProxyBypass) GlobalFree(proxyInfo.lpszProxyBypass);

                if (bSetOptions == FALSE)
                {
                    return FALSE;
                }
            }

            BOOL bHeadersQueried = WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_CONTENT_LENGTH | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX, reinterpret_cast<LPVOID>(&lpBuffer), &lpdwBufferLength, 0);

            if (bHeadersQueried == FALSE)
            {
                printf("[!] WinHttpQueryHeaders: %ld\n", GetLastError());
                return FALSE;
            }

            while (WinHttpQueryDataAvailable(hRequest, &dwSz))
            {
                if (dwSz)
                {
                    buf.resize(dwSz + 1);
                    BOOL bRead = WinHttpReadData(hRequest, &buf[0], dwSz, &dwDownloaded);
                    if (bRead == FALSE)
                    {
                        buf.clear();
                        data.clear();
                        break;
                    }
                    dwTotalRead += dwDownloaded;
                    data.insert(data.end(), buf.begin(), buf.begin() + dwDownloaded);
                    buf.clear();

                }
                else
                {
                    break;
                }
            }
            if (hSession) WinHttpCloseHandle(hSession);
            if (hConnect) WinHttpCloseHandle(hConnect);
            if (hRequest) WinHttpCloseHandle(hRequest);


            if (data.empty() == TRUE)
            {
                return FALSE;
            }
            else
            {
                return TRUE;
            }
        }
    private:
        std::wstring _pwsServerName;
        INTERNET_PORT _nServerPort;
        std::wstring _pwsVerb;
        std::wstring _pwsObjectName;
        std::wstring _pwsUserAgent;
        std::wstring _pwszVersion;
        std::wstring _pwszReferrer;
        std::wstring _ppwszAcceptTypes;
        std::wstring _lpszHeaders;
        std::wstring _lpwsData;
        BOOL _bSSL;
        BOOL _bAutoProxy;
        _request_data _rd;
    };
}