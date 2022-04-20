#include <string>
#include <vector>
#include <sstream>

namespace stdlib
{
    std::string RemoveSubstringA(std::string ss, const std::string& remove)
    {
        std::string newss = ss;
        size_t pos = ss.find(remove);

        if (pos != std::string::npos)
        {
            newss.erase(pos, remove.length());
        }
        return newss;
    }

    std::string JoinVectorByStringA(const std::vector<std::string>& v, const std::string& delimiter)
    {
        std::string out;
        if (auto i = v.begin(), e = v.end(); i != e)
        {
            out += *i++;
            for (; i != e; ++i)
            {
                out.append(delimiter).append(*i);
            }
        }
        return out;
    }

    std::string SplitAndGetSubstringA(std::string ss, char delimiter, int pos)
    {
        std::stringstream sstream(ss);
        std::string segment;
        std::vector<std::string> seglist;

        while (std::getline(sstream, segment, delimiter))
        {
            seglist.push_back(segment);
        }

        seglist.erase(seglist.begin(), seglist.begin() + pos);

        std::string joined = JoinVectorByStringA(seglist, std::string{ delimiter });

        joined = std::string{ delimiter } + joined;

        return joined;
    }

    std::string StringW2StringA(std::wstring ws)
    {
        return std::string(ws.begin(), ws.end());
    }

    std::wstring StringA2StringW(std::string ss)
    {
        return std::wstring(ss.begin(), ss.end());
    }

}