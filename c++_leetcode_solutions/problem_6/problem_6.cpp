class Solution {
    public:
        string convert(string s, int numRows) {
            if (s.size() == 1 || numRows == 1) {
                return s;
            }
    
            auto out = string{};
    
            for (auto ch = size_t{1}; ch <= numRows; ++ch) {
    
                auto next_ch = ch-1;
                auto dir = 1;
                while (next_ch <s.size()) {
                    out.push_back(s[next_ch]);
                    auto delta = 0;
    
                    if ((ch != numRows && dir > 0) || ch == 1 ) {
                        delta = (numRows - ch)*2;
                    } else if(ch == numRows || dir < 0) {
                        delta = (ch  - 1)*2;
                    }
                    
                    next_ch += delta;
                    dir *= -1;
                }
    
            }
            return out;
        }
    };