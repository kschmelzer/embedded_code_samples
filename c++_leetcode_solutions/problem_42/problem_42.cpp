class Solution {
    public:
        int trap(vector<int>& height) {
            if (height.size() < 3) {
                return 0;
            }
            vector<int> coast_stack;
            int sea_level = 0;
            int total_volume = 0;
    
            for (auto land = 0; land < height.size(); ++land) {
                
                if (!coast_stack.empty()) {
    
                    auto pop_iter = coast_stack.end();
                    
                    for (int coast = coast_stack.size() - 1; coast >= 0; --coast) {
                        if (height[land] > sea_level) {
                            auto slab_height = min(height[land], height[coast_stack[coast]]) - sea_level;
                            total_volume += (land - coast_stack[coast] - 1) * slab_height;
                         
                            sea_level += slab_height;
                            if (height[land] >= height[coast_stack[coast]]) {
                                pop_iter = coast_stack.begin() + coast;
                            }
                        } else {
                            break;
                        }
                    }
                    coast_stack.erase(pop_iter, coast_stack.end());
                    if (coast_stack.empty()) {
                        sea_level = 0;
                    }
                }
    
                if (land == height.size()-1) {
                    continue;
                }
                if (height[land] > height[land+1]) {
                    coast_stack.push_back(land); 
                    sea_level = height[land+1];
                } 
    
                
            }
            return total_volume;
    
        }
    };