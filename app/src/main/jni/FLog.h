//---- Created by NikkaG at (GMT +4) 23:12:56 # Nov 9 2023 ----//
/*
NOTE:
This library will work without any issues on Android and Linux platform, not sure about other Operating Systems...
*/

#include <list>
#include <unistd.h>
#include <string>
#include <cstring>
#include <memory.h>
#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <sstream>
#include <utility>
#include <fstream>
#include <vector>
#include <algorithm>
#include <iomanip>
#include <string.h>
#include <deque>
#include <bitset>
#include <dirent.h>
#include <cstddef>
#include <sys/stat.h>
#include <stdio.h>
#include <time.h>

#define NEW_LOG 0
#define APPEND_LOG 1
#define MAX_LEN 524288
typedef int S_MODE;

bool file_exists(const std::string& name) {
  struct stat buffer;   
  return (stat(name.c_str(), &buffer) == 0); 
}

long get_file_size(std::string filename) {
    struct stat stat_buf;
    int rc = stat(filename.c_str(), &stat_buf);
    return rc == 0 ? stat_buf.st_size : -1;
}

std::string currentDateTime() {
    time_t now = time(0);
    struct tm tstruct;
    char buf[128];
    tstruct = *localtime(&now);
    strftime(buf, sizeof(buf), "%Y-%m-%d | %X", &tstruct);
    return buf;
}

class FLog {
private:
    std::string fpath, cache;
    char instance_address[128];
    bool auto_s = false;

public:
    inline FLog(std::string path) {
        sprintf(instance_address, "%p", this);
        cache.append("/--- New FLog Instance / MemPtr : ");
        cache.append(instance_address);
        cache.append(" ---/");
        cache.append("\n/--- Path : ");
        cache.append(path);
        cache.append(" ---/");
		cache.append("\n/--- Creation Date : ");
		cache.append(currentDateTime());
		cache.append(" ---/\n\n");
        fpath = path;
    }
    
    inline void append(std::string str) {
        cache.append("\n");
		cache.append(currentDateTime());
		cache.append(" : ");
        cache.append(str);
        cache.append("\n");
        if (auto_s) {
            this->save(NEW_LOG);
        }
    }
	
	inline void append(int str) {
        cache.append("\n");
		cache.append(currentDateTime());
		cache.append(" : ");
        cache.append(std::to_string(str));
        cache.append("\n");
        if (auto_s) {
            this->save(NEW_LOG);
        }
    }
	
	template<typename ...Args>
	inline void append_arg(std::string str, Args ...args) {
		char memr[MAX_LEN];
		sprintf(memr, str.c_str(), args...);
		cache.append("\n");
		cache.append(currentDateTime());
		cache.append(" : ");
        cache.append(memr);
        cache.append("\n");
        if (auto_s) {
            this->save(NEW_LOG);
        }
	}
    
    template<typename ...Args>
	inline void append_arg_mode(std::string str, int modee, Args ...args) {
		char memr[MAX_LEN];
		sprintf(memr, str.c_str(), args...);
		cache.append("\n");
		cache.append(currentDateTime());
		cache.append(" : ");
        cache.append(memr);
        cache.append("\n");
        if (auto_s) {
            this->save(modee);
        }
	}
	
    inline std::string get_address_str() {
        return std::string(instance_address);
    }
    
    inline uintptr_t get_address_ptr() {
        return (uintptr_t) this;
    }
    
    inline void autosave(bool state) {
        auto_s = state;
    }
    
    inline void clear() {
        cache = "";
    }
    
    inline void erase() {
        if (file_exists(fpath) && get_file_size(fpath) > 0) {
            remove(fpath.c_str());
        }
    }
    
    inline void save(S_MODE mode) {
        if (mode == NEW_LOG) {
            std::ofstream out(fpath.c_str());
            out << cache;
        } else if (mode == APPEND_LOG) {
            std::ifstream in(fpath.c_str());
            std::stringstream data;
            if (file_exists(fpath) && get_file_size(fpath) > 0) {
                data << in.rdbuf();
                data << "\n";
                data << cache;
                std::ofstream out(fpath.c_str());
                out << data.str();
            } else {
                std::ofstream out(fpath.c_str());
                out << cache;
            }
        } else {
            std::ofstream out(fpath.c_str());
            out << "Failed to save logs!\nException : Unknown saving mode!";
        }
    }
};

