#include <cinttypes>
#include <sys/mman.h>
#include <set>
#include <string_view>
#include <pmparser.h>
#include "hide.h"
#include <android/log.h>

enum LogType {
    oDEBUG = 3,
    oERROR = 6,
    oINFO  = 4,
    oWARN  = 5
};

#define TAG "LHIDE"

#define LOGD(...) ((void)__android_log_print(oDEBUG, TAG, __VA_ARGS__))
#define LOGE(...) ((void)__android_log_print(oERROR, TAG, __VA_ARGS__))
#define LOGI(...) ((void)__android_log_print(oINFO,  TAG, __VA_ARGS__))
#define LOGW(...) ((void)__android_log_print(oWARN,  TAG, __VA_ARGS__))

/**
 * Magic to hide from /proc/###/maps, the idea is from Haruue Icymoon (https://github.com/haruue)
 */

#define EXPORT __attribute__((visibility("default"))) __attribute__((used))

struct hide_struct {
    procmaps_struct *original;
    uintptr_t backup_address;
};

static int get_prot(const procmaps_struct *procstruct) {
    int prot = 0;
    if (procstruct->is_r) {
        prot |= PROT_READ;
    }
    if (procstruct->is_w) {
        prot |= PROT_WRITE;
    }
    if (procstruct->is_x) {
        prot |= PROT_EXEC;
    }
    return prot;
}

#define FAILURE_RETURN(exp, failure_value) ({   \
    __typeof__(exp) _rc;                    \
    _rc = (exp);                            \
    if (_rc == failure_value) {             \
        return 1;                           \
    }                                       \
    _rc; })
	
bool setMap(Map &map, uint8_t flags)
{
	Map cmp{};
	bool match = false;
	FILE *maps = fopen("/proc/self/maps", "rb");

	if (maps != nullptr)
	{
		while (!(feof(maps) || match))
		{
			fscanf(maps, "%p-%p %s %x %s %d%*[ ]%[^\n]", &cmp.start, &cmp.end, cmp.mode, &cmp.offset, cmp.dev, &cmp.inode, cmp.path);

			cmp.length = cmp.end - cmp.start;

			if (flags & MAP_START && map.start != cmp.start)
				continue;
			if (flags & MAP_END && map.end != cmp.end)
				continue;
			if (flags & MAP_MODE && strcmp(map.mode, cmp.mode) != 0)
				continue;
			if (flags & MAP_OFFSET && map.offset != cmp.offset)
				continue;
			if (flags & MAP_DEV && strcmp(map.dev, cmp.dev) != 0)
				continue;
			if (flags & MAP_INODE && map.inode != cmp.inode)
				continue;
			if (flags & MAP_PATH && !strstr(cmp.path, map.path))
				continue;
			if (flags & MAP_LENGTH && map.length != cmp.length)
				continue;

			memcpy(&map, &cmp, sizeof(Map));

			match = true;
		}

		fclose(maps);
	}

	return match;
}

bool vcontains(const std::set<std::string_view>& sv_set, std::string_view target) {
    return std::any_of(sv_set.begin(), sv_set.end(), [&](std::string_view sv) {
        return sv.find(target) != std::string_view::npos;
    });
}

static int do_hide(hide_struct *data) {
    auto procstruct = data->original;
    auto start = (uintptr_t) procstruct->addr_start;
    auto end = (uintptr_t) procstruct->addr_end;
    auto length = end - start;
    int prot = get_prot(procstruct);
	//LOGD("action %p, %p, %p", start, end, length);
    // backup
    data->backup_address = (uintptr_t) FAILURE_RETURN(
            mmap(nullptr, length, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0),
            MAP_FAILED);
    if (!procstruct->is_r) {
        FAILURE_RETURN(mprotect((void *) start, length, prot | PROT_READ), -1);
    }
    memcpy((void *) data->backup_address, (void *) start, length);
    FAILURE_RETURN(munmap((void *) start, length), -1);
    FAILURE_RETURN(mmap((void *) start, length, prot, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0),
                   MAP_FAILED);
    FAILURE_RETURN(mprotect((void *) start, length, prot | PROT_WRITE), -1);
    memcpy((void *) start, (void *) data->backup_address, length);
    if (!procstruct->is_w) {
        FAILURE_RETURN(mprotect((void *) start, length, prot), -1);
    }
    return 0;
}

bool hcontains(const char* in, const char* target) {
    if (strstr(in, target)) {
        return true;
    }
    return false;
}

int riru_hide(const char* name) {
    procmaps_iterator *maps = pmparser_parse(-1);
    if (maps == nullptr) {
        return false;
    }

    char buf[PATH_MAX];
    hide_struct *data = nullptr;
    size_t data_count = 0;
	int countt = 0;
    procmaps_struct *maps_tmp;
    while ((maps_tmp = pmparser_next(maps)) != nullptr) {
        bool matched = false;
        matched = hcontains(maps_tmp->pathname, name);
        if (!matched) continue;
		//LOGD("Found %s, %p", maps_tmp->pathname, maps_tmp->length);

        auto start = (uintptr_t) maps_tmp->addr_start;
        auto end = (uintptr_t) maps_tmp->addr_end;
        
		if (maps_tmp->is_r) {
            if (data) {
                data = (hide_struct *) realloc(data, sizeof(hide_struct) * (data_count + 1));
            } else {
                data = (hide_struct *) malloc(sizeof(hide_struct));
            }
            data[data_count].original = maps_tmp;
            data_count += 1;
        }
    }

    for (int i = 0; i < data_count; ++i) {
        do_hide(&data[i]);
    }

    if (data) free(data);
    pmparser_free(maps);
    return 0;
}
