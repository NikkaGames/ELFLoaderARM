#include <cinttypes>
#include <sys/mman.h>
#include <set>
#include <string_view>

int riru_hide(const char* name);

enum : uint8_t
{
	MAP_START =  1,
	MAP_END =    2,
	MAP_MODE =   4,
	MAP_OFFSET = 8,
	MAP_DEV =    16,
	MAP_INODE =  32,
	MAP_PATH =   64,
	MAP_LENGTH = 128,
};

constexpr uint8_t BUFFER_SIZE = 255;

struct Map
{
	uintptr_t start, end;
	char mode[BUFFER_SIZE];
	intptr_t offset;
	char dev[BUFFER_SIZE];
	uint32_t inode;
	char path[BUFFER_SIZE];
	size_t length;
};

bool setMap(Map &map, uint8_t flags);
