#pragma once
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <mutex>

namespace gateway {
	inline HANDLE pipe;
	inline std::mutex pipe_mutex;

	inline uint32_t tid;
	inline bool in_operation = false;
	inline std::mutex op_mutex;

	void init( const char *pipe_name, const char *client_name, size_t bufsize );
}
