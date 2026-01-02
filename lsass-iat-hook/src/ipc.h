#pragma once
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

namespace ipc {
	inline HANDLE g_pipe;

	void init( );
	HANDLE create_target_pipe( );
}
