#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>

#include <bit>
#include <cstdint>
#include <cassert>

namespace driver {
	bool init( uint64_t pid );
	uintptr_t get_peb_addr( );
	bool read_raw( uintptr_t remote_addr, void *local_addr, size_t size );
	bool write_raw( uintptr_t remote_addr, void *local_addr, size_t size );
	
	template <typename T>
	T read( uintptr_t remote_addr ) {
		T x = { };
		bool r = read_raw( remote_addr, &x, sizeof( x ) );
		assert( r );
		return x;
	}

	template <typename T>
	T read( T *remote_addr ) {
		T x = { };
		bool r = read_raw( std::bit_cast< uintptr_t >( remote_addr ), &x, sizeof( x ) );
		assert( r );
		return x;
	}

	template <typename T>
	bool write( uintptr_t remote_addr, T x ) {
		bool res = write_raw( remote_addr, &x, sizeof( x ) );
		assert( res );
		return res;
	}

	template <typename T>
	bool write( T *remote_addr, T x ) {
		bool res = write_raw( std::bit_cast< uintptr_t >( remote_addr ), &x, sizeof( x ) );
		assert( res );
		return res;
	}

	bool read_unicode_str( UNICODE_STRING remote_string, wchar_t *local, size_t n );

	PEB get_peb( );

	uintptr_t alloc( size_t s );
	uintptr_t duplicate_handle( HANDLE source );
	// Returns old protection
	uint32_t protect( uintptr_t address, size_t size, uint32_t protection );

	inline uint64_t g_pid = { };
	inline HANDLE g_file = { };
}
