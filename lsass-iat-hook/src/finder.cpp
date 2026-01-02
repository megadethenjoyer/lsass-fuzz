#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <tlhelp32.h>
#include <cassert>

#include "finder.h"
#include "driver.h"

uint64_t finder::find_pid( std::string_view target_name ) {
	HANDLE h_snapshot = CreateToolhelp32Snapshot( TH32CS_SNAPPROCESS, 0 );
	PROCESSENTRY32 proc = {
		.dwSize = sizeof( proc )
	};

	uint32_t pid = 0;

	assert( Process32First( h_snapshot, &proc ) == TRUE );
	do {
		if ( target_name == proc.szExeFile ) {
			pid = proc.th32ProcessID;
			break;
		}
	} while ( Process32Next( h_snapshot, &proc ) == TRUE );
	CloseHandle( h_snapshot );

	return static_cast< uint64_t >( pid );
}

#pragma pack( push, 1 )
struct ldr_entry {
	LIST_ENTRY load_order_links;
    LIST_ENTRY memory_order_links;
	LIST_ENTRY init_order_links;
    uintptr_t dll_base;
	uintptr_t entry_point;
	uint32_t size;
	uint32_t padding;
    UNICODE_STRING full_dll_name;
	UNICODE_STRING base_dll_name;
};
#pragma pack( pop )

bool is_equal_lower( std::wstring_view a, std::string_view b ) {
	if ( a.size( ) != b.size( ) ) {
		return false;
	}

	for ( size_t i = 0; i < a.size( ); i++ ) {
		// don't compare wchars
		if ( a[ i ] > 0xFF ) {
			return false;
		}

		if ( tolower( static_cast< char >( a[ i ] ) ) != tolower( b[ i ] ) ) {
			return false;
		}
	}

	return true;
}

auto finder::find_module( uint64_t pid, std::string_view target_name ) -> mod {
	PEB peb = driver::get_peb( );
	auto ldr = driver::read< PEB_LDR_DATA >( std::bit_cast< uintptr_t >( peb.Ldr ) );

	LIST_ENTRY *head = &peb.Ldr->InMemoryOrderModuleList;
	LIST_ENTRY *list = ldr.InMemoryOrderModuleList.Flink;
	for ( ;; ) {
		auto *p_entry = CONTAINING_RECORD( list, ldr_entry, memory_order_links );
		auto entry = driver::read( p_entry );
		
		wchar_t dll_name[ 260 ] = { };
		driver::read_unicode_str( entry.base_dll_name, dll_name, 260 );

		if ( is_equal_lower( dll_name, target_name ) ) {
			return mod{
				.base = entry.dll_base,
				.size = entry.size
			};
		}

		list = entry.memory_order_links.Flink;
		if ( list == head ) {
			break;
		}
	}

	return mod::empty( );
}
