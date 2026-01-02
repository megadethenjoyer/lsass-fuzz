#include "driver.h"

#include <cassert>

constexpr const char *DEVICE_NAME = "\\\\.\\LsassFuzzHelper";

constexpr uint32_t READ = 0x220004;
constexpr uint32_t WRITE = 0x220008;
constexpr uint32_t GET_PEB = 0x22000C;
constexpr uint32_t ALLOC = 0x220010;
constexpr uint32_t DUPLICATE = 0x220014;
constexpr uint32_t PROTECT = 0x220018;

#pragma pack( push, 1 )
struct helper_data {
	uint64_t process_id;
	size_t data_size;
	uintptr_t remote_addr;
	void *local_addr;
};
#pragma pack( pop )

bool ioctl( uint32_t ctl_code, helper_data *data ) {
	return DeviceIoControl( driver::g_file, ctl_code, data, sizeof( *data ), data, sizeof( *data ), nullptr, nullptr );
}

bool driver::init( uint64_t pid ) {
	HANDLE h_file = CreateFileA( DEVICE_NAME, FILE_GENERIC_READ | FILE_GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_DEVICE, nullptr );
	assert( h_file != INVALID_HANDLE_VALUE );
	if ( h_file == INVALID_HANDLE_VALUE ) {
		return false;
	}

	driver::g_file = h_file;
	driver::g_pid = pid;
	
	return true;
}

uintptr_t driver::get_peb_addr( ) {
	uintptr_t peb_addr = { };
	helper_data data = {
		.process_id = driver::g_pid,
		.local_addr = &peb_addr
	};
	ioctl( GET_PEB, &data );
	return peb_addr;
}


bool driver::read_raw( uintptr_t remote_addr, void *local_addr, size_t size ) {
	helper_data data = {
		.process_id = driver::g_pid,
		.data_size = size,
		.remote_addr = remote_addr,
		.local_addr = local_addr,
	};
	return ioctl( READ, &data );
}
bool driver::write_raw( uintptr_t remote_addr, void *local_addr, size_t size ) {
	helper_data data = {
		.process_id = driver::g_pid,
		.data_size = size,
		.remote_addr = remote_addr,
		.local_addr = local_addr,
	};
	return ioctl( WRITE, &data );
}

bool driver::read_unicode_str( UNICODE_STRING remote_string, wchar_t *local, size_t n ) {
	size_t length = remote_string.Length;
	length = min( remote_string.Length, n );
	return read_raw( std::bit_cast< uintptr_t >( remote_string.Buffer ), static_cast< void * >( local ), length * 2 );

}

PEB driver::get_peb( ) {
	return read< PEB >( get_peb_addr( ) );
}

uintptr_t driver::alloc( size_t size ) {
	uintptr_t alloc = { };

	helper_data data = {
		.process_id = driver::g_pid,
		.data_size = size,
		.local_addr = static_cast< void * >( &alloc ),
	};
	assert( ioctl( ALLOC, &data ) );

	return alloc;
}

uintptr_t driver::duplicate_handle( HANDLE source ) {
	uintptr_t h_target = { };

	helper_data data = {
		.process_id = driver::g_pid,
		.remote_addr = std::bit_cast< uintptr_t >( source ),
		.local_addr = static_cast< void * >( &h_target ),
	};
	assert( ioctl( DUPLICATE, &data ) );

	return h_target;
}

uint32_t driver::protect( uintptr_t address, size_t size, uint32_t protection ) {
	uint32_t old_protect = { };
	
	uintptr_t info[ 2 ] = { };
	info[ 0 ] = protection;
	info[ 1 ] = std::bit_cast< uintptr_t >( &old_protect );

	helper_data data = {
		.process_id = driver::g_pid,
		.data_size = size,
		.remote_addr = address,
		.local_addr = static_cast< void * >( info ),
	};
	assert( ioctl( PROTECT, &data ) );

	return old_protect;
}
