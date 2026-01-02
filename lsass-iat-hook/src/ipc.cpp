#include <cassert>
#include <print>
#include <cstdint>
#include <thread>
#include "ipc.h"
#include "hook.h"

constexpr const char *pipe_name = "\\\\.\\pipe\\LsassFuzzPipe";

void client_thread( HANDLE h_pipe ) {
	char buffer[ 4 ];

	for ( ;; ) {
		assert( ReadFile( h_pipe, buffer, sizeof( buffer ), nullptr, nullptr ) );

		uint32_t fnv_hash = *std::bit_cast< uint32_t * >( &buffer[ 0 ] );
		std::println( "(*) IPC: Got buffer: FNV HASH {}", fnv_hash );
		std::println( "         -> BY NAME {}", hook::g_names[ fnv_hash ] );
	}
}

void ipc_thread( HANDLE h_pipe ) {
	bool is_connected = ConnectNamedPipe( h_pipe, NULL );
	if ( is_connected == false ) {
		is_connected = GetLastError( ) == ERROR_PIPE_CONNECTED;
	}

	assert( is_connected );

	std::println( "(*) IPC: client connected" );
	std::thread( client_thread, h_pipe ).detach( );
}

void ipc::init( ) {
	HANDLE h_pipe = CreateNamedPipe( pipe_name, PIPE_ACCESS_DUPLEX, PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT, PIPE_UNLIMITED_INSTANCES, 0, 4, 0, nullptr );
	assert( h_pipe != INVALID_HANDLE_VALUE );

	ipc::g_pipe = h_pipe;

	std::thread( ipc_thread, h_pipe ).detach( );
}

HANDLE ipc::create_target_pipe( ) {
	HANDLE h_pipe = CreateFile( "\\\\.\\pipe\\LsassFuzzPipe", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL );
	assert( h_pipe != INVALID_HANDLE_VALUE );

	DWORD mode = PIPE_READMODE_MESSAGE;
	assert( SetNamedPipeHandleState( h_pipe, &mode, nullptr, nullptr ) );

	return h_pipe;
}
