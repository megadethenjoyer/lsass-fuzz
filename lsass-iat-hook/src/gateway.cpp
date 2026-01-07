#include <cassert>
#include <print>
#include <cstdint>
#include <thread>
#include "gateway.h"
#include "hook.h"

constexpr const char *pipe_name = "\\\\.\\pipe\\GatewayPipe";

void gw_client_thread( HANDLE h_pipe ) {
	HANDLE harness = CreateFile( "\\\\.\\pipe\\TargetPipe", GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_ALWAYS, 0, nullptr );
	assert( harness != INVALID_HANDLE_VALUE );

	gateway::pipe = h_pipe;

	char buffer[ 5 ];

	while ( true ) {
		std::println( "a" );
		assert( ReadFile( h_pipe, buffer, sizeof( buffer ), nullptr, nullptr ) );

		std::println( "b" );
		WriteFile( harness, buffer, sizeof( buffer ), nullptr, nullptr );

		while ( true ) {
			char harness_buffer[ 4 ];
			std::println( "c" );
			ReadFile( harness, harness_buffer, sizeof( harness_buffer ), nullptr, nullptr );

			char wb_buffer[ 1 + 4 ] = { };
			wb_buffer[ 0 ] = 0x02;
			memcpy( wb_buffer + 1, harness_buffer, sizeof( harness_buffer ) );
			std::println( "d" );
			assert( WriteFile( h_pipe, wb_buffer, sizeof( wb_buffer ), nullptr, nullptr ) );

			if ( *( uint32_t * )harness_buffer == 'enod' ) {
				break;
			}
		}
	}


}

void gw_ipc_thread( HANDLE h_pipe ) {
	bool is_connected = ConnectNamedPipe( h_pipe, NULL );
	if ( is_connected == false ) {
		is_connected = GetLastError( ) == ERROR_PIPE_CONNECTED;
	}

	assert( is_connected );

	std::println( "(*) Gateway IPC: client connected" );
	std::thread( gw_client_thread, h_pipe ).detach( );
}

void gateway::init( ) {
	HANDLE h_pipe = CreateNamedPipe( pipe_name, PIPE_ACCESS_DUPLEX, PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT, PIPE_UNLIMITED_INSTANCES, 0, 4, 0, nullptr );
	assert( h_pipe != INVALID_HANDLE_VALUE );

	std::thread( gw_ipc_thread, h_pipe ).detach( );
}
