#include <cassert>
#include <print>
#include <cstdint>
#include <thread>
#include "ipc.h"
#include "gateway.h"
#include "hook.h"
#include "driver.h"

const char *pipe_name = nullptr;

void client_thread( HANDLE h_pipe ) {
	char buffer[ 8 ];

	for ( ;; ) {
		assert( ReadFile( h_pipe, buffer, sizeof( buffer ), nullptr, nullptr ) );

		uint32_t fnv_hash = *std::bit_cast< uint32_t * >( &buffer[ 0 ] );
		uint32_t thread_id = *std::bit_cast< uint32_t * >( &buffer[ 4 ] );

		if ( !hook::g_smbuf ) {
			continue;
		}
		auto smbuf_tid = driver::read< uintptr_t >( hook::g_smbuf );

		if ( smbuf_tid != gateway::tid ) {
			continue;
		}

		//std::println( "(*) ipc: got buffer: fnv hash {}", fnv_hash );
		//std::println( "         -> by name     {}", hook::g_names[ fnv_hash ] );

		char wb_buffer[ 5 ] = { };
		wb_buffer[ 0 ] = 0x01;
		*std::bit_cast< uint32_t * >( wb_buffer + 1 ) = fnv_hash;

		//std::println( "o op lock" );
		gateway::op_mutex.lock( );
		//std::println( "o op lockd" );
		
		if ( gateway::in_operation ) {
			//std::println( "inop" );
			//std::println( "         -> by name {}", hook::g_names[ fnv_hash ] );
			gateway::pipe_mutex.lock( );

			//DWORD mode = PIPE_NOWAIT | PIPE_READMODE_MESSAGE;
			//SetNamedPipeHandleState( gateway::pipe, &mode, nullptr, nullptr );

			DWORD wr = { };
			assert( WriteFile( gateway::pipe, wb_buffer, sizeof( wb_buffer ), &wr, nullptr ) );

			//mode = PIPE_WAIT | PIPE_READMODE_MESSAGE;
			//SetNamedPipeHandleState( gateway::pipe, &mode, nullptr, nullptr );

			gateway::pipe_mutex.unlock( );
		}

		//std::println( "o op unl" );
		gateway::op_mutex.unlock( );

		//std::println( "(*) Written to pipe" );
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

void ipc::init( const char *name ) {
	pipe_name = name;

	HANDLE h_pipe = CreateNamedPipe( pipe_name, PIPE_ACCESS_DUPLEX, PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT, PIPE_UNLIMITED_INSTANCES, 0, 4, 0, nullptr );
	assert( h_pipe != INVALID_HANDLE_VALUE );

	ipc::g_pipe = h_pipe;

	std::thread( ipc_thread, h_pipe ).detach( );
}

HANDLE ipc::create_target_pipe( ) {
	HANDLE h_pipe = CreateFile( pipe_name, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL );
	assert( h_pipe != INVALID_HANDLE_VALUE );

	DWORD mode = PIPE_READMODE_MESSAGE;
	assert( SetNamedPipeHandleState( h_pipe, &mode, nullptr, nullptr ) );

	return h_pipe;
}
