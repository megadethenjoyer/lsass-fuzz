#include <cassert>
#include <print>
#include <cstdint>
#include <thread>
#include "gateway.h"
#include "hook.h"

const char *gw_pipe_name = nullptr;
size_t BUF_SIZE = 0;

void gw_client_thread( HANDLE h_pipe ) {
	HANDLE harness = CreateFile( gw_pipe_name, GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_ALWAYS, 0, nullptr );
	assert( harness != INVALID_HANDLE_VALUE );

	uint32_t start_tid = { };
	assert( ReadFile( harness, ( void * )&start_tid, 4, nullptr, nullptr ) );

	std::println( "(*) ipc: connected by tid {}", start_tid );

	gateway::tid = start_tid;
	gateway::pipe = h_pipe;

	static char *buffer = std::bit_cast< char * >( malloc( BUF_SIZE ) );

	//gateway::op_mutex.lock( );
	while ( true ) {
		gateway::op_mutex.lock( );
		gateway::in_operation = false;
		gateway::op_mutex.unlock( );
		//std::println( "read" );
		gateway::pipe_mutex.lock( );
		bool read_st = ReadFile( h_pipe, buffer, BUF_SIZE, nullptr, nullptr );
		gateway::pipe_mutex.unlock( );
		if ( !read_st ) { std::println( "(*) GW IPC: read fail {}", GetLastError( ) ); }
		assert( read_st );
		//std::println( "done read" );

		gateway::op_mutex.lock( );
		gateway::in_operation = true;
		gateway::op_mutex.unlock( );

		WriteFile( harness, buffer, BUF_SIZE, nullptr, nullptr );

		while ( true ) {
			char harness_buffer[ 4 ];
			ReadFile( harness, harness_buffer, sizeof( harness_buffer ), nullptr, nullptr );

			bool done = *( uint32_t * )harness_buffer == 'enod';


			if ( done ) {
				//std::println( "done" );
				gateway::op_mutex.lock( );
				gateway::in_operation = false;
				gateway::op_mutex.unlock( );
				//std::println( "ddone {}", gateway::in_operation );
			}

			char wb_buffer[ 1 + 4 ] = { };
			wb_buffer[ 0 ] = 0x02;
			memcpy( wb_buffer + 1, harness_buffer, sizeof( harness_buffer ) );
			gateway::pipe_mutex.lock( );
			DWORD wr = { };
			assert( WriteFile( h_pipe, wb_buffer, sizeof( wb_buffer ), &wr, nullptr ) );
			gateway::pipe_mutex.unlock( );

			if ( done ) {
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

void gateway::init( const char *pipe_name, const char *client_name, size_t bufsize ) {
	BUF_SIZE = bufsize;
	gw_pipe_name = pipe_name;
	
	HANDLE h_pipe = CreateNamedPipe( client_name, PIPE_ACCESS_DUPLEX, PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT, PIPE_UNLIMITED_INSTANCES, 0, 4, 0, nullptr );
	assert( h_pipe != INVALID_HANDLE_VALUE );

	std::thread( gw_ipc_thread, h_pipe ).detach( );
}
