// TODO: rewrite
// TODO: add Lsa function support

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <print>
#include <cassert>
#include <cstdint>
#include <cstdlib>
#include <cstdio>
#include <print>

#include "sample.h"
#include "lsalogonuser-interactive-logon.h"

using current_harness = lsa_logon_user_interactive_logon_harness;

constexpr size_t BUFSIZE = current_harness::buf_size;
char buffer[ BUFSIZE ];

HANDLE g_pipe = { };

void send_done( ) {
	char done_buffer[ 4 ] = { 'd', 'o', 'n', 'e' };
	WriteFile( g_pipe, done_buffer, sizeof( done_buffer ), nullptr, nullptr );
}

void send_crashed( ) {
	char crash_buffer[ 4 ] = { 0xAA, 0xCC, 0xAA, 0xCC };
	WriteFile( g_pipe, crash_buffer, sizeof( crash_buffer ), nullptr, nullptr );
}

void recv_buf( ) {
	ReadFile( g_pipe, buffer, sizeof( buffer ), nullptr, nullptr );
}

int main( ) {
	std::println( "(*) Setting up harness" );
	if ( !current_harness::setup( ) ) {
		std::println( "(!) Failed to set up harness" );
		system( "pause" );
		return EXIT_FAILURE;
	}

	std::println( "(+) Harness set up" );
	HANDLE h_pipe = CreateNamedPipeA( "\\\\.\\pipe\\TargetPipe", PIPE_ACCESS_DUPLEX, PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT, PIPE_UNLIMITED_INSTANCES, 0, 4, 0, nullptr );
	assert( h_pipe != INVALID_HANDLE_VALUE );

	g_pipe = h_pipe;

	bool is_connected = ConnectNamedPipe( h_pipe, NULL );
	if ( is_connected == false ) {
		is_connected = GetLastError( ) == ERROR_PIPE_CONNECTED;
	}
	assert( is_connected );

	std::println( "(*) Pipe ready, run main loop (bufsize = {})", current_harness::buf_size );
	while ( true ) {
		recv_buf( );

		bool crashed = current_harness::execute( buffer );
		if ( crashed ) {
			send_crashed( );
			puts( "CRASH" );
			system( "pause" );
			return EXIT_SUCCESS;
		}

		send_done( );
	}


}