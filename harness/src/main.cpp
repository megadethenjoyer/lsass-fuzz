// TODO: rewrite
// TODO: add Lsa function support

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <print>
#include <cassert>
#include <cstdint>
#include <cstdlib>
#include <cstdio>
#include <memory>
#include <iostream>
#include <fstream>
#include <print>

#include "lsalogonuser-msv1-interactive-logon.h"
#include "lsalogonuser-kerb-interactive-logon.h"

#define OPT( x ) if ( name == #x ) { return std::make_unique< x >( ); }
std::unique_ptr< harness > get_harness( const std::string_view name ) {
	OPT( lsa_logon_user_msv1_interactive_logon_harness );
	OPT( lsa_logon_user_kerb_interactive_logon_harness );

	return nullptr;
}

char *buffer = nullptr;
size_t buf_size = 0;

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
	ReadFile( g_pipe, buffer, buf_size, nullptr, nullptr );
}

int main( int argc, char **argv ) {
	if ( argc < 4 ) {
		std::println( "(*) bad args" );
		std::println( "    usage: <x.exe> gw_pipe_name harness_name tmp_bufsize_file" );
		system( "pause" );
		return 2;
	}

	const char *bufsize_file = argv[ 3 ];

	const char *harness_name = argv[ 2 ];
	std::println( "(*) Getting harness {}", harness_name );
	auto harness = get_harness( harness_name );
	if ( harness == nullptr ) {
		std::println( "(!) No such harness {}", harness_name );
		system( "pause" );
		return 3;
	}

	std::println( "(*) Write to {}", bufsize_file );
	{
		std::ofstream s( bufsize_file );
		s << harness->get_bufsize( );
	}

	std::println( "(*) Setting up harness" );
	if ( !harness->setup( ) ) {
		std::println( "(!) Failed to set up harness" );
		system( "pause" );
		return EXIT_FAILURE;
	}

	std::println( "(+) Harness set up" );
	std::println( "(*) Use pipe {}", argv[ 1 ] );
	HANDLE h_pipe = CreateNamedPipeA( argv[ 1 ], PIPE_ACCESS_DUPLEX, PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT, PIPE_UNLIMITED_INSTANCES, 0, 4, 0, nullptr );
	assert( h_pipe != INVALID_HANDLE_VALUE );

	g_pipe = h_pipe;

	bool is_connected = ConnectNamedPipe( h_pipe, NULL );
	if ( is_connected == false ) {
		is_connected = GetLastError( ) == ERROR_PIPE_CONNECTED;
	}
	assert( is_connected );

	uint32_t tid = GetCurrentThreadId( );
	std::println( "(*) Pipe connected, send TID {}", tid );
	bool res = WriteFile( h_pipe, ( void * )&tid, 4, nullptr, nullptr );
	assert( res );

	std::println( "(*) written" );
	Sleep( 500 );

	buffer = harness->alloc_buffer( );
	buf_size = harness->get_bufsize( );
	std::println( "(*) Pipe ready, run main loop (bufsize = {})", buf_size );
	while ( true ) {
		recv_buf( );

		bool crashed = harness->execute( buffer );
		if ( crashed ) {
			send_crashed( );
			puts( "CRASH" );
			system( "pause" );
			return EXIT_SUCCESS;
		}

		send_done( );
	}


}