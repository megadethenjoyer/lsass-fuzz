// TODO: rewrite
// TODO: add Lsa function support

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <print>
#include <cassert>
#include <cstdint>
#include <cstdlib>
#include <cstdio>
#include <winternl.h>

int main( ) {
	puts( "1" );
	HANDLE h_pipe = CreateNamedPipeA( "\\\\.\\pipe\\TargetPipe", PIPE_ACCESS_DUPLEX, PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT, PIPE_UNLIMITED_INSTANCES, 0, 4, 0, nullptr );
	assert( h_pipe != INVALID_HANDLE_VALUE );

	puts( "2" );
	bool ic = ConnectNamedPipe( h_pipe, NULL );
	if ( ic == false ) {
		ic = GetLastError( ) == ERROR_PIPE_CONNECTED;
	}
	puts( "3" );
	assert( ic );
	puts( "4" );

	char buffer[ 5 ];

	for ( ;; ) {
		//puts( "a" );
		ReadFile( h_pipe, buffer, sizeof( buffer ), nullptr, nullptr );
		//puts( "b" );

		//std::println( "got buffer {} {} {} {}", buffer[ 0 ], buffer[ 1 ], buffer[ 2 ], buffer[ 3 ] );


		if ( buffer[ 0 ] == 'a' ) {
			GetCurrentProcess( );
			if ( buffer[ 1 ] == 'b' ) {
				GetCurrentProcessId( );
				if ( buffer[ 2 ] == 'c' ) {
					GetAsyncKeyState( 'x' );
					if ( buffer[ 3 ] == 'd' ) {
						printf( "%c%c%c%c%c\n", buffer[ 0 ], buffer[ 1 ], buffer[ 2 ], buffer[ 3 ], buffer[ 4 ] );
						GetCurrentThreadId( );
						if ( buffer[ 4 ] == 'e' ) {

							uint32_t nc = 0xCCAACCAA;
							WriteFile( h_pipe, ( void * )&nc, sizeof( nc ), nullptr, nullptr );
							puts( "crash" );
							system( "pause" );
							return 0;
						}
					}
				}
			}
		}

		uint32_t nb = 0;
		nb = 'enod';
		WriteFile( h_pipe, ( char * )&nb, sizeof( nb ), nullptr, nullptr );
		//puts( "c" );
	}

	puts( "bye" );
	//std::println( "bye" );

}