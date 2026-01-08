#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <print>
#include <cstdio>
#include "sample.h"

bool sample_harness::execute( char *buffer ) {
	//printf( "%c%c%c%c%c\n", buffer[ 0 ], buffer[ 1 ], buffer[ 2 ], buffer[ 3 ], buffer[ 4 ] );
	if ( buffer[ 0 ] != 'a' ) {
		return false;
	}
	printf( "%c%c%c%c\n", buffer[ 0 ], buffer[ 1 ], buffer[ 2 ], buffer[ 3 ] );
	GetCurrentProcess( ); // sample call

	if ( buffer[ 1 ] != 'b' ) {
		return false;
	}
	GetCurrentProcessId( ); // sample call

	if ( buffer[ 2 ] != 'c' ) {
		return false;
	}
	GetCurrentThreadId( ); // sample call

	if ( buffer[ 3 ] != 'd' ) {
		return false;
	}
	//GetAsyncKeyState( 0 ); // sample call

	//if ( buffer[ 4 ] != 'e' ) {
	//	return false;
	//}

	return true;
}