#include <cassert>
#include <cstdlib>
#include <print>
#include <thread>

#include "driver.h"
#include "finder.h"
#include "hook.h"
#include "gateway.h"
#include "ipc.h"


int main( int argc, char **argv ) {

	Sleep( 1000 );

	if ( argc < 5 ) {
		std::println( "(*) bad args" );
		std::println( "    usage: <x.exe> (pipe name) (client pipe name) (gw pipe name) (bufsize)" );
		return 2;
	}

	std::println( "(*) use pipe {} c pipe {} gw pipe {}", argv[ 1 ], argv[ 2 ], argv[ 3 ] );

	char *bufsize_str = argv[ 4 ];
	size_t bufsize = strtoull( bufsize_str, nullptr, 10 );

	std::println( "(*) Use bufsize {}", bufsize );

	ipc::init( argv[ 1 ] );

	//hook::hook_iat( "lsa_test2.exe", "lsa_test2.exe" );
	//hook::hook_iat( "harness.exe", "harness.exe" );
	hook::hook_iat( "lsass.exe", "lsasrv.dll" );

	hook::hook_cid_gather( "sspisrv.dll", 0x16F0, 13 );

	gateway::init( argv[ 3 ], argv[ 2 ], bufsize );

	while ( true ) {
		Sleep( 10 * 60000 );
	}

	return EXIT_SUCCESS;
}