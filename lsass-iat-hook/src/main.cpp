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

	ipc::init( );

	hook::hook_iat( "harness.exe", "harness.exe" );
	//hook::hook_iat( "lsass.exe", "lsasrv.dll" );

	gateway::init( );

	Sleep( 10 * 60000 );

	return EXIT_SUCCESS;
}