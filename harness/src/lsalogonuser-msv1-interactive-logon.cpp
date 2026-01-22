#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <ntsecapi.h>
#include <print>
#include <cstdio>
#include <iostream>
#include "lsalogonuser-msv1-interactive-logon.h"

#pragma comment(lib, "secur32.lib")

bool lsa_logon_user_msv1_interactive_logon_harness::setup( ) {
	/*
	LSA_OPERATIONAL_MODE mode = { };

	char proc_name_str[ ] = "cool";
	LSA_STRING proc_name = {
		.Length = sizeof( proc_name_str ) - 1,
		.MaximumLength = sizeof( proc_name_str ) - 1,
		.Buffer = proc_name_str
	};

	NTSTATUS status = LsaRegisterLogonProcess( &proc_name, &g_lsa_handle, &mode );
	if ( status != ( NTSTATUS )( 0 ) ) {
		std::println( "(!) LsaRegisterLogonProcess( ) = 0x{:X}", static_cast< uint32_t >( status ) );
		return false;
	}
	*/

	NTSTATUS status = LsaConnectUntrusted( &g_lsa_handle );
	if ( status != ( NTSTATUS )( 0 ) ) {
		std::println( "(!) LsaConnectUntrusted( ) = 0x{:X}", static_cast< uint32_t >( status ) );
		return false;
	}
	

	char package_name_str[ ] = MSV1_0_PACKAGE_NAME;
	LSA_STRING package_name = {
		.Length = sizeof( package_name_str ) - 1,
		.MaximumLength = sizeof( package_name_str ) - 1,
		.Buffer = package_name_str
	};

	status = LsaLookupAuthenticationPackage(
		g_lsa_handle,
		&package_name,
		&g_auth_package
	);
	if ( status != ( NTSTATUS )( 0 ) ) {
		std::println( "(!) LsaLookupAuthenticationPackage( ) = 0x{:X}", static_cast< uint32_t >( status ) );
		return false;
	}

	HANDLE h_token = { };
	if ( !OpenProcessToken( GetCurrentProcess( ), TOKEN_QUERY | TOKEN_QUERY_SOURCE, &h_token ) ) {
		std::println( "(!) OpenProcessToken( ) -> {}", GetLastError( ) );
		return false;
	}
	
	DWORD out_len = { };
	if ( !GetTokenInformation( h_token, TokenSource, &g_token_source, sizeof( g_token_source ), &out_len ) ) {
		std::println( "(!) GetTokenInformation( ) -> {}", GetLastError( ) );
		return false;
	}

	std::print( "(*) token source = " );
	for ( int i = 0; i < 8; i++ ) {
		std::print( "{}", g_token_source.SourceName[ i ] );
	}
	std::println( );

	return true;
}

bool lsa_logon_user_msv1_interactive_logon_harness::execute( char *buffer ) {

	MSV1_0_INTERACTIVE_LOGON il = {
		.MessageType = MsV1_0InteractiveLogon
	};
	
	uint16_t b1 = wcsnlen( ( wchar_t* )buffer, 8 );
	uint16_t b2 = wcsnlen( ( wchar_t* )buffer + b1 + 1, 8 );
	uint16_t b3 = wcsnlen( ( wchar_t* )buffer + b1 + 1 + b2 + 1, 8 );

	buffer[ b1 ] = 0;
	buffer[ b1 + 1 + b2 ] = 0;
	buffer[ b1 + 1 + b2 + 1 + b3 ] = 0;


	UNICODE_STRING a1 = {
		.Length = b1,
		.MaximumLength = b1,
		.Buffer = (wchar_t*)buffer,
	};

	UNICODE_STRING a2 = {
		.Length = b2,
		.MaximumLength = b2,
		.Buffer = (wchar_t*)buffer + b1 + 1,
	};

	UNICODE_STRING a3 = {
		.Length = b3,
		.MaximumLength = b3,
		.Buffer = (wchar_t*)buffer + b1 + 1 + b2 + 1,
	};

	il.LogonDomainName = a1;
	il.Password = a2;
	il.UserName = a3;

	for ( int i = 0; i < a1.Length; i++ ) {
		std::cout << ( char )a1.Buffer[ i ];
	}
	std::cout << " // ";
	for ( int i = 0; i < a2.Length; i++ ) {
		std::cout << ( char )a2.Buffer[ i ];
	}
	std::cout << " // ";
	for ( int i = 0; i < a3.Length; i++ ) {
		std::cout << ( char )a3.Buffer[ i ];
	}
	std::cout << '\n';

	void *profile;
	ULONG profile_len;
	LUID logon_luid;
	HANDLE out_token;
	QUOTA_LIMITS ql;
	NTSTATUS subst;

	NTSTATUS st = LsaLogonUser(
		g_lsa_handle,
		&g_origin_name,
		Interactive,
		g_auth_package,
		&il,
		sizeof( il ),
		nullptr,
		&g_token_source,
		&profile, &profile_len, &logon_luid, &out_token, &ql, &subst  // outputs
	);

	//std::println( "LsaLogonUser( ) = 0x{:X}", static_cast< uint32_t >( st ) );
	//std::cout << "wcout test\n";

	if ( ( uint32_t )st != 0xC000000D ) {
		return true;
	}

	return false;
}
