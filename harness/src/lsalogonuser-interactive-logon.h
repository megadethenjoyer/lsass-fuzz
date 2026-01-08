#pragma once
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <ntsecapi.h>
#include <cstddef>

struct lsa_logon_user_interactive_logon_harness {
	static constexpr size_t buf_size = 8*3*2;
	static bool setup( );
	static bool execute( char *buffer );

	static inline char g_origin_name_str[ ] = "uselessoriginname";
	static inline LSA_STRING g_origin_name = {
		.Length = sizeof( g_origin_name_str ) - 1,
		.MaximumLength = sizeof( g_origin_name_str ) - 1,
		.Buffer = g_origin_name_str,
	};
	static inline DWORD g_auth_package = { };
	static inline HANDLE g_lsa_handle = { };
	static inline TOKEN_SOURCE g_token_source = { };
};
