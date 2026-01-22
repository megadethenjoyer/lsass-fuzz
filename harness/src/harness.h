#pragma once
#include <cstdlib>

struct harness {
	virtual bool setup( ) = 0;
	virtual bool execute( char *buffer ) = 0;
	virtual size_t get_bufsize( ) = 0;

	inline char *alloc_buffer( ) {
		return std::bit_cast< char * >( malloc( this->get_bufsize( ) ) );
	}
};
