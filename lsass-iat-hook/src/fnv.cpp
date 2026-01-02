#include "fnv.h"

uint32_t fnv::hash( std::string_view str ) {
    const size_t length = str.length( );
    unsigned int hash = BASIS;
    for ( char c: str ) {
        hash ^= c;
        hash *= PRIME;
    }
    return hash;
}