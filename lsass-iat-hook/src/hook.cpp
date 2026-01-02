#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bit>
#include <cassert>
#include <print>

#include "hook.h"
#include "driver.h"
#include "finder.h"
#include "ipc.h"
#include "fnv.h"

bool create_universal_buffer( HANDLE h_pipe ) {
	std::println( "{:X}", ( uintptr_t )h_pipe );
	uintptr_t h_target = driver::duplicate_handle( h_pipe );

	uint8_t buffer[ ] = {
		0x48, 0x83, 0xEC, 0x14,						// sub rsp, 20 (4 for buf, 16 for IoStatusBlock)
		//0xC7, 0x04, 0x24, 0x7B, 0x00, 0x00, 0x00,   // mov dword [rsp (buf)], 123
		0x89, 0x0C, 0x24, 0x90, 0x90, 0x90, 0x90,	// mov dword [rsp (buf)], ecx
		0x48, 0x8D, 0x44, 0x24, 0x04,				// lea rax, [rsp + 4] IoStatusBlock
		0x48, 0x89, 0xE1,							// mov rcx, rsp       Buffer
		0x48, 0xC7, 0xC2, 0x04, 0x00, 0x00, 0x00,	// mov rdx, 4         Length
		0x4D, 0x31, 0xC0,							// xor r8, r8         ByteOffset & Key
		0x41, 0x50,									// push r8  ; Key = 0
		0x41, 0x50,									// push r8  ; ByteOffset = 0
		0x52,										// push rdx ; Length
		0x51,										// push rcx ; Buffer
		0x50,										// push rax ; IoStatusBlock
		0x48, 0x83, 0xEC, 0x20,						// sub rsp, 0x20 (ABI mandated)
		0x48, 0x31, 0xC9,							// xor rcx, rcx
		//    [ replace this value ] (FileHandle)
		//		VVVVVVVVVVVVVVVVVV
		0xB9, 0xDD, 0xCC, 0xBB, 0xAA,				// mov ecx, ... ; FileHandle - ideally would use rcx but c'est la vie
		0x48, 0x31, 0xD2,							// xor rdx, rdx ; Event
		0x4D, 0x31, 0xC0,							// xor r8, r8   ; ApcRoutine
		0x4D, 0x31, 0xC9,							// xor r9, r9   ; ApcContext
		0xFF, 0x15, 0x0D, 0x00, 0x00, 0x00,			// call qword [rip + 0xD] ; .call_pointer
		0x48, 0x83, 0xC4, 0x20,						// add rsp, 0x20 (ABI)
		0x48, 0x83, 0xC4, 0x28,						// add rsp, 0x28 (parameters)
		0x48, 0x83, 0xC4, 0x14,						// add rsp, 20 (buf and IoStatusBlock)
		0xC3,										// ret
		// .call_pointer:
		0xCC, 0xDD, 0xCC, 0xAA, 0xDD, 0xCC, 0xBB, 0xAA	// overwrite this with a pointer to NtWriteFile
	};

	*std::bit_cast< uint32_t * >( buffer + 44 ) = static_cast< uint32_t >( h_target );

	HMODULE ntdll = GetModuleHandle( "ntdll" );
	assert( ntdll != nullptr );
	void *NtWriteFile = GetProcAddress( ntdll, "NtWriteFile" );
	assert( NtWriteFile != nullptr );
	*std::bit_cast< uintptr_t * >( buffer + 76 ) = std::bit_cast< uintptr_t >( NtWriteFile );

	uintptr_t remote_buffer = driver::alloc( sizeof( buffer ) );

	driver::write_raw( remote_buffer, buffer, sizeof( buffer ) );

	hook::g_universal_buffer = remote_buffer;

	return true;
}

uintptr_t create_individual_buffer( uintptr_t original, uint32_t id ) {
	uint8_t buffer[ ] = {
		0x51,								// push rcx
		0x52,								// push rdx
		0x41, 0x50,							// push r8
		0x41, 0x51,							// push r9
		0xB9, 0xDD, 0xCC, 0xBB, 0xAA,		// mov ecx, ... (syscall hash)
		0xFF, 0x15, 0x0C, 0x00, 0x00, 0x00,	// call qword  [.unibuf] (universal buffer)
		0x41, 0x59,							// pop r9
		0x41, 0x58,							// pop r8
		0x5A,								// pop rdx
		0x59,								// pop rcx
		0xFF, 0x25, 0x08, 0x00, 0x00, 0x00, // jmp qword [.orig] (original import)
		// .unibuf:
		0, 0, 0, 0, 0, 0, 0, 0,
		// .orig:
		0, 0, 0, 0, 0, 0, 0, 0
	};

	*std::bit_cast< uint32_t * >( buffer + 7 ) = id;
	*std::bit_cast< uintptr_t * >( buffer + 29 ) = hook::g_universal_buffer;
	*std::bit_cast< uintptr_t * >( buffer + 37 ) = original;

	size_t remote_buffer = driver::alloc( sizeof( buffer ) );

	driver::write_raw( remote_buffer, buffer, sizeof( buffer ) );

	return remote_buffer;
}

bool hook_module( uint8_t *module_buffer, IMAGE_IMPORT_DESCRIPTOR *descriptor, uintptr_t actual_base ) {
	auto *name = std::bit_cast< char * >( module_buffer + descriptor->Name );
	std::println( "(*) Hooking {}", name );

	auto *func = std::bit_cast< IMAGE_THUNK_DATA * >( module_buffer + descriptor->FirstThunk );
	auto *og_func = std::bit_cast< IMAGE_THUNK_DATA * >( module_buffer + descriptor->OriginalFirstThunk );

	for ( ; og_func->u1.AddressOfData != 0; func++, og_func++ ) {
		if ( IMAGE_SNAP_BY_ORDINAL( og_func->u1.Ordinal ) ) {
			std::println( "(!) Ordinal {}!{}", name, og_func->u1.Ordinal & ( ~IMAGE_ORDINAL_FLAG ) );
			continue;
		}

		auto *import_name = std::bit_cast< IMAGE_IMPORT_BY_NAME * >( module_buffer + og_func->u1.AddressOfData );
		std::println( "(*) {}!{}", name, import_name->Name );

		uintptr_t offset = std::bit_cast< uintptr_t >( func ) - std::bit_cast< uintptr_t >( module_buffer );
		uintptr_t actual_func = actual_base + offset;

		auto original = driver::read< uintptr_t >( actual_func );
		uint32_t fnv_hash = fnv::hash( import_name->Name );
		uintptr_t individual_buffer = create_individual_buffer( original, fnv_hash );

		hook::g_names[ fnv_hash ] = import_name->Name;

		uint32_t old_prot = driver::protect( actual_func, sizeof( uintptr_t ), PAGE_READWRITE );
		driver::write( actual_func, individual_buffer );
		driver::protect( actual_func, sizeof( uintptr_t ), old_prot );
	}
	
	return true;
}

bool hook::hook_iat( std::string_view process_name, std::string_view module_name ) {
	uint64_t pid = finder::find_pid( process_name );
	assert( pid != 0 );

	std::println( "(*) Found PID {}", pid );
	assert( driver::init( pid ) );

	assert( create_universal_buffer( ipc::create_target_pipe( ) ) );

	finder::mod mod = finder::find_module( pid, module_name );
	assert( mod.invalid( ) == false );

	std::println( "(*) Found target module at {:X} (size {:X})", mod.base, mod.size );

	auto *module_buffer = static_cast< uint8_t * >( malloc( mod.size ) );
	assert( module_buffer != nullptr );

	assert( driver::read_raw( mod.base, module_buffer, mod.size ) );

	auto *dos_header = std::bit_cast< IMAGE_DOS_HEADER * >( module_buffer );
	assert( dos_header->e_magic == IMAGE_DOS_SIGNATURE );

	auto *nt_headers = std::bit_cast< IMAGE_NT_HEADERS * >( module_buffer + dos_header->e_lfanew );
	assert( nt_headers->Signature == IMAGE_NT_SIGNATURE );

	// todo: size of optional header might not include some data directories
	IMAGE_DATA_DIRECTORY import_dir = nt_headers->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_IMPORT ];
	assert( import_dir.Size != 0 );

	size_t n_descriptors = import_dir.Size / sizeof( IMAGE_IMPORT_DESCRIPTOR );
	auto *descriptors = std::bit_cast< IMAGE_IMPORT_DESCRIPTOR * >( module_buffer + import_dir.VirtualAddress );

	for ( size_t i = 0; i < n_descriptors; i++ ) {
		IMAGE_IMPORT_DESCRIPTOR *descriptor = &descriptors[ i ];

		if ( descriptor->Name == 0 ) {
			break;
		}

		assert( hook_module( module_buffer, descriptor, mod.base ) );
	}

	return true;
}
