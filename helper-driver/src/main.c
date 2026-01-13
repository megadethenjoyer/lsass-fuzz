#include <ntifs.h>

#define HELPER_READ  CTL_CODE( FILE_DEVICE_UNKNOWN, 1, METHOD_BUFFERED, FILE_ANY_ACCESS )
#define HELPER_WRITE CTL_CODE( FILE_DEVICE_UNKNOWN, 2, METHOD_BUFFERED, FILE_ANY_ACCESS )
#define HELPER_GET_PEB CTL_CODE( FILE_DEVICE_UNKNOWN, 3, METHOD_BUFFERED, FILE_ANY_ACCESS )
#define HELPER_ALLOCATE CTL_CODE( FILE_DEVICE_UNKNOWN, 4, METHOD_BUFFERED, FILE_ANY_ACCESS )
#define HELPER_DUPLICATE CTL_CODE( FILE_DEVICE_UNKNOWN, 5, METHOD_BUFFERED, FILE_ANY_ACCESS )
#define HELPER_PROTECT CTL_CODE( FILE_DEVICE_UNKNOWN, 6, METHOD_BUFFERED, FILE_ANY_ACCESS )

#pragma pack( push, 1 )
struct helper_data {
	HANDLE process_id;
	size_t data_size;
	void *remote_addr;
	void *local_addr;
};
#pragma pack( pop )

#define PROCESS_VM_OPERATION      0x008
#define PROCESS_QUERY_INFORMATION 0x400
typedef UINT32 uint32_t;

#define H_CURRENT_PROCESS ( ( HANDLE )( 0xFFFF'FFFF'FFFF'FFFFull ) )

#define DEVICE_NAME RTL_CONSTANT_STRING( L"\\Device\\LsassFuzzHelper" )
#define DOS_NAME RTL_CONSTANT_STRING( L"\\DosDevices\\LsassFuzzHelper" )

NTKERNELAPI NTSTATUS MmCopyVirtualMemory(
	PEPROCESS source_proc, void *source_addr,
	PEPROCESS target_proc, void *target_addr,
	size_t buf_size, KPROCESSOR_MODE prev_mode, size_t *ret_size );

NTKERNELAPI NTSTATUS ZwQueryInformationProcess(
	_In_ HANDLE handle,
	_In_ PROCESSINFOCLASS info_class,
	_Out_ void *proc_info,
	_In_ uint32_t proc_info_size,
	_Out_opt_ uint32_t *ret_size
);

NTKERNELAPI NTSTATUS ZwDuplicateObject(
	_In_ HANDLE SourceProcessHandle,
	_In_ HANDLE SourceHandle,
	_In_opt_ HANDLE TargetProcessHandle,
	_Out_opt_ PHANDLE TargetHandle,
	_In_ ACCESS_MASK DesiredAccess,
	_In_ ULONG HandleAttributes,
	_In_ ULONG Options
);

NTKERNELAPI NTSTATUS ZwProtectVirtualMemory(
	_In_ HANDLE ProcessHandle,
	_Inout_ PVOID *BaseAddress,
	_Inout_ PSIZE_T RegionSize,
	_In_ ULONG NewProtection,
	_Out_ PULONG OldProtection
);


NTKERNELAPI NTSTATUS ZwOpenProcess(
	PHANDLE            ProcessHandle,
	ACCESS_MASK        DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PCLIENT_ID         ClientId
);

NTSTATUS irp_create_close( _In_ DEVICE_OBJECT *device, _Inout_ IRP *irp ) {
	UNREFERENCED_PARAMETER( device );

	IoCompleteRequest( irp, IO_NO_INCREMENT );
	irp->IoStatus.Status = STATUS_SUCCESS;
	return irp->IoStatus.Status;
}

NTSTATUS ioctl( uint32_t ctl_code, void *sys_buf, uint32_t buf_len ) {
	if ( buf_len != sizeof( struct helper_data ) ) {
		//DbgPrintEx( 0, 0, "lsass-fuzz-helper: invalid buf size\n" );
		return STATUS_INVALID_PARAMETER;
	}

	struct helper_data *data = sys_buf;

	PEPROCESS process = NULL;
	NTSTATUS lookup_status = PsLookupProcessByProcessId( data->process_id, &process );
	if ( NT_SUCCESS( lookup_status ) == FALSE ) {
		//DbgPrintEx( 0, 0, "lsass-fuzz-helper: lookup %d failed\n", ( uint32_t )( ( UINT64 )data->process_id ) );
		return lookup_status;
	}
	HANDLE h_proc = { 0 };
	OBJECT_ATTRIBUTES oa = { 0 };
	oa.Length = sizeof( oa );
	CLIENT_ID cid = { 0 };
	cid.UniqueProcess = data->process_id;

	NTSTATUS open_status = ZwOpenProcess( &h_proc, PROCESS_ALL_ACCESS, &oa, &cid );
	if ( NT_SUCCESS( open_status ) == FALSE ) {
		//DbgPrintEx( 0, 0, "lsass-fuzz-helper: failed to open handle %x\n", ( UINT32 )( open_status ) );
		return open_status;
	}

	size_t ret_size = 0;

	NTSTATUS status = STATUS_INVALID_PARAMETER;

	switch ( ctl_code ) {
	case HELPER_READ: {
		//DbgPrintEx( 0, 0, "lsass-fuzz-helper: read [0x%p]\n", data->remote_addr );
		status = MmCopyVirtualMemory( process, data->remote_addr, PsGetCurrentProcess( ), data->local_addr, data->data_size, KernelMode, &ret_size );
		break;
	}

	case HELPER_WRITE: {
		//DbgPrintEx( 0, 0, "lsass-fuzz-helper: write [0x%p]\n", data->remote_addr );
		status = MmCopyVirtualMemory( PsGetCurrentProcess( ), data->local_addr, process, data->remote_addr, data->data_size, KernelMode, &ret_size );
		break;
	}

	case HELPER_GET_PEB: {
		//DbgPrintEx( 0, 0, "lsass-fuzz-helper: get peb for %lld\n", ( UINT64 )( data->process_id ) );

		PROCESS_BASIC_INFORMATION basic_info = { 0 };
		NTSTATUS query_status = ZwQueryInformationProcess( h_proc, ProcessBasicInformation, &basic_info, sizeof( basic_info ), NULL );
		if ( NT_SUCCESS( query_status ) == FALSE ) {
			//DbgPrintEx( 0, 0, "lsass-fuzz-helper: failed to query info %x\n", ( UINT32 )( query_status ) );
			return query_status;
		}

		//DbgPrintEx( 0, 0, "lsass-fuzz-helper: got PEB base %p\n", basic_info.PebBaseAddress );
		memcpy( data->local_addr, &basic_info.PebBaseAddress, sizeof( basic_info.PebBaseAddress ) );

		status = STATUS_SUCCESS;
		break;
	}

	case HELPER_ALLOCATE: {
		//DbgPrintEx( 0, 0, "lsass-fuzz-helper: allocate %lld for %lld\n", data->data_size, ( UINT64 )( data->process_id ) );
		void *allocated_base = NULL;
		size_t size = data->data_size;
		NTSTATUS alloc_status = ZwAllocateVirtualMemory( h_proc, &allocated_base, 0, &size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE );
		if ( NT_SUCCESS( alloc_status ) == FALSE ) {
			//DbgPrintEx( 0, 0, "lsass-fuzz-helper: failed to allocate %x\n", ( UINT32 )( alloc_status ) );
			return alloc_status;
		}

		//DbgPrintEx( 0, 0, "lsass-fuzz-helper: got alloc base %p\n", allocated_base );
		memcpy( data->local_addr, &allocated_base, sizeof( allocated_base ) );

		status = STATUS_SUCCESS;
		break;
	}

	case HELPER_DUPLICATE: {

		HANDLE h_target = { 0 };
		NTSTATUS dup_status = ZwDuplicateObject( H_CURRENT_PROCESS, data->remote_addr, h_proc, &h_target, GENERIC_READ | GENERIC_WRITE, 0, 0 );
		if ( NT_SUCCESS( dup_status ) == FALSE ) {
			//DbgPrintEx( 0, 0, "lsass-fuzz-helper: failed to duplicate %x\n", ( UINT32 )( dup_status ) );
			return dup_status;
		}

		memcpy( data->local_addr, &h_target, sizeof( h_target ) );

		status = STATUS_SUCCESS;
		break;
	}
	case HELPER_PROTECT: {
		void *target_addr = ( void * )( data->remote_addr );
		size_t size = data->data_size;

		uintptr_t *protect_info = data->local_addr;
		uint32_t new_protect = ( uint32_t )( protect_info[ 0 ] );
		ULONG *old_protect = ( ULONG * )( protect_info[ 1 ] );

		NTSTATUS protect_status = ZwProtectVirtualMemory( h_proc, &target_addr, &size, new_protect, old_protect );
		if ( NT_SUCCESS( protect_status ) == FALSE ) {
			//DbgPrintEx( 0, 0, "lsass-fuzz-helper: failed to protect %x\n", ( UINT32 )( protect_status ) );
			return protect_status;
		}

		status = STATUS_SUCCESS;
	}

	default: {
		//DbgPrintEx( 0, 0, "lsass-fuzz-helper: invalid ctl_code\n" );
		break;
	}
	}

	ZwClose( h_proc );

	return status;
}


NTSTATUS irp_ioctl( _In_ DEVICE_OBJECT *device, _Inout_ IRP *irp ) {
	UNREFERENCED_PARAMETER( device );

	IO_STACK_LOCATION *stack = IoGetCurrentIrpStackLocation( irp );
	uint32_t ctl_code = stack->Parameters.DeviceIoControl.IoControlCode;
	void *sys_buf = irp->AssociatedIrp.SystemBuffer;
	uint32_t buf_len = stack->Parameters.DeviceIoControl.InputBufferLength;

	NTSTATUS status = ioctl( ctl_code, sys_buf, buf_len );

	IoCompleteRequest( irp, IO_NO_INCREMENT );
	irp->IoStatus.Status = status;
	return irp->IoStatus.Status;
}

void DriverUnload( _In_ DRIVER_OBJECT *driver ) {
	UNREFERENCED_PARAMETER( driver );

	//DbgPrintEx( 0, 0, "lsass-fuzz-helper: driver unloading\n" );

	UNICODE_STRING dos_name = DOS_NAME;
	IoDeleteSymbolicLink( &dos_name );

	IoDeleteDevice( driver->DeviceObject );
}

NTSTATUS DriverEntry( _In_ DRIVER_OBJECT *driver, _In_ UNICODE_STRING *registry_path ) {
	UNREFERENCED_PARAMETER( registry_path );

	driver->DriverUnload = DriverUnload;

	DEVICE_OBJECT *device = { 0 };

	UNICODE_STRING device_name = DEVICE_NAME;
	NTSTATUS device_status = IoCreateDevice(
		driver,
		0,
		&device_name,
		FILE_DEVICE_UNKNOWN,
		0,
		FALSE,
		&device
	);
	if ( NT_SUCCESS( device_status ) == FALSE ) {
		return device_status;
	}

	UNICODE_STRING dos_device_name = DOS_NAME;
	NTSTATUS symlink_status = IoCreateSymbolicLink( &dos_device_name, &device_name );
	if ( NT_SUCCESS( symlink_status ) == FALSE ) {
		return symlink_status;
	}

	driver->MajorFunction[ IRP_MJ_CREATE ] = irp_create_close;
	driver->MajorFunction[ IRP_MJ_DEVICE_CONTROL ] = irp_ioctl;

	//DbgPrintEx( 0, 0, "lsass-fuzz-helper: driver device set up\n" );

	return STATUS_SUCCESS;
}