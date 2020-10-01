//#include <ntddk.h>
#include <ntifs.h>

DRIVER_INITIALIZE FxDriverEntry;
#pragma alloc_text(INIT, FxDriverEntry)

#define IOCTL_COOKIE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0301, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IOCTL_GET_PROC CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0302, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IOCTL_GET_MODULE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0303, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IOCTL_GET_SIZE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0304, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IOCTL_CALLBACK CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0305, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IOCTL_RPM CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0306, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IOCTL_WPM CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0307, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IOCTL_ALLOC CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0308, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IOCTL_DEALLOC CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0309, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IOCTL_CREATE_THREAD CTL_CODE(FILE_DEVICE_UNKNOWN, 0x030A, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IOCTL_FIND_MODULE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x030B, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
//#define IOCTL_UNLOAD CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0308, METHOD_NEITHER, FILE_SPECIAL_ACCESS)

PDEVICE_OBJECT DeviceObject = { 0 };
PDRIVER_OBJECT DriverObject = { 0 };
UNICODE_STRING DriverName, DeviceName, DosName, ProcessName;

HANDLE ProcessId;
PVOID ImageBase;
SIZE_T ImageSize;

typedef struct _KERNEL_MEMORY_REQUEST
{
	HANDLE ProcessId;
	PVOID Address;
	PVOID Value;
	ULONG Size;
} KERNEL_MEMORY_REQUEST, *PKERNEL_MEMORY_REQUEST;
typedef struct _KERNEL_HOOK_REQUEST
{
	BOOLEAN Load;
	UNICODE_STRING ProcessName;
	HANDLE ProcessId;
	PVOID Value;
} KERNEL_HOOK_REQUEST, *PKERNEL_HOOK_REQUEST;

NTSTATUS NTAPI MmCopyVirtualMemory(PEPROCESS SourceProcess, PVOID SourceAddress, PEPROCESS TargetProcess, PVOID TargetAddress, SIZE_T BufferSize, KPROCESSOR_MODE PreviousMode, PSIZE_T ReturnSize);
//NTSYSAPI NTSTATUS NTAPI RtlCreateUserThread(IN HANDLE ProcessHandle, IN PSECURITY_DESCRIPTOR SecurityDescriptor OPTIONAL, IN BOOLEAN CreateSuspended, IN ULONG StackZeroBits, IN OUT PULONG StackReserved, IN OUT PULONG StackCommit, IN PVOID StartAddress, IN PVOID StartParameter OPTIONAL, OUT PHANDLE ThreadHandle, OUT PCLIENT_ID ClientID);
NTSYSCALLAPI NTSTATUS NtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);
NTKERNELAPI PPEB NTAPI PsGetProcessPeb(IN PEPROCESS Process);
NTSTATUS ZwAllocateVirtualMemory(_In_ HANDLE ProcessHandle, _Inout_ PVOID* BaseAddress, _In_ ULONG_PTR ZeroBits, _Inout_ PSIZE_T RegionSize, _In_ ULONG AllocationType, _In_ ULONG Protect );
NTSYSAPI NTSTATUS NTAPI ZwProtectVirtualMemory(IN HANDLE ProcessHandle, IN OUT PVOID* BaseAddress, IN OUT PULONG NumberOfBytesToProtect, IN ULONG NewAccessProtection, OUT PULONG OldAccessProtection);
//NTSTATUS NtProtectVirtualMemory(IN HANDLE ProcessHandle, IN OUT PVOID* BaseAddress, IN OUT PULONG RegionSize, IN  ULONG NewProtect, OUT PULONG OldProtec);
//NTSTATUS UnloadDriver(PDRIVER_OBJECT pDriverObject);

//void RemoveLoadCallback();
BOOLEAN CallbackAttached = FALSE;
void ImageLoadCallback(PUNICODE_STRING FullImageName, HANDLE ProcId, PIMAGE_INFO ImageInfo)
{
	if (FullImageName->Length < ProcessName.Length)
		return;
	UNICODE_STRING subString;
	RtlCreateUnicodeString(&subString, FullImageName->Buffer + FullImageName->Length / 2 - ProcessName.Length / 2);
	if (RtlEqualUnicodeString(&subString, &ProcessName, TRUE))
	{
		DbgPrintEx(0, 0, "matched: %wZ \n", FullImageName);
		ImageBase = ImageInfo->ImageBase;
		ImageSize = ImageInfo->ImageSize;
		ProcessId = ProcId;
	}
}
/*
void RemoveLoadCallback()
{
	LARGE_INTEGER i;// { 1000 };
	i.QuadPart = 1000;
	KeDelayExecutionThread(KernelMode, FALSE, &i);
	PsRemoveLoadImageNotifyRoutine((PLOAD_IMAGE_NOTIFY_ROUTINE)ImageLoadCallback);
	CallbackAttached = FALSE;
}*/
typedef struct _MEMORY_ENTRY
{
	PVOID pBuffer;
} MEMORY_ENTRY, * PMEMORY_ENTRY;
typedef struct _PEB_LDR_DATA
{
	ULONG Length;
	UCHAR Initialized;
	PVOID SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;
typedef struct _PEB
{
	UCHAR InheritedAddressSpace;
	UCHAR ReadImageFileExecOptions;
	UCHAR BeingDebugged;
	UCHAR BitField;
	PVOID Mutant;
	PVOID ImageBaseAddress;
	PPEB_LDR_DATA Ldr;
	PVOID ProcessParameters;
	PVOID SubSystemData;
	PVOID ProcessHeap;
	PVOID FastPebLock;
	PVOID AtlThunkSListPtr;
	PVOID IFEOKey;
	PVOID CrossProcessFlags;
	PVOID KernelCallbackTable;
	ULONG SystemReserved;
	ULONG AtlThunkSListPtr32;
	PVOID ApiSetMap;
} PEB, * PPEB;
typedef struct _LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	LIST_ENTRY HashLinks;
	ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;
NTSTATUS IoCtlCallback(PDEVICE_OBJECT a, PIRP Irp)
{
	UNREFERENCED_PARAMETER(a);
	NTSTATUS Status = STATUS_SUCCESS;
	
	ULONG BytesIO = 0;
	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
	auto ControlCode = stack->Parameters.DeviceIoControl.IoControlCode;

	if (ControlCode == IOCTL_COOKIE)
	{
		//DbgPrintEx(0, 0, "%wZ cookie\n", &drv);
		PUINT64 Request = (PUINT64)Irp->AssociatedIrp.SystemBuffer;
		*Request = 0x80085;
		BytesIO = sizeof(*Request);
	}
	else if (ControlCode == IOCTL_CALLBACK)
	{
		PKERNEL_HOOK_REQUEST Request = (PKERNEL_HOOK_REQUEST)Irp->AssociatedIrp.SystemBuffer;
		RtlCreateUnicodeString(&ProcessName, Request->ProcessName.Buffer);
		//DbgPrintEx(0, 0, "%wZ callback %wZ\n", &drv, &ProcessName);
		if (Request->Load && !CallbackAttached)
		{
			ImageBase = ProcessId = 0;
			PsSetLoadImageNotifyRoutine((PLOAD_IMAGE_NOTIFY_ROUTINE)ImageLoadCallback);
			CallbackAttached = TRUE;
		}
		else if (!Request->Load && CallbackAttached)
		{
			PsRemoveLoadImageNotifyRoutine((PLOAD_IMAGE_NOTIFY_ROUTINE)ImageLoadCallback);
			CallbackAttached = FALSE;
		}
		Request->Load = CallbackAttached;
		BytesIO = sizeof(Request->Load);
	}
	else if (ControlCode == IOCTL_ALLOC)
	{
		PAGED_CODE();
		PKERNEL_MEMORY_REQUEST Request = (PKERNEL_MEMORY_REQUEST)Irp->AssociatedIrp.SystemBuffer;
		DbgPrintEx(0, 0, "%wZ alloc memory %x\n", &DriverName, Request->Size);
		//Request->Size = 4 * 1024;
		PEPROCESS Process;
		if (NT_SUCCESS(PsLookupProcessByProcessId(Request->ProcessId, &Process))) {
			PRKAPC_STATE apc = NULL;
			KeStackAttachProcess(Process, &apc);
			//PVOID AllocMem = ExAllocatePoolWithTag(NonPagedPool, Request->Size, '1gaT');
			//PMDL AllocMdl = IoAllocateMdl(AllocMem, Request->Size, FALSE, FALSE, NULL);
			//MmProtectMdlSystemAddress(AllocMdl, PAGE_EXECUTE_READWRITE);
			//MmBuildMdlForNonPagedPool(AllocMdl);
			//MmProbeAndLockPages(AllocMdl, UserMode, IoWriteAccess);
			//PVOID AllocAddr = MmMapLockedPagesSpecifyCache(AllocMdl, UserMode, MmNonCached, NULL, FALSE, NormalPagePriority);
			//MmSecureVirtualMemory(AllocAddr, Request->Size, PAGE_EXECUTE_READWRITE);
			PVOID AllocAddr = NULL;
			ZwAllocateVirtualMemory(ZwCurrentProcess(), &AllocAddr, 0, &Request->Size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
			//ZwAllocateVirtualMemory(ZwCurrentProcess(), (PVOID*)&baseAddress, 0, &regionSize, allocationFlags, protectionFlags);
			//MmProtectMdlSystemAddress(AllocMdl, PAGE_EXECUTE_READWRITE);
			//ULONG OldProtect; ZwProtectVirtualMemory(ZwCurrentProcess(), &AllocAddr, &Request->Size, PAGE_EXECUTE_READWRITE, &OldProtect);
			KeUnstackDetachProcess(&apc);
			/*PVOID mod;
			OBJECT_ATTRIBUTES oa;
			oa.Length = sizeof(oa);
			oa.RootDirectory = 0;
			oa.ObjectName = 0;
			oa.Attributes = 0;
			oa.SecurityDescriptor = 0;
			oa.SecurityQualityOfService = 0;

			CLIENT_ID ClientId;
			ClientId.UniqueProcess = (HANDLE)Process-;
			ClientId.UniqueThread = 0;
			//ZwOpenProcess(&mod, PROCESS_ALL_ACCESS, &oa, &ClientId);
			//ZwClose(mod);*/
			//PVOID data[] = { AllocAddr, AllocMdl, AllocMem };
			PVOID data[] = { AllocAddr, Request->Size, 0 };
			RtlCopyMemory(Request->Value, &data, 24);
		}
		BytesIO = sizeof(KERNEL_MEMORY_REQUEST);
	}
	else if (ControlCode == IOCTL_DEALLOC)
	{
		PAGED_CODE();
		PKERNEL_MEMORY_REQUEST Request = (PKERNEL_MEMORY_REQUEST)Irp->AssociatedIrp.SystemBuffer;
		DbgPrintEx(0, 0, "%wZ dealloc memory\n", &DriverName);
		PEPROCESS Process;
		if (NT_SUCCESS(PsLookupProcessByProcessId(Request->ProcessId, &Process))) {
			PRKAPC_STATE apc = NULL;
			PVOID data[] = { NULL, NULL, NULL };
			RtlCopyMemory(&data, Request->Value, 24);
			PVOID AllocAddr = data[0];
			PMDL AllocMdl = data[1];
			PVOID AllocMem = data[2];

			KeStackAttachProcess(Process, &apc);
			ZwFreeVirtualMemory(ZwCurrentProcess(), &AllocAddr, &AllocMdl, MEM_DECOMMIT);
			//MmUnmapLockedPages(AllocAddr, AllocMdl);
			//MmUnlockPages(AllocMdl);
			//IoFreeMdl(AllocMdl);
			//ExFreePoolWithTag(AllocMem, '1gaT');
			KeUnstackDetachProcess(&apc);
		}
		BytesIO = sizeof(KERNEL_MEMORY_REQUEST);
	}
	else if (ControlCode == IOCTL_RPM || ControlCode == IOCTL_WPM)
	{
		DbgPrintEx(0, 0, "%wZ read/write memory\n", &DriverName);
		PKERNEL_MEMORY_REQUEST Request = (PKERNEL_MEMORY_REQUEST)Irp->AssociatedIrp.SystemBuffer;
		PEPROCESS Process;
		if (NT_SUCCESS(PsLookupProcessByProcessId(Request->ProcessId, &Process))) {
			PSIZE_T Bytes;
			if (ControlCode == IOCTL_RPM)
				MmCopyVirtualMemory(Process, Request->Address, PsGetCurrentProcess(), Request->Value, Request->Size, KernelMode, (PSIZE_T)&Bytes);
			else
				MmCopyVirtualMemory(PsGetCurrentProcess(), Request->Value, Process, Request->Address, Request->Size, KernelMode, (PSIZE_T)&Bytes);
		}
		BytesIO = sizeof(KERNEL_MEMORY_REQUEST);
	}
	else if (ControlCode == IOCTL_CREATE_THREAD)
	{
		DbgPrintEx(0, 0, "%wZ create thread\n", &DriverName);
		PKERNEL_MEMORY_REQUEST Request = (PKERNEL_MEMORY_REQUEST)Irp->AssociatedIrp.SystemBuffer;
		PEPROCESS Process;
		if (NT_SUCCESS(PsLookupProcessByProcessId(Request->ProcessId, &Process))) {
			HANDLE targetThreadHandle;
			CLIENT_ID cid;
			PRKAPC_STATE apc = NULL;
			KeStackAttachProcess(Process, &apc);
			//RtlCreateUserThread(Process, NULL, FALSE, 0, 0, 0, Request->Address, Request->Value, &targetThreadHandle, &cid);
			KeUnstackDetachProcess(&apc);
		}
		BytesIO = sizeof(KERNEL_MEMORY_REQUEST);
	}
	else if (ControlCode == IOCTL_GET_PROC || ControlCode == IOCTL_GET_MODULE || ControlCode == IOCTL_GET_SIZE)
	{
		//DbgPrintEx(0, 0, "%wZ get process or module\n", &drv);
		PUINT64 Request = (PUINT64)Irp->AssociatedIrp.SystemBuffer;
		*Request = ControlCode == IOCTL_GET_PROC ? (UINT64)ProcessId : IOCTL_GET_MODULE ? (UINT64)ImageBase : (UINT64)ImageSize;
		BytesIO = sizeof(*Request);
	}
	else if (ControlCode == IOCTL_FIND_MODULE)
	{
		DbgPrintEx(0, 0, "%wZ find module\n", &DriverName);
		PKERNEL_HOOK_REQUEST Request = (PKERNEL_HOOK_REQUEST)Irp->AssociatedIrp.SystemBuffer;
		PVOID dllBase = NULL;
		RtlCopyMemory(Request->Value, &dllBase, 8);
		RtlCreateUnicodeString(&ProcessName, Request->ProcessName.Buffer);
		PEPROCESS Process;
		if (NT_SUCCESS(PsLookupProcessByProcessId(Request->ProcessId, &Process))) {
			PPEB pPeb = PsGetProcessPeb(Process);
			KAPC_STATE state;
			KeStackAttachProcess(Process, &state);
			for (PLIST_ENTRY pListEntry = pPeb->Ldr->InMemoryOrderModuleList.Flink; pListEntry != &pPeb->Ldr->InMemoryOrderModuleList; pListEntry = pListEntry->Flink)
			{
				PLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
				if (RtlEqualUnicodeString(&pEntry->BaseDllName, &ProcessName, TRUE))
					dllBase = pEntry->DllBase;
			}
			KeUnstackDetachProcess(&state);
			RtlCopyMemory(Request->Value, &dllBase, 8);
		}
		BytesIO = sizeof(*Request);
	}
	/*else if (ControlCode == IOCTL_UNLOAD)
	{
		DbgPrintEx(0, 0, "%wZ unload\n", &driver);
		ZwUnloadDriver(&driver);
	}*/
	else
	{
		Status = STATUS_INVALID_PARAMETER;
		BytesIO = 0;
	}
	Irp->IoStatus.Status = Status;
	Irp->IoStatus.Information = BytesIO;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return Status;
}
NTSTATUS CreateOrCloseCall(PDEVICE_OBJECT pDeviceObject, PIRP irp)
{
	UNREFERENCED_PARAMETER(pDeviceObject);
	irp->IoStatus.Status = STATUS_SUCCESS;
	irp->IoStatus.Information = 0;
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}
/*NTSTATUS UnloadDriver(PDRIVER_OBJECT pDriverObject)
{
	if (CallbackAttached) PsRemoveLoadImageNotifyRoutine((PLOAD_IMAGE_NOTIFY_ROUTINE)ImageLoadCallback);
	IoDeleteSymbolicLink(&sym);
	IoDeleteDevice(pDriverObject->DeviceObject);
	return STATUS_SUCCESS;
}*/
NTKERNELAPI NTSTATUS IoCreateDriver(IN PUNICODE_STRING DriverName, OPTIONAL IN PDRIVER_INITIALIZE InitializationFunction);
NTSTATUS DriverInitialize(_In_ PDRIVER_OBJECT pDriverObject, _In_ PUNICODE_STRING pRegistryPath)
{
	UNREFERENCED_PARAMETER(pRegistryPath);
	IoCreateDevice(pDriverObject, 0, &DeviceName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &DeviceObject);
	IoCreateSymbolicLink(&DosName, &DeviceName);
	DriverObject = pDriverObject;
	DriverObject->MajorFunction[IRP_MJ_CREATE] = DriverObject->MajorFunction[IRP_MJ_CLOSE] = CreateOrCloseCall;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IoCtlCallback;
	DeviceObject->Flags |= DO_BUFFERED_IO;
	DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

	return STATUS_SUCCESS;
}
NTSTATUS FxDriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath)
{
	UNREFERENCED_PARAMETER(pDriverObject);
	UNREFERENCED_PARAMETER(pRegistryPath);
	RtlInitUnicodeString(&DriverName, L"\\Driver\\shalz");
	RtlInitUnicodeString(&DeviceName, L"\\Device\\shalz");
	RtlInitUnicodeString(&DosName, L"\\DosDevices\\shalz");

	auto status = IoCreateDriver(&DriverName, &DriverInitialize);
	DbgPrintEx(0, 0, "%wZ status : %lx\n", &DriverName, status);
	return STATUS_SUCCESS;
}
