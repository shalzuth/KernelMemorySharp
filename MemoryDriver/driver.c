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
} KERNEL_HOOK_REQUEST, *PKERNEL_HOOK_REQUEST;

NTSTATUS NTAPI MmCopyVirtualMemory(PEPROCESS SourceProcess, PVOID SourceAddress, PEPROCESS TargetProcess, PVOID TargetAddress, SIZE_T BufferSize, KPROCESSOR_MODE PreviousMode, PSIZE_T ReturnSize);

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
		//DbgPrintEx(0, 0, "matched: %wZ \n", FullImageName);
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
	else if (ControlCode == IOCTL_RPM || ControlCode == IOCTL_WPM)
	{
		//DbgPrintEx(0, 0, "%wZ read/write memory\n", &drv);
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
	else if (ControlCode == IOCTL_GET_PROC || ControlCode == IOCTL_GET_MODULE || ControlCode == IOCTL_GET_SIZE)
	{
		//DbgPrintEx(0, 0, "%wZ get process or module\n", &drv);
		PUINT64 Request = (PUINT64)Irp->AssociatedIrp.SystemBuffer;
		*Request = ControlCode == IOCTL_GET_PROC ? (UINT64)ProcessId : IOCTL_GET_MODULE ? (UINT64)ImageBase : (UINT64)ImageSize;
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
