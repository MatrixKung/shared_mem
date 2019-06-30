#include "stdafx.h"
#include "shared_mem.h"

NTSTATUS DriverEntry(PDRIVER_OBJECT  DriverObject, PUNICODE_STRING RegistryPath)
{
	DbgPrintEx(0, 0, "Driver entry called at %p.\n", DriverEntry);

	create_shared_memory();

	DbgPrintEx(0, 0, "Finished calling create_shared_memory.\n");

	open_events();

	DbgPrintEx(0, 0, "Open events completed.\n");

	HANDLE thread_handle = NULL;

	// Create server thread that will wait for incoming connections.
	NTSTATUS status = PsCreateSystemThread( &thread_handle, GENERIC_ALL, NULL, NULL, NULL, driver_loop, NULL);

	if (!NT_SUCCESS(status))
	{
		DbgPrintEx(0, 0, "Failed to create server thread. Status code: %X.", status);
		return STATUS_UNSUCCESSFUL;
	}

	ZwClose(thread_handle);

	DbgPrintEx(0, 0, "Driver entry completed.\n");

	return STATUS_SUCCESS;
}
