#include "shared_mem.h"

#define ABSOLUTE(wait) (wait)

#define RELATIVE(wait) (-(wait))

#define NANOSECONDS(nanos) \
(((signed __int64)(nanos)) / 100L)

#define MICROSECONDS(micros) \
(((signed __int64)(micros)) * NANOSECONDS(1000L))

#define MILLISECONDS(milli) \
(((signed __int64)(milli)) * MICROSECONDS(1000L))

#define SECONDS(seconds) \
(((signed __int64)(seconds)) * MILLISECONDS(1000L))

const WCHAR shared_memory_name[] = L"\\BaseNamedObjects\\SharedMem";

PVOID	pSharedSection = NULL;
PVOID	pSectionObj = NULL;
HANDLE	hSection = NULL;

HANDLE sectionHandle;
PVOID	SharedSection = NULL;
PVOID	Sharedoutputvar = NULL;

SECURITY_DESCRIPTOR security_desc;
ULONG DaclLength;
PACL Dacl;

// data arrived
HANDLE  SharedEventHandle_dt = NULL;
PKEVENT SharedEvent_dt = NULL;
UNICODE_STRING EventName_dt;

// trigger loop
HANDLE  SharedEventHandle_trigger = NULL;
PKEVENT SharedEvent_trigger = NULL;
UNICODE_STRING EventName_trigger;

// ReadyRead
HANDLE  SharedEventHandle_ReadyRead = NULL;
PKEVENT SharedEvent_ReadyRead = NULL;
UNICODE_STRING EventName_ReadyRead;

NTSTATUS create_shared_memory()
{
	NTSTATUS status = STATUS_SUCCESS;
	DbgPrintEx(0, 0, "Calling create shared memory at %p.\n", create_shared_memory);

	status = RtlCreateSecurityDescriptor(&security_desc, SECURITY_DESCRIPTOR_REVISION);

	if (!NT_SUCCESS(status)) {
		DbgPrintEx(0, 0, "RtlCreateSecurityDescriptor failed : %p\n", status);
		return status;
	}

	//sets size of pool
	DaclLength = sizeof(ACL) + sizeof(ACCESS_ALLOWED_ACE) * 3 + RtlLengthSid(SeExports->SeLocalSystemSid) + RtlLengthSid(SeExports->SeAliasAdminsSid) +
		RtlLengthSid(SeExports->SeWorldSid);

	//allocates pool for shared_mem
	Dacl = ExAllocatePoolWithTag(PagedPool, DaclLength, 'lcaD');

	//check if failed. If failed no space in memory
	if (Dacl == NULL) {
		DbgPrintEx(0, 0, "ExAllocatePoolWithTag  failed  : %p\n", status);
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	status = RtlCreateAcl(Dacl, DaclLength, ACL_REVISION);

	if (!NT_SUCCESS(status)) {
		ExFreePool(Dacl);
		DbgPrintEx(0, 0, "RtlCreateAcl  failed  : %p\n", status);
		return status;
	}

	status = RtlAddAccessAllowedAce(Dacl, ACL_REVISION, FILE_ALL_ACCESS, SeExports->SeWorldSid);

	if (!NT_SUCCESS(status)) {
		ExFreePool(Dacl);
		DbgPrintEx(0, 0, "RtlAddAccessAllowedAce SeWorldSid failed  : %p\n", status);
		return status;
	}

	status = RtlAddAccessAllowedAce(Dacl,
		ACL_REVISION,
		FILE_ALL_ACCESS,
		SeExports->SeAliasAdminsSid);

	if (!NT_SUCCESS(status)) {
		ExFreePool(Dacl);
		DbgPrintEx(0, 0, "RtlAddAccessAllowedAce SeAliasAdminsSid failed  : %p\n", status);
		return status;
	}

	status = RtlAddAccessAllowedAce(Dacl,
		ACL_REVISION,
		FILE_ALL_ACCESS,
		SeExports->SeLocalSystemSid);

	if (!NT_SUCCESS(status)) {
		ExFreePool(Dacl);
		DbgPrintEx(0, 0, "RtlAddAccessAllowedAce SeLocalSystemSid failed  : %p\n", status);
		return status;
	}

	//DbgPrintEx(0, 0, "RtlAddAccessAllowedAce SeLocalSystemSid succeed  : %p\n", Status);

	status = RtlSetDaclSecurityDescriptor(&security_desc,
		TRUE,
		Dacl,
		FALSE);

	if (!NT_SUCCESS(status)) {
		ExFreePool(Dacl);
		DbgPrintEx(0, 0, "RtlSetDaclSecurityDescriptor failed  : %p\n", status);
		return status;
	}

	//DbgPrintEx(0, 0, "RtlSetDaclSecurityDescriptor  succeed  : %p\n", Status);

	OBJECT_ATTRIBUTES objAttr;
	UNICODE_STRING sectionName;
	RtlInitUnicodeString(&sectionName, shared_memory_name);
	InitializeObjectAttributes(&objAttr, &sectionName, OBJ_CASE_INSENSITIVE, NULL, &security_desc);

	if (!NT_SUCCESS(status)) {
		DbgPrintEx(0, 0, "last thing  has failed : %p\n", status);
	}

	//DbgPrintEx(0, 0, "last thing  was successfully created : %p\n", Status);

	//DbgPrintEx(0, 0, "Finished everything...\n");

	//DbgBreakPoint(); // dbg break point here..

	LARGE_INTEGER lMaxSize = { 0 };
	lMaxSize.HighPart = 0;
	lMaxSize.LowPart = 1024 * 10;
	status = ZwCreateSection(&sectionHandle, SECTION_ALL_ACCESS, &objAttr, &lMaxSize, PAGE_READWRITE, SEC_COMMIT, NULL); // Create section with section handle, object attributes, and the size of shared mem struct
	if (!NT_SUCCESS(status))
	{
		DbgPrintEx(0, 0, "ZwCreateSection failed: %p\n", status);
		return status;
	}

	DbgPrintEx(0,0,"ZwCreateSection was successfully created: %p\n", status);

	// my code starts from here xD
	SIZE_T ulViewSize = 1024 * 10;   // &sectionHandle before was here i guess i am correct 
	status = ZwMapViewOfSection(sectionHandle, NtCurrentProcess(), &SharedSection, 0, ulViewSize, NULL, &ulViewSize, ViewShare, 0, PAGE_READWRITE | PAGE_NOCACHE);
	if (!NT_SUCCESS(status)) {
		DbgPrintEx(0, 0, "ZwMapViewOfSection fail! Status: %p\n", status);
		ZwClose(sectionHandle);
		return status;
	}

	DbgPrintEx(0,0,"ZwMapViewOfSection was successfully created: %p\n", status);

	DbgPrintEx(0, 0, "CreateSharedMemory called finished \n");

	ExFreePool(Dacl); // moved this from line : 274 to here 313 its maybe why its causing the error (would be better if i put this in unload driver)

	return status;
}

VOID open_events() {

	RtlInitUnicodeString(&EventName_dt, L"\\BaseNamedObjects\\DataArrived");
	SharedEvent_dt = IoCreateNotificationEvent(&EventName_dt, &SharedEventHandle_dt);

	if (SharedEvent_dt == NULL) {
		DbgPrintEx(0, 0, "It didn't work lol ! \n");
	}

	RtlInitUnicodeString(&EventName_trigger, L"\\BaseNamedObjects\\trigger");
	SharedEvent_trigger = IoCreateNotificationEvent(&EventName_trigger, &SharedEventHandle_trigger);
	if (SharedEvent_trigger == NULL) {
		DbgPrintEx(0, 0, "It didn't work lol ! \n");
	}


	RtlInitUnicodeString(&EventName_ReadyRead, L"\\BaseNamedObjects\\ReadyRead");
	SharedEvent_ReadyRead = IoCreateNotificationEvent(&EventName_ReadyRead, &SharedEventHandle_ReadyRead);
	if (SharedEvent_ReadyRead == NULL) {
		DbgPrintEx(0, 0, "It didn't work lol ! \n");
	}

	DbgPrintEx(0, 0, "Open events done.\n");
}

VOID ReadSharedMemory()
{

	DbgPrintEx(0, 0, "Read shared memory called.\n");

	if (!sectionHandle)
	{
		DbgPrintEx(0, 0, "sectionHandle invalid data.\n");
		return;
	}

	if (SharedSection)
		ZwUnmapViewOfSection(NtCurrentProcess(), SharedSection);

	DbgPrintEx(0, 0, "Read shared memory ZwMapViewOfSection.\n");

	SIZE_T ulViewSize = 1024 * 10;
	NTSTATUS ntStatus = ZwMapViewOfSection(sectionHandle, NtCurrentProcess(), &SharedSection, 0, ulViewSize, NULL, &ulViewSize, ViewShare, 0, PAGE_READWRITE | PAGE_NOCACHE);
	if (!NT_SUCCESS(ntStatus))
	{
		DbgPrintEx(0, 0, "ZwMapViewOfSection fail! Status: %p.\n", ntStatus);
		ZwClose(sectionHandle);
	}

	if ((PCHAR)SharedSection = NULL)
	{
		DbgPrintEx(0, 0, "Shared mem NULL.\n");
		return;
	}

	DbgPrintEx(0, 0, "Shared memory read data: %s.\n", (PCHAR)SharedSection);
}

void NTAPI driver_loop(PVOID StartContext)
{
	while (1)
	{
		DbgPrintEx(0, 0, "Loop called.\n");

		DbgPrintEx(0, 0, "Reading shared memory.\n");

		ReadSharedMemory();
		
		DbgPrintEx(0, 0, "Finished reading shared memory.\n");
		DbgBreakPoint();

		if ((PCHAR)SharedSection = NULL)
		{
			DbgPrintEx(0, 0, "Shared mem NULL.\n");
			continue;
		}

		if (strcmp((PCHAR)SharedSection, "Stop") == 0) {
			DbgPrintEx(0, 0, "Breaking out of the loop\n");
			break;
		}
		
		DbgPrintEx(0, 0, "Finished comparing strings, Continuing loop...\n");

		//delay
		LARGE_INTEGER Timeout;
		Timeout.QuadPart = RELATIVE(SECONDS(1));
		KeDelayExecutionThread(KernelMode, FALSE, &Timeout);
	}
}
