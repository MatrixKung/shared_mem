#pragma once

#include "stdafx.h"

// read struct
typedef struct _KM_READ_REQUEST
{
	ULONG pid;
	UINT_PTR source_pid;
	ULONGLONG size;
	void* output;

} KM_READ_REQUEST;

// write struct
typedef struct _KM_WRITE_REQUEST
{
	ULONG pid;
	ULONG source_pid;
	UINT_PTR source_address;
	UINT_PTR target_address;
	ULONGLONG size;

} KM_WRITE_REQUEST;
