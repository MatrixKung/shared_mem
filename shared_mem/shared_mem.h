#pragma once

#include "stdafx.h"

//functions
NTSTATUS create_shared_memory();
VOID open_events();
void NTAPI driver_loop(PVOID StartContext);
