#include "pte_protect.h"

auto pte_protect::manipulation::give_page_excecute_permisions(unsigned __int64 process_id, unsigned __int64 virtual_address) -> NTSTATUS
{
	PEPROCESS process = { 0 }; NTSTATUS status = STATUS_UNSUCCESSFUL;
	PsLookupProcessByProcessId(HANDLE(process_id), &process);

	if (process != nullptr && virtual_address != 0)
	{
		unsigned __int64 pte_virtual = pte_protect::utility::resolve_pte_for_virtual_address(virtual_address);

		if (pte_virtual != 0)
		{
			KAPC_STATE state = { 0 };
			KeStackAttachProcess(process, &state);

			unsigned __int64 bits = *(unsigned __int64*)pte_virtual;

			pte pte_new = { 0 };

			pte_new.value = bits;
			pte_new.nx = 0;

			*(unsigned __int64*)pte_virtual = pte_new.value;

			KeUnstackDetachProcess(&state);

			status = STATUS_SUCCESS;
		}

		ObDereferenceObject(process);
	}

	return status;
}

auto pte_protect::manipulation::give_page_write_permisions(unsigned __int64 process_id, unsigned __int64 virtual_address) -> NTSTATUS
{
	PEPROCESS process = { 0 }; NTSTATUS status = STATUS_UNSUCCESSFUL;
	PsLookupProcessByProcessId(HANDLE(process_id), &process);

	if (process != nullptr && virtual_address != 0)
	{
		unsigned __int64 pte_virtual = pte_protect::utility::resolve_pte_for_virtual_address(virtual_address);

		if (pte_virtual != 0)
		{
			KAPC_STATE state = { 0 };
			KeStackAttachProcess(process, &state);

			unsigned __int64 bits = *(unsigned __int64*)pte_virtual;

			pte pte_new = { 0 };

			pte_new.value = bits;
			pte_new.rw = 1;

			*(unsigned __int64*)pte_virtual = pte_new.value;

			KeUnstackDetachProcess(&state);

			status = STATUS_SUCCESS;
		}

		ObDereferenceObject(process);
	}

	return status;
}

auto pte_protect::manipulation::give_page_user_supervisor_permissions(unsigned __int64 process_id, unsigned __int64 virtual_address) -> NTSTATUS
{
	PEPROCESS process = { 0 }; NTSTATUS status = STATUS_UNSUCCESSFUL;
	PsLookupProcessByProcessId(HANDLE(process_id), &process);

	if (process != nullptr && virtual_address != 0)
	{
		unsigned __int64 pte_virtual = pte_protect::utility::resolve_pte_for_virtual_address(virtual_address);

		if (pte_virtual != 0)
		{
			KAPC_STATE state = { 0 };
			KeStackAttachProcess(process, &state);
			
			unsigned __int64 bits = *(unsigned __int64*)pte_virtual;
			
			pte pte_new = { 0 };
			
			pte_new.value = bits;
			pte_new.user_supervisor = 1;
			
			*(unsigned __int64*)pte_virtual = pte_new.value;
			
			KeUnstackDetachProcess(&state);
			
			status = STATUS_SUCCESS;
		}

		ObDereferenceObject(process);
	}

	return status;
}

auto pte_protect::manipulation::remove_page_excecute_permisions(unsigned __int64 process_id, unsigned __int64 virtual_address) -> NTSTATUS
{
	PEPROCESS process = { 0 }; NTSTATUS status = STATUS_UNSUCCESSFUL;
	PsLookupProcessByProcessId(HANDLE(process_id), &process);

	if (process != nullptr && virtual_address != 0)
	{
		unsigned __int64 pte_virtual = pte_protect::utility::resolve_pte_for_virtual_address(virtual_address);

		if (pte_virtual != 0)
		{
			KAPC_STATE state = { 0 };
			KeStackAttachProcess(process, &state);

			unsigned __int64 bits = *(unsigned __int64*)pte_virtual;

			pte pte_new = { 0 };

			pte_new.value = bits;
			pte_new.nx = 1;

			*(unsigned __int64*)pte_virtual = pte_new.value;

			KeUnstackDetachProcess(&state);

			status = STATUS_SUCCESS;
		}

		ObDereferenceObject(process);
	}

	return status;
}

auto pte_protect::manipulation::remove_page_write_permisions(unsigned __int64 process_id, unsigned __int64 virtual_address) -> NTSTATUS
{
	PEPROCESS process = { 0 }; NTSTATUS status = STATUS_UNSUCCESSFUL;
	PsLookupProcessByProcessId(HANDLE(process_id), &process);

	if (process != nullptr && virtual_address != 0)
	{
		unsigned __int64 pte_virtual = pte_protect::utility::resolve_pte_for_virtual_address(virtual_address);

		if (pte_virtual != 0)
		{
			KAPC_STATE state = { 0 };
			KeStackAttachProcess(process, &state);

			unsigned __int64 bits = *(unsigned __int64*)pte_virtual;

			pte pte_new = { 0 };

			pte_new.value = bits;
			pte_new.rw = 0;

			*(unsigned __int64*)pte_virtual = pte_new.value;

			KeUnstackDetachProcess(&state);

			status = STATUS_SUCCESS;
		}

		ObDereferenceObject(process);
	}

	return status;
}

auto pte_protect::manipulation::remove_page_user_supervisor_permissions(unsigned __int64 process_id, unsigned __int64 virtual_address) -> NTSTATUS
{
	PEPROCESS process = { 0 }; NTSTATUS status = STATUS_UNSUCCESSFUL;
	PsLookupProcessByProcessId(HANDLE(process_id), &process);

	if (process != nullptr && virtual_address != 0)
	{
		unsigned __int64 pte_virtual = pte_protect::utility::resolve_pte_for_virtual_address(virtual_address);

		if (pte_virtual != 0)
		{
			KAPC_STATE state = { 0 };
			KeStackAttachProcess(process, &state);

			unsigned __int64 bits = *(unsigned __int64*)pte_virtual;

			pte pte_new = { 0 };

			pte_new.value = bits;
			pte_new.user_supervisor = 0;

			*(unsigned __int64*)pte_virtual = pte_new.value;

			KeUnstackDetachProcess(&state);

			status = STATUS_SUCCESS;
		}

		ObDereferenceObject(process);
	}

	return status;
}