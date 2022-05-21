#pragma once
#include <ntifs.h>

#include "undocumented.h"

namespace pte_protect
{
	auto driver_entry() -> NTSTATUS;

	namespace manipulation
	{
		auto give_page_excecute_permisions(unsigned __int64 process_id, unsigned __int64 virtual_address) -> NTSTATUS;
		auto give_page_write_permisions(unsigned __int64 process_id, unsigned __int64 virtual_address) -> NTSTATUS;
		auto give_page_user_supervisor_permissions(unsigned __int64 process_id, unsigned __int64 virtual_address) -> NTSTATUS;

		auto remove_page_excecute_permisions(unsigned __int64 process_id, unsigned __int64 virtual_address)->NTSTATUS;
		auto remove_page_write_permisions(unsigned __int64 process_id, unsigned __int64 virtual_address)->NTSTATUS;
		auto remove_page_user_supervisor_permissions(unsigned __int64 process_id, unsigned __int64 virtual_address)->NTSTATUS;
	}

	namespace utility
	{
		auto find_pte_base() -> unsigned __int64;
		auto resolve_pte_for_virtual_address(unsigned __int64 virtual_address) -> unsigned __int64;
		auto get_system_module_information(PCWSTR system_module) -> PLDR_DATA_TABLE_ENTRY;
		auto search_byte_sequence(unsigned __int64 base, unsigned __int64 size, unsigned char byte_sequence[]) -> unsigned __int64;
	}
}