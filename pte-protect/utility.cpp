#include "pte_protect.h"

auto pte_protect::utility::find_pte_base() -> unsigned __int64
{
    unsigned char MiGetPteAddress_sequence[] =
    {
        0x48, 0xC1, 0xE9, 0x09, 0x48, 0xB8, 0xF8, 0xFF, 0xFF, 0xFF, 0x7F, 0x00, 0x00, 0x00, 0x48, 0x23, 0xC8, 0x48, 0xB8
    };

    PLDR_DATA_TABLE_ENTRY  ldr_data_table_entry = pte_protect::utility::get_system_module_information(L"ntoskrnl.exe");

    if (ldr_data_table_entry != nullptr)
    {
        unsigned __int64 result = pte_protect::utility::search_byte_sequence(unsigned __int64(ldr_data_table_entry->DllBase), unsigned __int64(ldr_data_table_entry->SizeOfImage), MiGetPteAddress_sequence);

        return result ? *(unsigned __int64*)(result + sizeof(MiGetPteAddress_sequence)) : 0;
    }

    return 0;
}

auto pte_protect::utility::resolve_pte_for_virtual_address(unsigned __int64 virtual_address) -> unsigned __int64
{
    auto MiGetPteAddress = [](unsigned __int64 a1) -> unsigned __int64
    {
        unsigned __int64 pte_base = pte_protect::utility::find_pte_base();

        return pte_base ? ((a1 >> 9) & 0x7FFFFFFFF8) + pte_base : 0;
    };

    return MiGetPteAddress(virtual_address);
}

auto pte_protect::utility::get_system_module_information(PCWSTR system_module) -> PLDR_DATA_TABLE_ENTRY
{
    UNICODE_STRING ps_loaded = { 0 }; RtlInitUnicodeString(&ps_loaded, L"PsLoadedModuleList");
    UNICODE_STRING module_name = { 0 }; RtlInitUnicodeString(&module_name, system_module);

    PLIST_ENTRY PsLoadedModuleList = (PLIST_ENTRY)MmGetSystemRoutineAddress(&ps_loaded);

    if (!IsListEmpty(PsLoadedModuleList))
    {
        for (PLIST_ENTRY list_entry = PsLoadedModuleList->Flink; list_entry != PsLoadedModuleList; list_entry = list_entry->Flink)
        {
            PLDR_DATA_TABLE_ENTRY ldr_data_entry = CONTAINING_RECORD(list_entry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

            if (RtlCompareUnicodeString(&module_name, &ldr_data_entry->BaseDllName, 0) == 0)
            {
                return ldr_data_entry;
            }
        }
    }

    return nullptr;
}

auto pte_protect::utility::search_byte_sequence(unsigned __int64 base, unsigned __int64 size, unsigned char byte_sequence[]) -> unsigned __int64
{
    for (int i = 0; i < size - sizeof(byte_sequence); ++i)
    {
        if (RtlCompareMemory((void*)(base + i), byte_sequence, sizeof(byte_sequence)) == sizeof(byte_sequence))
        {
            return base + i;
        }
    }

    return 0;
}