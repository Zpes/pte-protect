#include "pte_protect.h"

auto pte_protect::driver_entry() -> NTSTATUS
{
    NTSTATUS status = pte_protect::manipulation::give_page_write_permisions(3436, 0x7FF7344A5A30);

    if (status == STATUS_SUCCESS)
    {
        // ...
    }
    else
    {
        // ...
    }

    return STATUS_SUCCESS;
}