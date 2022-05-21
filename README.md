# pte-protect

##What is this?
Directly changing the bits in the Page Table Entry (PTE) of the corrosponding page to a virtual address to "spoof" protection / being able to hide memory from usermode applications. Because we only touch the PTE the VAD will stay the same so there is no trace other then the PTE that the permission has changed. It will still look like its original protection.

## Functionality
* Changing read / write / execute permissions while maintaining the VAD with the old permissions so it does not look like the page has the "spoofed" permissions.
* Setting the "User Supervisor" bit from the PTE to 0, this will make the page invisible from any usermode api / application.
