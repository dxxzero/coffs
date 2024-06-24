# coffs
Collection of COFFS for BruteRatel C2.

Compile with `x86_64-w64-mingw32-gcc <coff>.c -c -o <coff>.o`

## DCOM.c
PoC lateral movement technique for MMC20.Application.<br>
Currently there is a known issue, that the user is not impersonated when giving the credentials as arguments to the coff.
