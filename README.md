Repository for performing DLL Unhooking on Windows.

It includes two methods:

Classic: uses standard Windows API calls.

Direct: performs direct syscalls to Windows APIs. This is made possible by the https://github.com/C-Sto/BananaPhone repository. However, this method may not be stable or function correctly on certain versions of Windows 11.
