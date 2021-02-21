Simple Example
===

Using a generic `x86_64` guest, revert to a root snapshot and run a few commands.

Use the `on_sys_read_return` callback provided by the syscalls2 plugin to report information about when read system calls are issued.
