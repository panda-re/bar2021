from pandare import Panda

panda = Panda(generic="x86_64")
@panda.queue_blocking
def driver():
    panda.revert_sync("root")
    print("User:", panda.run_serial_cmd("whoami"))
    print("Version:", panda.run_serial_cmd("uname -a"))
    print("OS:", panda.run_serial_cmd("cat /etc/issue"))
    panda.end_analysis()
#panda.run()

@panda.ppp("syscalls2", "on_sys_read_return")
def read(cpu, pc, fd, buf, mode):
    name = panda.get_process_name(cpu)
    proc  = panda.plugins['osi'].get_current_process(cpu)
    proc_name = panda.ffi.string(proc.name).decode()
    bytes_read = panda.plugins['syscalls2'].get_syscall_retval(cpu)
    if bytes_read < 0:
        return
    data = panda.read_str(cpu, buf)[:bytes_read]
    print(f"{name} read {bytes_read}: {repr(data)}\n")

panda.run()
