#!/usr/bin/env python3
from pandare import Panda
import matplotlib.pyplot as plt

panda = Panda(generic="x86_64")

(malloc_offset, free_offset) = (None, None)
analysis_active = False
hooked_asids = set()

def hook_ret_with_args(panda, name, entry_addr, func=None, asid=None, kernel=False):
  '''
  Helper function to run `func` when a function returns.
  The function is called with three args: in_arg1, in_arg2, and ret_val

  This is done by setting up a hook at the function start, which grabs the first 2
  arguments, then registers a second hook at the return address.  When the second hook
  fires, we call the user-provided function.
  '''
  hooked_args = []

  @panda.hook(entry_addr, asid=asid, kernel=kernel)
  def _enter(cpu, tb, h):
    # Grab ret_addr off stack and first two args
    ret_addr = panda.virtual_memory_read(cpu, panda.arch.get_reg(cpu, "rsp"), 8, fmt="int")
    hooked_args = [panda.arch.get_arg(cpu, idx) for idx in range(2)]

    # Setup a new hook to run just once at ret_addr and call user-provided func
    @panda.hook(ret_addr, asid=asid, kernel=kernel)
    def _return(cpu, tb, h):
      h.enabled = False
      retval = panda.arch.get_reg(cpu, "rax")
      func(cpu, hooked_args, retval)

def add_hooks_if_necessary(cpu):
  '''
  Called when something may have changed with the memory maps
  in the current process. Scan mappings for libc and set hooks
  on malloc and free relative to the libc base address.
  '''

  if not analysis_active:
    return # Don't setup hooks until we're ready

  asid = panda.current_asid(cpu)
  if asid in hooked_asids:
      return # Already hooked this process

  name = panda.get_process_name(cpu)
  # Find current libc address and update hooks
  for mapping in panda.get_mappings(cpu):
    if mapping.file != panda.ffi.NULL and \
        panda.ffi.string(mapping.file).decode().startswith("/lib/x86_64-linux-gnu/libc-"):
      hooked_asids.add(asid)
      hook_ret_with_args(panda, f"{name}_malloc", mapping.base + malloc_offset, asid=asid,
          func=lambda cpu, in_args, retval: add_alloc(retval, in_args[0],
                                             asid=panda.current_asid(cpu),
                                             name=panda.get_process_name(cpu)))

      # Note for free we don't need retval, just the hook
      @panda.hook(mapping.base+free_offset, asid=asid, kernel=False)
      def process_free(cpu, tb, h):
        buf = panda.arch.get_reg(cpu, 'rax')
        asid = panda.current_asid(cpu)
        rem_alloc(buf, asid=asid)

# Allocation trackers
recorded_results = [] # List of active allocations updated every 1k blocks
active_allocs = {} # (asid, addr): (size, name). If kernel, asid=0 & name=None
def add_alloc(address, size, asid=0, name=None):
  global active_allocs
  active_allocs[(asid, address)] = (size, name)

def rem_alloc(address, asid=0):
  global active_allocs
  if (asid, address) in active_allocs:
    del active_allocs[(asid, address)]

def report_allocs():
  global recorded_results
  active_sizes  = {} # asid (0 for kernel): {name: 'foo', total_size: X, total_allocs: Y}
  for ((asid, addr), (size, name)) in active_allocs.items():
    if asid not in active_sizes:
      active_sizes[asid] = {'name': name, 'total_size': 0, 'total_allocs': 0}

    active_sizes[asid]['total_size'  ] += size
    active_sizes[asid]['total_allocs'] += 1

  this_ts = {}
  for asid, details in active_sizes.items():
    this_ts[asid] = details
  recorded_results.append(this_ts)


BBE_CTR = 0
@panda.cb_before_block_exec(enabled=False)
def report_every_1000(cpu, tb):
  global BBE_CTR
  BBE_CTR += 1
  if BBE_CTR % 1000 == 0:
    report_allocs()
    BBE_CTR = 0
# End allocation trackers

# There are three times we need to update our hooks: on process changes
# and on return from sys_brk or sys_mmap which may have loaded libc
@panda.ppp("osi", "on_task_change")
def task_change(cpu):
  add_hooks_if_necessary(cpu)

@panda.ppp("syscalls2", "on_sys_brk_return")
def brk(cpu, *unused):
  add_hooks_if_necessary(cpu)

@panda.ppp("syscalls2", "on_sys_mmap_return")
def mmap(cpu, *unused):
  add_hooks_if_necessary(cpu)

@panda.queue_blocking
def setup_hooks():
  '''
  Drive guest to look at libc and System.map to identify offsets into libraries
  and kernel addresses we want to hook.
  '''
  panda.revert_sync("root")

  # Find malloc and free offsets in libc
  global malloc_offset, free_offset
  libc = panda.run_serial_cmd("find /lib/ -name 'libc.so.*'")
  malloc_offset = int("0x"+panda.run_serial_cmd(f"nm -D {libc} | grep 'T malloc$' | awk '{{print $1}}'"), 16)
  free_offset = int("0x"+panda.run_serial_cmd(f"nm -D {libc} | grep 'T free$' | awk '{{print $1}}'"), 16)

  # Get addresses to hook and setup hooks. Note kmalloc/vmalloc use helper to hook at return
  for fname in ["kfree", "__kmalloc", "vmalloc"]:
    addr = int(panda.run_serial_cmd(f"grep 'T {fname}$' /boot/System.map*|tail -n1|awk '{{print $1}}'"), 16)
    if fname == "kfree":
      @panda.hook(addr, kernel=True)
      def kfree_hook(cpu, tb, h):
        rem_alloc(panda.arch.get_reg(cpu, 'rax'))
    else:
      hook_ret_with_args(panda, fname, addr, kernel=True,
                        func=lambda cpu, in_args, retval: add_alloc(retval, in_args[0]))


@panda.queue_blocking
def drive_guest():
  '''
  Revert to root snapshot, copy 'tree' binary in,
  enable analyses, and run tree program
  '''
  panda.revert_sync("root")
  panda.copy_to_guest("tree")

  global analysis_active
  analysis_active = True
  panda.enable_callback("report_every_1000")
  print("Guest output:\n", "="*60 , "\n", panda.run_serial_cmd("./tree/tree 100"))
  print("="*60)
  panda.end_analysis()

panda.run()

# Visualize results with matplotlib
for (figname, prop_name) in [('Heap Chunks Allocated', 'total_allocs'), ('Heap Bytes Allocated', 'total_size')]:
  user_sizes = {} # asid: [ allocations_at_0, ... allocations_at_N ]
  asid_names = {} # asid: name

  # First go through all timestamps and grab all asids observed, make a list of 0s for each at each timestamp
  for ts_details in recorded_results:
    for asid, asid_details in ts_details.items():
      if asid not in user_sizes.keys():
        user_sizes[asid] = [0]*len(recorded_results)
        asid_names[asid] = asid_details['name']


  # At each time stamp, append num active allocations for the asid
  for ts, ts_details in enumerate(recorded_results):
    for asid, asid_details in ts_details.items():
      user_sizes[asid][ts] = asid_details[prop_name]

  fig = plt.gcf()
  fig.set_size_inches(9, 5)

  # Plot each result
  for asid in user_sizes:
    if asid == 0:            label = "Kernel"
    elif asid in asid_names: label = asid_names[asid]
    else:                    label = hex(asid)
    plt.plot([x for x in range(len(recorded_results))], user_sizes[asid], label=label)

  plt.title(f'Total {figname} per Process')
  plt.xlabel('Basic Block Count (thousands)')
  plt.ylabel(figname)
  lgd = plt.legend(bbox_to_anchor=(1.01, 1), loc='upper left', fontsize='small')

  plt.savefig(prop_name+".png", bbox_inches='tight')
  plt.clf()
