FROM pandare/panda:latest
# These demos are known to work with panda as of 2/20/2021

# Apt deps
RUN apt-get update && apt-get install -y build-essential

RUN mkdir -p /demos/unpacker /demos/heaptracker/ /demos/ir_eval

COPY ir_eval/requirements.txt ir_eval/
COPY unpacker/requirements.txt unpacker/
COPY heaptracker/requirements.txt heaptracker/

RUN python3 -m pip install --upgrade setuptools wheel pip
RUN python3 -m pip install -r ir_eval/requirements.txt
RUN python3 -m pip install -r unpacker/requirements.txt
RUN python3 -m pip install -r heaptracker/requirements.txt

# IR eval
WORKDIR /demo/ir_eval
COPY ir_eval/cache.py ir_eval/run.py ir_eval/switchboard.py ir_eval/test.py /demo/ir_eval/
RUN mkdir ghidra_v9.2_sla
COPY ir_eval/ghidra_v9.2_sla/ ghidra_v9.2_sla/

# Unpacker
WORKDIR /demo/unpacker
COPY unpacker/pyunpacker.py unpacker/ghidra_integration.py unpacker/make_recording.py unpacker/webserver.py unpacker/utility.py /demo/unpacker/
RUN mkdir templates to_move
COPY unpacker/templates/ /demo/unpacker/templates/
COPY unpacker/to_move/ /demo/unpacker/to_move/
EXPOSE 8888/tcp
EXPOSE 4768

# Heap tracker
WORKDIR /demo/heaptracker
COPY heaptracker/heaptracker.py /demo/heaptracker/
RUN mkdir tree
COPY heaptracker/tree tree/

WORKDIR /demo
