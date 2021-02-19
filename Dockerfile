FROM pandare/panda:7710a1a45399b26dd3b7a68e20b3317ae8e65fe9
# These demos are known to work with the above PANDA commit

RUN mkdir -p /demos/unpacker /demos/heaptracker/ /demos/ir_eval

# Unpacker
WORKDIR /demo/unpacker
COPY unpacker/pyunpacker.py unpacker/ghidra_integration.py unpacker/make_recording.py unpacker/webserver.py unpacker/utility.py unpacker/requirements.txt /demo/unpacker/
RUN mkdir templates to_move
COPY unpacker/templates/ /demo/unpacker/templates/
COPY unpacker/to_move/ /demo/unpacker/to_move/
RUN python3 -m pip install -r requirements.txt
EXPOSE 8888/tcp
EXPOSE 4768

# Heap tracker
WORKDIR /demo/heaptracker
COPY heaptracker/heaptracker.py heaptracker/requirements.txt /demo/heaptracker/
RUN mkdir tree
COPY heaptracker/tree tree/
RUN python3 -m pip install -r requirements.txt

# IR eval
WORKDIR /demo/ir_eval
COPY ir_eval/cache.py ir_eval/requirements.txt ir_eval/run.py ir_eval/switchboard.py ir_eval/test.py /demo/ir_eval/
RUN mkdir ghidra_v9.2_sla
COPY ir_eval/ghidra_v9.2_sla/ ghidra_v9.2_sla/
RUN python3 -m pip install -r requirements.txt

WORKDIR /demo
