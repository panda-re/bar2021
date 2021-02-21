FROM pandare/panda:8bebf696ca0945e91bf87023b9579488d4845526
# These demos are known to work with the above PANDA commit

RUN mkdir -p /demos/unpacker /demos/heaptracker/ /demos/ir_eval

COPY ir_eval/requirements.txt ir_eval/
COPY unpacker/requirements.txt unpacker/
COPY heaptracker/requirements.txt heaptracker/

#RUN python3 -m pip install -r ir_eval/requirements.txt # XXX: Requirements do not install
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
