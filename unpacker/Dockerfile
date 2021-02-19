FROM pandare/panda:7710a1a45399b26dd3b7a68e20b3317ae8e65fe9
RUN mkdir /server
WORKDIR /server
COPY pyunpacker.py ghidra_integration.py make_recording.py webserver.py utility.py requirements.txt /server/
RUN mkdir templates to_move
COPY templates/ /server/templates
COPY to_move/ /server/to_move/
RUN python3 -m pip install -r requirements.txt
EXPOSE 8888/tcp
EXPOSE 4768