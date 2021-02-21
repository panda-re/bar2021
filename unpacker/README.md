# unpacker detailed README

NOTE: To get the network to work you may need to run docker with `--net="host"`.

NOTE: There seems to be an issue with memory transactions in the very newest Ghidra version (v9.2.2). This is likely a change in API our code hasn't handled properly yet. This code works properly in Ghidra version 9.2 Public.

Set up an empty Ghidra project on your host or other machine (with a blank file) or via headless and run ghidra_bridge.

Make sure your Ghidra machine can reach the machine your program is running on port 4768 if running on different hosts. I used ssh port forwarding for this and on my ghidra box I ran `ssh -R 4768:localhost:4768`.

Next, run the following:

`cd unpacker`

`python3 make_recording.py [name_for_recording]`

`python3 pyunpacker.py [name_for_recording] --granularity 10000`

Adjust the granularity to get better values.

Go to the web server address of the machine you ran the `pyunpacker` script on and connect to the web server on port 8888. When you find a point you are interested in click on it and switch back to Ghidra.
