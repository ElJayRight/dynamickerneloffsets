import subprocess
import sys
import os
import re
import json

def parse_imports(pe_name, modules, src):
    # Run objdump -x
    IAT = []
    result = subprocess.run(
        ["objdump", "-x", pe_name],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if result.returncode != 0:
        print(f"Error running objdump on {pe_name}: {result.stderr.strip()}")
        return

    dll = None
    for line in result.stdout.splitlines():
        line = line.strip()

        # Detect DLL name
        if line.startswith("DLL Name:"):
            dll = os.path.splitext(os.path.basename(line.split(":", 1)[1].strip()))[0]

        # Detect imported functions (lines start with hex addr)
        else:
            m = re.match(r"^([0-9a-fA-F]+)\s+\d+\s+(\S+)", line)
            if m and dll.lower() in modules:
                func = m.group(2)
                file_result = subprocess.run(["grep", "-i", f"{func}", src], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                if len(file_result.stdout.splitlines()) != 0:
                    output = f"{dll}${func}"
                    IAT.append(output)
    return IAT 

def build_linker_imports(iat):
    imports = []
    for entry in iat:
        module, api_call = entry.split("$")

        result = subprocess.run(["grep", "-haiR", f'WINAPI {api_call} (', "/usr/x86_64-w64-mingw32/include/"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.returncode != 0:
            print(f"Error running grep on {api_call}")
            return

        for line in result.stdout.splitlines():
            line = line.strip()
            data = line.split()

            # get every second value
            vars = line.split("(")[1][:-2]
            vars = ', '.join([x for j, x in enumerate(vars.split()) if j%2==0]) 
            output = f"DECLSPEC_IMPORT {data[1]} {module}${data[3]}({vars});"
            imports.append(output)

    with open("linking.c", "w") as out_file:
        for api_import in imports:
            out_file.write(api_import+"\n")
    return imports

def update_src(src, iat, new_file_name=''):
    if new_file_name == '':
        new_file_name = f'{src}.bof.c'
    sed_args = []
    for entry in iat:
        _, api_call = entry.split("$")
        sed_args.extend(["-e", f"s/{api_call}(/{entry}(/g"])
    print("[i] Updating imports")
    subprocess.run(["cp", src, new_file_name], check=True)
    subprocess.run(["sed", "-i"] + sed_args + [new_file_name], check=True)
    print("[i] Adding linking file")
    subprocess.run(["sed", "-i", '3i#include "linking.c"', new_file_name], check=True)
    subprocess.run(["sed", "-i", '3i#include "beacon.h"', new_file_name], check=True)
    print("[i] Changing printf to BeaconPrintf") # This will cause a bug but idc
    subprocess.run(["sed", "-i", "-e", "s/printf(/BeaconPrintf( CALLBACK_OUTPUT, /g", "-e", "s/void main(/void go(/g", new_file_name], check=True)
    print("[+] Done!")


def main():
    if len(sys.argv) != 2:
        print(f"[!] Usage: {sys.argv[0]} <json input file>")
        exit(1)

    input_file = sys.argv[1]
    with open(input_file, 'r') as file:
        input_data = json.load(file)

    #print(input_data)
    for source_file in input_data:
        print(f"[+] Compiling and getting IAT for {source_file}")
        file_name = source_file.split('.')[0]+".exe"
        subprocess.run(["x86_64-w64-mingw32-gcc", source_file, "-o", file_name], check=True)
        iat = parse_imports(file_name, input_data[source_file]['modules'], source_file)
        imports = build_linker_imports(iat)
        #[print(x) for x in imports]
        update_src(source_file, iat, input_data[source_file]['output'])

if __name__ == "__main__":
    main()
