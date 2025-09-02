import re
import ast
import sys
import os
import json

def load_struct_as_dict(text: str) -> dict:
    # Replace `=` with `:` only when it is used in dict-like contexts
    # (we don't want to touch `==` etc., but in your tool output it's always key = value)
    text = re.sub(r"(\s*)'([^']+)'\s*=", r"\1'\2':", text)

    # 3. Convert `dict(a = 1, b = 2)` → `{'a': 1, 'b': 2}`
    def dict_repl(match):
        inner = match.group(1)
        # Replace a = b with 'a': b
        inner_fixed = re.sub(r"(\w+)\s*=", r"'\1':", inner)
        return "{" + inner_fixed + "}"

    text = re.sub(r"dict\((.*?)\)", dict_repl, text, flags=re.S)
    # Convert into a real Python object safely
    return ast.literal_eval(text)

# Example input
def main():
    # Usage: wrapper.py <json input file> [output file]
    if len(sys.argv) < 2 or len(sys.argv) > 3:
        print(f"[!] Usage: {sys.argv[0]} <json input file> [output file]\n"
              f"    Defaults to 'offsets.h' if output file not provided.")
        exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) >= 3 else 'offsets.h'

    with open(input_file, 'r') as file:
        input_data = json.load(file)

    with open(output_file, 'w') as out_file:
        for pdb in input_data:
            print(f"[i] Loading {pdb}, this can take a few seconds")
            os.system(f"pdb_tpi_vtypes.py {pdb} > {pdb}.json")


            with open(f"{pdb}.json", 'r') as file:
                data = file.read()
                rhs = data.split("=", 1)[1].strip()

                parsed = load_struct_as_dict(rhs)

            print("Done!")
            for struct in input_data[pdb]:
                try:
                    structure = dict(parsed[struct][1])
                except KeyError as e:
                    print(f'[!] {struct} was not found in {pdb}')
                    print(f'[i] try ', end='')
                    if struct[0] != '_':
                        print('_', end='')
                    print(f'{struct.upper()}')
                    exit(1)

                for field in input_data[pdb][struct]:
                    try:
                        offset, struct_type  = structure[field]
                    except KeyError as e:
                        print(f'[!] {field} was not found in {struct}')
                        exit(1)

                    data = f'#define {struct}_{field} 0x{offset:x}'
                    print(data)
                    out_file.write(data+"\n")
        print(f"output saved to {output_file}")


if __name__ == "__main__":
    main()
