import struct
import lief
import requests

def get_null_terminated_string(binary, offset):
    output_bytes = []
    while True:
        byte = binary.get_content_from_virtual_address(offset, 1)[0]
        if not byte:
            break
        output_bytes.append(byte)
        offset += 1
    
    return bytes(output_bytes).decode()

def download_pdb(kernel_path, output_path):
    binary = lief.parse(kernel_path)
    debug = next(filter(lambda x: int(x.type), binary.debug))

    if not debug:
        print("Couldn't find CODEVIEW debug section")
        return
    
    bytes(binary.get_content_from_virtual_address(debug.addressof_rawdata, 24))
    rsds_magic = bytes(binary.get_content_from_virtual_address(debug.addressof_rawdata, 4))
    if rsds_magic != b"RSDS":
        print("Magic didn't match, should be RSDS but got %s" % rsds_magic)
        return

    guid = "%08X%04X%04X%02X%02X%02X%02X%02X%02X%02X%02X1" % struct.unpack("<LHHBBBBBBBB", bytes(binary.get_content_from_virtual_address(debug.addressof_rawdata+4, 16)))
    path = get_null_terminated_string(binary, debug.addressof_rawdata+24)

    download_path = "https://msdl.microsoft.com/download/symbols/%s/%s/%s" % (path, guid, path)

    print("Downloading: %s" % download_path)

    with open(output_path, "wb") as outfile:
        response = requests.get(download_path, allow_redirects=True)
        outfile.write(response.content)


if __name__ == "__main__":
    from argparse import ArgumentParser
    parser = ArgumentParser()
    parser.add_argument("kernel_path")
    parser.add_argument("output_path")
    args = parser.parse_args()

    download_pdb(args.kernel_path, args.output_path)