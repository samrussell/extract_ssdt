import lief
import json

def rva_as_hex(rva_as_list):
    return rva_as_list[0] + rva_as_list[1]*0x100 + rva_as_list[2]*0x10000

def format_ssdt(rdata, export_lookup, symbol_rva_lookup, ssdt_start, arg_counts_start, ssdt_size):
    for x in range(ssdt_size):
        ssdt_offset = ssdt_start + (x*4)
        arg_count_offset = arg_counts_start + x
        address_rva = rva_as_hex(rdata.content[ssdt_offset:ssdt_offset+4])
        if address_rva in export_lookup:
            function_name = export_lookup[address_rva]
        elif address_rva in symbol_rva_lookup:
            function_name = symbol_rva_lookup[address_rva]
        else:
            function_name = "?"
        print("0x%03X: 0x%08X (%s)" % (x, address_rva, function_name))
    return

def test_arg_counts(rdata, arg_counts_start, ssdt_size):
    for y in range(ssdt_size):
        arg_count = rdata.content[arg_counts_start + y]
        if arg_count & 0x3:
            print("Fail: Arg count 0x%X was 0x%X, bottom 2 bits shouldn't be set" % (y, arg_count))
            return False
    
    return True

def test_ssdt_rvas(rdata, pointer):
    # scroll forward
    # size of SSDT is a 16 bit WORD
    for x in range(0x10000):
        offset = pointer + (x*4)
        rva = rdata.content[offset:offset+4]
        if (rva[2] or rva[3]) and rva[0] & 0x0F:
            print("Low nybble is set, not SSDT")
            return None
        if rva[2] == 0 and rva[3] == 0:
            # final entry
            ssdt_size = rva[1]*256 + rva[0]
            print("Final entry at 0x%X, value 0x%X" % (offset + rdata.virtual_address, ssdt_size))
            # jump past this and test the next X bytes
            ssdt_start = offset - (ssdt_size * 4)
            arg_counts_start = offset + 4
            if not test_arg_counts(rdata, arg_counts_start, ssdt_size):
                continue
            final_arg_value = rdata.content[arg_counts_start + ssdt_size]
            print("Arg count check successful, all have bottom 2 bits = 0 and final value is 0x%X" % final_arg_value)
            return (ssdt_start, arg_counts_start, ssdt_size)
    print("Didn't find end")
    return None

def extract_ssdt(kernel_path, symbols):
    binary = lief.parse(kernel_path)

    # convert segment:offset to actual addresses
    symbol_rva_lookup = {}
    for symbol, address in symbols.items():
        segment, offset = address.split(":")
        try:
            base_rva = binary.sections[int(segment, 0x10)-1].virtual_address
        except IndexError:
            continue
        symbol_rva_lookup[base_rva  + int(offset, 0x10)] = symbol

    # how to find SSDT
    # - find RVA of something we know is exported (e.g. NtWaitForSingleObject)
    # - find occurrences of this RVA
    # skip past every 00xxxxxx DWORD until we get to a 0000xxxx DWORD
    # jump back 4*val and make sure our RVA is inside that, make sure dest is an RVA 00xxxxxx and in export table
    # iterate over next val bytes and make sure each has 

    ntwaitforsingleobject = next(filter(lambda x: x.name == "NtWaitForSingleObject", binary.exported_functions))
    export_lookup = {x.address : x.name for x in binary.exported_functions}
    print("NtWaitForSingleObject exported with RVA %X" % ntwaitforsingleobject.address)
    rdata = binary.get_section(".rdata")
    ntwaitforsingleobjectpointers = rdata.search_all(ntwaitforsingleobject.address)
    print("Found %d instances of RVA, testing..." % len(ntwaitforsingleobjectpointers))
    for pointer in ntwaitforsingleobjectpointers:
        print("Found RVA at 0x%X, testing for end of SSDT" % (pointer + rdata.virtual_address))
        result = test_ssdt_rvas(rdata, pointer)
        if result:
            (ssdt_start, arg_counts_start, ssdt_size) = result
            return format_ssdt(rdata, export_lookup, symbol_rva_lookup, ssdt_start, arg_counts_start, ssdt_size)
    
    print("Fail: couldn't extract SSDT :'(")

if __name__ == "__main__":
    from argparse import ArgumentParser
    parser = ArgumentParser()
    parser.add_argument("kernel_path")
    parser.add_argument("--symbol_path")
    args = parser.parse_args()

    if args.symbol_path:
        with open(args.symbol_path) as file:
            symbols = json.loads(file.read())
    else:
        symbols = {}
    extract_ssdt(args.kernel_path, symbols)
