import struct
import math
import json

class Dbi:
    def __init__(self, VersionSignature, VersionHeader, Age, GlobalStreamIndex, BuildNumber, PublicStreamIndex, PdbDllVersion, SymRecordStream, PdbDllRbld, ModInfoSize, SectionContributionSize, SectionMapSize, SourceInfoSize, TypeServerMapSize, MFCTypeServerIndex, OptionalDbgHeaderSize, ECSubstreamSize, Flags, Machine, Padding, data):
        self.VersionSignature = VersionSignature
        self.VersionHeader = VersionHeader
        self.Age = Age
        self.GlobalStreamIndex = GlobalStreamIndex
        self.BuildNumber = BuildNumber
        self.PublicStreamIndex = PublicStreamIndex
        self.PdbDllVersion = PdbDllVersion
        self.SymRecordStream = SymRecordStream
        self.PdbDllRbld = PdbDllRbld
        self.ModInfoSize = ModInfoSize
        self.SectionContributionSize = SectionContributionSize
        self.SectionMapSize = SectionMapSize
        self.SourceInfoSize = SourceInfoSize
        self.TypeServerMapSize = TypeServerMapSize
        self.MFCTypeServerIndex = MFCTypeServerIndex
        self.OptionalDbgHeaderSize = OptionalDbgHeaderSize
        self.ECSubstreamSize = ECSubstreamSize
        self.Flags = Flags
        self.Machine = Machine
        self.Padding = Padding
        self.data = data

def build_dbi(data):
    size = 4 + 4 + 4 + 2 + 2 + 2 + 2 + 2 + 2 + 4 + 4 + 4 + 4 + 4 + 4 + 4 + 4 + 2 + 2 + 4
    return Dbi(*struct.unpack("<IIIHHHHHHIIIIIIIIHHI", data[:size]), data)

class Pdb:
    def __init__(self, signature, block_size, free_block_map_block, num_blocks, num_dir_bytes, _unknown, block_map_addr, data):
        self.signature = signature
        self.block_size = block_size
        self.free_block_map_block = free_block_map_block
        self.num_blocks = num_blocks
        self.num_dir_bytes = num_dir_bytes
        self._unknown = _unknown
        self.block_map_addr = block_map_addr
        self.data = data

    def get_pages(self, index, length=1):
        return self.data[index*self.block_size:index*self.block_size + length*self.block_size]
    
    def get_block_map_indices(self):
        block_map = self.get_pages(self.block_map_addr)
        indices = []
        for x in range(0, len(block_map), 4):
            index = struct.unpack("<I", block_map[x:x+4])[0]
            if not index:
                break
            indices.append(index)
        
        return indices
    
    def get_block_map(self):
        indices = self.get_block_map_indices()
        data = b""
        for index in indices:
            data += self.get_pages(index)
        
        return data


def build_pdb(data):
    size = 32 + 4 + 4 + 4 + 4 + 4 + 4
    return Pdb(*struct.unpack("<32sIIIIII", data[:size]), data)

def get_stream(pdb, block_map, stream_blocks_offset, stream_block_counts, index):
    dbi_block_counts_offset = stream_blocks_offset + (4*sum(stream_block_counts[:index]))
    dbi_block_counts_end = dbi_block_counts_offset + stream_block_counts[index]*4

    dbi_block_counts = struct.unpack("<%dI" % stream_block_counts[index], block_map[dbi_block_counts_offset:dbi_block_counts_end])

    return b"".join(pdb.get_pages(x) for x in dbi_block_counts)

def read_pdb(pdb_path):
    with open(pdb_path, "rb") as file:
        data = file.read()
    
    pdb = build_pdb(data)

    block_map = pdb.get_block_map()

    num_streams = struct.unpack("<I", block_map[:4])[0]
    stream_lengths_offset = 4
    stream_blocks_offset = stream_lengths_offset + 4*num_streams
    stream_sizes = struct.unpack("<%dI" % num_streams, block_map[stream_lengths_offset:stream_blocks_offset])
    stream_block_counts = [math.ceil(x / pdb.block_size) for x in stream_sizes]

    # we want stream 3

    dbi = build_dbi(get_stream(pdb, block_map, stream_blocks_offset, stream_block_counts, 3))

    symbol_stream = get_stream(pdb, block_map, stream_blocks_offset, stream_block_counts, dbi.SymRecordStream)

    index = 0
    symbols = {}
    while index < len(symbol_stream):
        length, magic = struct.unpack("<HH", symbol_stream[index:index+4])
        if length == 0:
            break
        elif length < 0:
            print("Bad length: %d" % length)
        if magic & 0xFF00 != 0x1100:
            print("Bad magic: %04X" % magic)
            import pdb
            pdb.set_trace()
        elif magic == 0x110E:
            # read rest
            flags, offset, segment = struct.unpack("<IIH", symbol_stream[index+4:index+14])
            symbol_name = symbol_stream[index+14:index+length+1].decode()
            symbols[symbol_name.rstrip("\x00")] = "%02X:%04X" % (segment, offset)
            #print("%s: %08X" % (symbol_name, offset))
        index += length + 2
    
    return symbols


if __name__ == "__main__":
    from argparse import ArgumentParser
    parser = ArgumentParser()
    parser.add_argument("pdb_path")
    parser.add_argument("output")
    args = parser.parse_args()

    symbols = read_pdb(args.pdb_path)
    with open(args.output, "w") as outfile:
        outfile.write(json.dumps(symbols))
    print("Done")
