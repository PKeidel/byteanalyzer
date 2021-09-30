function read2ByteInt(bytes, offset) {
    return (bytes[offset]) << 8 | bytes[offset + 1];
}

export const parseHeader = function(bytes) {
    const flags = read2ByteInt(bytes, 2)
    return {
        txid: read2ByteInt(bytes, 0),
        flag: flags,
        flags: {
            qr: (flags & (1<<15)) >> 15,
            opcode: (flags & (15<<11)) >> 11,
            aa: (flags & (1<<10)) >> 10,
            tc: (flags & (1<<9)) >> 9,
            rd: (flags & (1<<8)) >> 8,
            ra: (flags & (1<<7)) >> 7,
            z: (flags & (7<<4)) >> 4,
            rcode: flags & 15,
        },
        qdcount: read2ByteInt(bytes, 4),
        ancount: read2ByteInt(bytes, 6),
        nscount: read2ByteInt(bytes, 8),
        arcount: read2ByteInt(bytes, 10),
    }
}
