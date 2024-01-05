const std = @import("std");
const testing = std.testing;

pub const ethFrame = packed struct {
    dst: u48,
    src: u48,
    type: u16,
};
pub fn fromBytes(comptime t: type, data: [*]u8) t {
    var data_slice: []u8 = undefined;
    data_slice.ptr = data;
    data_slice.len = @sizeOf(t);
    var layer: t = std.mem.bytesToValue(t, data[0..@sizeOf(t)]);
    std.mem.byteSwapAllFields(t, &layer);
    return layer;
}

pub const ipHeader = packed struct {
    LengthAndVersion: u8,
    prioAndTOS: u8,
    totalLength: u16,
    identification: u16,
    flagAndOffset: u16,
    ttl: u8,
    protocol: u8,
    checksum: u16,
    src: u32,
    dst: u32,
};

pub const icmpHeader = packed struct {
    type: u8,
    code: u8,
    checksum: u16,
    roh: u32, //rest of header
    pub const ping = packed struct {
        type: u8,
        code: u8,
        checksum: u16,
        identifier: u16,
        seqNum: u16,
        timeStamp: u64,
    };
};

pub const tcpHeader = packed struct {
    srcPort: u16,
    dstPort: u16,
    seqNum: u32,
    ackNum: u32,
    headerLength: u8,
    flags: u8,
    windowSize: u16,
    checkSum: u16,
    urgentPrt: u16,

    pub fn hasOptions(self: tcpHeader) bool {
        var it_does: bool = false;
        if (self.headerLength > @bitSizeOf(tcpHeader)) {
            it_does = true;
        }
        return it_does;
    }
};

test "IP header size == 24" {
    try testing.expect(@sizeOf(ipHeader) == 20);
}

test "TCP header size == 20" {
    try testing.expect(@sizeOf(tcpHeader) == 20);
}
