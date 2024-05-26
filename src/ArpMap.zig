const std = @import("std");

const addrParse = @import("AddrParse");

const Allocator = std.mem.Allocator;

pub const ipAndMac = struct { address: u32, mac: u48 };
pub const ArpMap = struct {
    const IpAndMacList = std.ArrayList(ipAndMac);
    map: IpAndMacList,

    pub fn init(allocator: Allocator) !ArpMap {
        return .{
            .map = getARPMap(allocator) catch |err| return err,
        };
    }

    pub fn deinit() void {
        @This().map.deinit();
    }

    pub fn getARPMap(allocator: Allocator) !IpAndMacList {
        var file = std.fs.cwd().openFile("/proc/net/arp", .{}) catch |err| return err;
        defer file.close();

        var list = IpAndMacList.init(allocator);

        var buf_reader = std.io.bufferedReader(file.reader());
        var in_stream = buf_reader.reader();
        var buf = [_]u8{0} ** 2048;

        _ = in_stream.readUntilDelimiterOrEof(&buf, '\n') catch |err| return err;
        while (try in_stream.readUntilDelimiterOrEof(&buf, '\n')) |line| {
            var token_iter = std.mem.tokenizeAny(u8, line, " ");
            const ip = token_iter.next().?;
            _ = token_iter.next().?;
            _ = token_iter.next().?;
            const mac = token_iter.next().?;

            var ip_pair: ipAndMac = .{ //
                .address = addrParse.parseIpv4(ip) catch |err| return err, //
                .mac = addrParse.parseMAC(mac) catch |err| return err,
            };

            list.append(ip_pair) catch |err| return err;
        }
        return list;
    }

    pub fn findMac(ip: u32) ?u48 {
        var found_address: ?u48 = null;
        for (@This().map) |iandm| {
            if (iandm.ip == ip) {
                found_address = iandm.address;
            }
        }
        return found_address;
    }
    pub fn printArpIPMACs() !void {
        for (try @This().map.toOwnedSlice()) |ip| {
            var backingMem: [24:0]u8 = undefined;
            const ipslice = addrParse.Ipv4ToString(ip.address, &backingMem) catch |err| return err;
            std.debug.print("{s} ", .{ipslice});
            const MACslice = addrParse.MACToString(ip.mac, &backingMem) catch |err| return err;
            std.debug.print("{s} \n", .{MACslice});
        }
    }
};
