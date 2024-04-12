const std = @import("std");

pub fn build(b: *std.build.Builder) void {
    const pcaptest = b.addExecutable(.{
        .name = "raw-sock",
        .root_source_file = .{ .path = "src/main.zig" },
    });
    pcaptest.linkSystemLibrary("libpcap");
    pcaptest.linkLibC();

    b.installArtifact(pcaptest);

    const ping = b.addExecutable(.{
        .name = "ping-o-death",
        .root_source_file = .{ .path = "src/ping-o-death.zig" },
    });

    const addrParseMod = b.addModule("AddrParse", .{ .source_file = .{ .path = "AddrParse/src/addrParse.zig" } });

    const clap = std.build.dependency(b, "clap", .{});
    ping.addModule("clap", clap.module("clap"));

    ping.addModule("AddrParse", addrParseMod);
    b.installArtifact(ping);
}
