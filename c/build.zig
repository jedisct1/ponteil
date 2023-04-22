const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{ .preferred_optimize_mode = .ReleaseFast });

    const lib = b.addStaticLibrary(.{
        .name = "ponteil",
        .root_source_file = .{ .path = "ponteil.c" },
        .target = target,
        .optimize = optimize,
    });

    b.installArtifact(lib);
}
