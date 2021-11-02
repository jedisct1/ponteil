const std = @import("std");

pub fn build(b: *std.build.Builder) void {
    const target = b.standardTargetOptions(.{});
    const lib = b.addStaticLibrary("ponteil", null);
    lib.addCSourceFile("ponteil.c", &.{});
    lib.setBuildMode(.ReleaseFast);
    lib.setTarget(target);
    lib.strip = true;
    lib.install();
}
