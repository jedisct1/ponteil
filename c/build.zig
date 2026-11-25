const std = @import("std");

pub fn build(b: *std.Build) void {
    const module = b.createModule(.{
        .target = b.standardTargetOptions(.{}),
        .optimize = b.standardOptimizeOption(.{ .preferred_optimize_mode = .fast }),
        .link_libc = true,
    });
    module.addCSourceFile(.{ .file = b.path("ponteil.c") });
    const lib = b.addLibrary(.{
        .name = "ponteil",
        .linkage = .static,
        .root_module = module,
    });
    b.installArtifact(lib);
}
