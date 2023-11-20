const std = @import("std");
const mem = std.mem;
const AesBlock = std.crypto.core.aes.Block;

pub const Ponteil = struct {
    const State = [8]AesBlock;

    pub const block_length: usize = 32;
    pub const key_length: usize = 32;
    pub const digest_length = 32;

    s: State,
    ctx_segments: u64 = 0,
    m_segments: u64 = 0,
    keyed: bool = false,

    const rounds: usize = 12;

    inline fn aesround(in: AesBlock, rk: AesBlock) AesBlock {
        return in.encrypt(rk);
    }

    fn update(self: *Ponteil, m0: AesBlock, m1: AesBlock) void {
        const s = self.s;
        self.s = State{
            aesround(s[7], s[0].xorBlocks(m0)),
            aesround(s[0], s[1]),
            aesround(s[1], s[2]),
            aesround(s[2], s[3]),
            aesround(s[3], s[4].xorBlocks(m1)),
            aesround(s[4], s[5]),
            aesround(s[5], s[6]),
            aesround(s[6], s[7]),
        };
    }

    inline fn absorb_block(self: *Ponteil, xi: *const [32]u8) void {
        const t0 = AesBlock.fromBytes(xi[0..16]);
        const t1 = AesBlock.fromBytes(xi[16..32]);
        self.update(t0, t1);
    }

    fn init_(k: [32]u8) Ponteil {
        const c0 = AesBlock.fromBytes(&[16]u8{ 0x0, 0x1, 0x01, 0x02, 0x03, 0x05, 0x08, 0x0d, 0x15, 0x22, 0x37, 0x59, 0x90, 0xe9, 0x79, 0x62 });
        const c1 = AesBlock.fromBytes(&[16]u8{ 0xdb, 0x3d, 0x18, 0x55, 0x6d, 0xc2, 0x2f, 0xf1, 0x20, 0x11, 0x31, 0x42, 0x73, 0xb5, 0x28, 0xdd });
        const zero = AesBlock.fromBytes(&[_]u8{0} ** 16);
        const k0 = AesBlock.fromBytes(k[0..16]);
        const k1 = AesBlock.fromBytes(k[16..32]);

        var self = Ponteil{ .s = State{
            zero,             k1,
            k0.xorBlocks(c1), k0.xorBlocks(c0),
            zero,             k0,
            k1.xorBlocks(c0), k1.xorBlocks(c1),
        } };
        var i: usize = 0;
        while (i < rounds) : (i += 1) {
            self.update(c0, c1);
        }
        return self;
    }

    pub fn init(k: ?[32]u8) Ponteil {
        if (k) |k_| {
            var st = Ponteil.init_(k_);
            st.keyed = true;
            return st;
        }
        const k_ = [_]u8{0} ** 32;
        return Ponteil.init_(k_);
    }

    fn absorb(self: *Ponteil, x: []const u8, up: u8) void {
        var i: usize = 0;

        if (self.keyed) {
            while (i + 32 <= x.len) : (i += 32) {
                self.absorb_block(x[i..][0..32]);
            }
            if (x.len % 32 != 0) {
                var pad = [_]u8{0} ** 32;
                mem.copy(u8, pad[0 .. x.len % 32], x[i..]);
                self.absorb_block(&pad);
            }
        } else {
            var pad = [_]u8{0} ** 32;
            while (i + 16 <= x.len) : (i += 16) {
                @memcpy(pad[0..8], x[i..][0..8]);
                @memcpy(pad[16..24], x[i + 8 ..][0..8]);
                self.absorb_block(&pad);
            }
            const left = x.len % 16;
            if (left != 0) {
                const left1 = @min(8, left);
                mem.copy(u8, pad[0..left1], x[i..][0..left1]);
                if (left > 8) {
                    const left2 = left - 8;
                    mem.copy(u8, pad[16..][0..left2], x[i + 8 ..][0..left2]);
                }
                self.absorb_block(&pad);
            }
        }

        var len = [_]u8{0x00} ** 32;
        mem.writeIntLittle(u64, len[0..8], @as(u64, @intCast(x.len)) * 8);
        len[31] ^= up;
        self.absorb_block(&len);
    }

    pub fn push_context(self: *Ponteil, ctx: []const u8) void {
        self.absorb(ctx, 0x80);
        self.ctx_segments += 1;
    }

    pub fn push(self: *Ponteil, m: []const u8) void {
        self.absorb(m, 0x00);
        self.m_segments += 1;
    }

    pub fn finalize(self: *Ponteil, out: []u8) void {
        var b: [16]u8 = undefined;
        mem.writeIntLittle(u64, b[0..8], @as(u64, @intCast(self.ctx_segments)) * 8);
        mem.writeIntLittle(u64, b[8..16], @as(u64, @intCast(self.m_segments)) * 8);
        const t = self.s[2].xorBlocks(AesBlock.fromBytes(&b));
        var i: usize = 0;
        while (i < rounds - 1) : (i += 1) {
            self.update(t, t);
        }
        const s = &self.s;
        i = 0;
        while (i + 32 <= out.len) : (i += 32) {
            self.update(t, t);
            mem.copy(u8, out[i..][0..16], &s[1].xorBlocks(s[6]).xorBlocks(s[2].andBlocks(s[3])).toBytes());
            mem.copy(u8, out[i..][16..32], &s[2].xorBlocks(s[5]).xorBlocks(s[6].andBlocks(s[7])).toBytes());
        }
        if (out.len % 32 != 0) {
            self.update(t, t);
            var pad = [_]u8{0} ** 32;
            mem.copy(u8, pad[0..16], &s[1].xorBlocks(s[6]).xorBlocks(s[2].andBlocks(s[3])).toBytes());
            mem.copy(u8, pad[16..32], &s[2].xorBlocks(s[5]).xorBlocks(s[6].andBlocks(s[7])).toBytes());
            mem.copy(u8, pad[0 .. out.len % 32], out[i..]);
        }
    }

    pub fn mac(k: [32]u8, ctx: ?[]const u8, m: []const u8) [32]u8 {
        var ponteil = Ponteil.init(k);
        if (ctx) |c| {
            ponteil.push_context(c);
        }
        ponteil.push(m);
        var out: [32]u8 = undefined;
        ponteil.finalize(&out);
        return out;
    }

    pub fn hash(ctx: ?[]const u8, m: []const u8) [32]u8 {
        var ponteil = Ponteil.init(null);
        if (ctx) |c| {
            ponteil.push_context(c);
        }
        ponteil.push(m);
        var out: [32]u8 = undefined;
        ponteil.finalize(&out);
        return out;
    }
};

const testing = std.testing;
const fmt = std.fmt;

test "hash" {
    const len = 100_000 - 1;
    const alloc = testing.allocator;
    const m = try alloc.alloc(u8, len);
    defer alloc.free(m);
    @memset(m, 0);
    var h = Ponteil.hash(null, m);
    var expected_h: [32]u8 = undefined;
    _ = try fmt.hexToBytes(&expected_h, "60ed63cf13fb49596a567a0b3538d16e6fa22a746531905fb93ed184783b5432");
    try testing.expectEqualSlices(u8, &h, &expected_h);
}
