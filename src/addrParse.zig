const std = @import("std");
const testing = std.testing;

const parseError = error{
    CannotParse,
};

pub fn parseIpv4(addr: []const u8) !u32 {
    var iterum: u8 = 0;
    var ip: u32 = 0;
    for (addr) |c| {
        if (std.ascii.isDigit(c)) {
            iterum = iterum * 10;
            iterum += c - '0';
        } else if ('.' == c) {
            ip = ip << 8;
            ip |= iterum;
            iterum = 0;
        } else {
            return parseError.CannotParse;
        }
    }

    ip = ip << 8;
    ip |= iterum;
    return ip;
}

pub fn parseMAC(addr: []const u8) !u48 {
    var iterum: u8 = 0;
    var mac: u48 = 0;
    for (addr) |c| {
        if (std.ascii.isXDigit(c)) {
            iterum = iterum << 4;
            iterum |= switch (c) {
                '0'...'9' => c - '0',
                'a'...'f' => c - 'a' + 10,
                'A'...'F' => c - 'A' + 10,
                else => {
                    return parseError.CannotParse;
                },
            };
        } else if (':' == c) {
            mac = mac << 8;
            mac |= iterum;
        } else {
            return parseError.CannotParse;
        }
    }

    mac = mac << 8;
    mac |= iterum;
    return mac;
}

test "parse ip4 0.0.0.0" {
    try testing.expect(0 == try parseIpv4("0.0.0.0"));
}

test "parse ip4 1.1.1.1" {
    const expected: u32 = 0x01010101;
    const result = try parseIpv4("1.1.1.1");
    try testing.expect(result == expected);
}

test "parse ip4 10.10.10.10" {
    const expected: u32 = 0x0A0A0A0A;
    const result = try parseIpv4("10.10.10.10");
    try testing.expect(result == expected);
}

test "parse ip4 255.255.255.255" {
    const expected: u32 = 0xFFFFFFFF;
    const result = try parseIpv4("255.255.255.255");
    try testing.expect(result == expected);
}

test "parse MAC 00:00:00:00:00:00" {
    const expected: u48 = 0x0;
    const result: u48 = try parseMAC("00:00:00:00:00:00");
    try testing.expect(result == expected);
}

test "parse MAC FF:FF:FF:FF:FF:FF" {
    const expected: u48 = 0xFFFFFFFFFFFF;
    const result: u48 = try parseMAC("FF:FF:FF:FF:FF:FF");
    try testing.expect(result == expected);
}

test "parse MAC 54:ee:75:86:72:b3" {
    const expected: u48 = 0x54EE758672B3;
    const result: u48 = try parseMAC("54:ee:75:86:72:b3");
    try testing.expect(result == expected);
}
