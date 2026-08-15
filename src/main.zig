const r4os = @import("r4os");

const role_count: usize = 9;

const App = struct {
    sys: r4os.r4sys.Context,
    net: r4os.r4net.Context,

    fn init(r4_app: *r4os.App) ?App {
        return .{
            .sys = r4_app.system(),
            .net = r4_app.networkLowLevel() orelse return null,
        };
    }
};

const Totals = struct {
    active: u64 = 0,
    missing: u64 = 0,
    absent: u64 = 0,
    blocked: u64 = 0,
    errors: u64 = 0,
    required: u64 = 0,
    r4p_rx: u64 = 0,
    r4p_tx: u64 = 0,
    r4p_control: u64 = 0,
    r4p_build: u64 = 0,
    r4p_classify: u64 = 0,
    dispatch_failures: u64 = 0,
};

pub fn r4_app_main(r4_app: *r4os.App) i32 {
    var app = App.init(r4_app) orelse return r4os.abi.err_no_group;
    const args = trim(zSlice(app.sys.argsRaw()));
    const selftest_mode = isSelfTestMode(args);
    const expected_missing = if (selftest_mode) null else expectedMissingRole(args);

    var detail: r4os.abi.NetDetailSnapshot = .{};
    _ = app.net.netDetailGet(0, &detail);

    const totals = collectTotals(detail);
    printTotals(&app, totals);
    var role: usize = 0;
    while (role < role_count) : (role += 1) printRole(&app, detail, role);

    const ok = if (selftest_mode) validateSelfTest(detail, totals) else validateExpected(detail, expected_missing);

    if (selftest_mode) {
        app.sys.write("NETR4P selftest: ");
    } else if (expected_missing != null) {
        app.sys.write("NETR4P missing-module: ");
    } else {
        app.sys.write("NETR4P runtime/required: ");
    }
    app.sys.println(if (ok) "ok" else "failed");
    return if (ok) 0 else 1;
}

fn collectTotals(detail: r4os.abi.NetDetailSnapshot) Totals {
    var totals: Totals = .{};
    var role: usize = 0;
    while (role < role_count) : (role += 1) {
        const stats = detail.protocols[protocolIndex(role)];
        if (stats.active_r4p != 0) {
            totals.active += 1;
        } else {
            totals.missing += 1;
        }
        switch (stats.r4p_state) {
            r4os.abi.net_detail_r4p_state_missing => totals.absent += 1,
            r4os.abi.net_detail_r4p_state_blocked => totals.blocked += 1,
            r4os.abi.net_detail_r4p_state_error => totals.errors += 1,
            else => {},
        }
        if (stats.builtin_fallback == 0 and
            stats.fallback_policy == r4os.abi.net_detail_fallback_policy_none and
            stats.fallback_decision == r4os.abi.net_detail_fallback_decision_none)
        {
            totals.required += 1;
        }
        totals.r4p_rx += stats.r4p_rx;
        totals.r4p_tx += stats.r4p_tx;
        totals.r4p_control += stats.r4p_control;
        totals.r4p_build += stats.r4p_build;
        totals.r4p_classify += stats.r4p_classify;
        totals.dispatch_failures += stats.dispatch_failures;
    }
    return totals;
}

fn printTotals(app: *const App, totals: Totals) void {
    app.sys.write("R4P runtime: active=");
    app.sys.printU64(totals.active);
    app.sys.write("/");
    app.sys.printU64(@intCast(role_count));
    app.sys.write(" missing=");
    app.sys.printU64(totals.missing);
    app.sys.write(" absent=");
    app.sys.printU64(totals.absent);
    app.sys.write(" blocked=");
    app.sys.printU64(totals.blocked);
    app.sys.write(" errors=");
    app.sys.printU64(totals.errors);
    app.sys.write(" required=");
    app.sys.printU64(totals.required);
    app.sys.write(" dispatch_fail=");
    app.sys.printU64(totals.dispatch_failures);
    app.sys.write(" rx=");
    app.sys.printU64(totals.r4p_rx);
    app.sys.write(" tx=");
    app.sys.printU64(totals.r4p_tx);
    app.sys.write(" build=");
    app.sys.printU64(totals.r4p_build);
    app.sys.write(" classify=");
    app.sys.printU64(totals.r4p_classify);
    app.sys.write(" control=");
    app.sys.printU64(totals.r4p_control);
    app.sys.write("\r\n");
}

fn printRole(app: *const App, detail: r4os.abi.NetDetailSnapshot, role: usize) void {
    const stats = detail.protocols[protocolIndex(role)];
    const missing = stats.active_r4p == 0;
    app.sys.write("NETR4P role ");
    app.sys.write(roleName(role));
    app.sys.write(" source=");
    app.sys.write(roleSource(stats));
    app.sys.write(" state=");
    app.sys.write(roleStateName(stats.r4p_state));
    app.sys.write(" missing=");
    app.sys.write(if (missing) "yes" else "no");
    app.sys.write(" policy=");
    app.sys.write(fallbackPolicyName(stats.fallback_policy));
    app.sys.write(" dispatch_fail=");
    app.sys.printU64(stats.dispatch_failures);
    app.sys.write(" decision=");
    app.sys.write(fallbackDecisionName(stats.fallback_decision));
    app.sys.write("\r\n");
}

fn validateExpected(detail: r4os.abi.NetDetailSnapshot, expected_missing: ?usize) bool {
    if (expected_missing) |missing_role| {
        var role: usize = 0;
        while (role < role_count) : (role += 1) {
            if (!roleMatchesState(detail, role, expectedState(role, missing_role))) return false;
            if (!roleHasRequiredContract(detail, role)) return false;
        }
        return true;
    }

    var role: usize = 0;
    while (role < role_count) : (role += 1) {
        if (!roleMatchesState(detail, role, r4os.abi.net_detail_r4p_state_active)) return false;
        if (!roleHasRequiredContract(detail, role)) return false;
    }
    return true;
}

fn validateSelfTest(detail: r4os.abi.NetDetailSnapshot, totals: Totals) bool {
    if (totals.active != role_count or
        totals.required != role_count or
        totals.missing != 0 or
        totals.absent != 0 or
        totals.blocked != 0 or
        totals.errors != 0)
    {
        return false;
    }

    var role: usize = 0;
    while (role < role_count) : (role += 1) {
        if (!roleMatchesState(detail, role, r4os.abi.net_detail_r4p_state_active)) return false;
        if (!roleHasRequiredContract(detail, role)) return false;
    }
    return true;
}

fn expectedState(role: usize, missing_role: usize) u8 {
    if (role == missing_role) return r4os.abi.net_detail_r4p_state_missing;
    if (dependsTransitivelyOn(role, missing_role)) return r4os.abi.net_detail_r4p_state_blocked;
    return r4os.abi.net_detail_r4p_state_active;
}

fn roleMatchesState(detail: r4os.abi.NetDetailSnapshot, role: usize, state: u8) bool {
    if (role >= role_count) return false;
    const stats = detail.protocols[protocolIndex(role)];
    if (state == r4os.abi.net_detail_r4p_state_active) {
        return stats.active_r4p != 0 and stats.r4p_state == r4os.abi.net_detail_r4p_state_active;
    }
    return stats.active_r4p == 0 and stats.r4p_state == state;
}

fn roleHasRequiredContract(detail: r4os.abi.NetDetailSnapshot, role: usize) bool {
    if (role >= role_count) return false;
    const stats = detail.protocols[protocolIndex(role)];
    return stats.builtin_fallback == 0 and
        stats.fallback_policy == r4os.abi.net_detail_fallback_policy_none and
        stats.fallback_decision == r4os.abi.net_detail_fallback_decision_none;
}

fn dependsTransitivelyOn(role: usize, needle: usize) bool {
    var index: usize = 0;
    while (index < directDependencyCount(role)) : (index += 1) {
        const dep = directDependencyAt(role, index);
        if (dep == needle or dependsTransitivelyOn(dep, needle)) return true;
    }
    return false;
}

fn directDependencyCount(role: usize) usize {
    return switch (role) {
        1 => 1,
        2 => 2,
        3 => 1,
        4 => 1,
        5 => 2,
        6 => 2,
        7 => 1,
        else => 0,
    };
}

fn directDependencyAt(role: usize, index: usize) usize {
    return switch (role) {
        1 => 0,
        2 => if (index == 0) 0 else 1,
        3 => 2,
        4 => 2,
        5 => if (index == 0) 4 else 2,
        6 => if (index == 0) 4 else 2,
        7 => 2,
        else => 0,
    };
}

fn isSelfTestMode(args: []const u8) bool {
    return equalsIgnoreCase(args, "/SELFTEST") or
        equalsIgnoreCase(args, "SELFTEST") or
        equalsIgnoreCase(args, "/CHECK") or
        equalsIgnoreCase(args, "CHECK");
}

fn expectedMissingRole(args: []const u8) ?usize {
    if (equalsIgnoreCase(args, "/MISSING-R4SL")) return 8;
    if (equalsIgnoreCase(args, "MISSING-R4SL")) return 8;
    if (startsWithIgnoreCase(args, "/EXPECT-MISSING=")) return roleFromName(args["/EXPECT-MISSING=".len..]);
    if (startsWithIgnoreCase(args, "EXPECT-MISSING=")) return roleFromName(args["EXPECT-MISSING=".len..]);
    if (startsWithIgnoreCase(args, "/MISSING-")) return roleFromName(args["/MISSING-".len..]);
    if (startsWithIgnoreCase(args, "MISSING-")) return roleFromName(args["MISSING-".len..]);
    return null;
}

fn roleFromName(value: []const u8) ?usize {
    if (equalsIgnoreCase(value, "net.ethernet") or equalsIgnoreCase(value, "NETETH") or equalsIgnoreCase(value, "NETETH.R4P")) return 0;
    if (equalsIgnoreCase(value, "net.arp") or equalsIgnoreCase(value, "NETARP") or equalsIgnoreCase(value, "NETARP.R4P")) return 1;
    if (equalsIgnoreCase(value, "net.ipv4") or equalsIgnoreCase(value, "NETIPV4") or equalsIgnoreCase(value, "NETIPV4.R4P")) return 2;
    if (equalsIgnoreCase(value, "net.icmp") or equalsIgnoreCase(value, "NETICMP") or equalsIgnoreCase(value, "NETICMP.R4P")) return 3;
    if (equalsIgnoreCase(value, "net.udp") or equalsIgnoreCase(value, "NETUDP") or equalsIgnoreCase(value, "NETUDP.R4P")) return 4;
    if (equalsIgnoreCase(value, "net.dhcp") or equalsIgnoreCase(value, "NETDHCP") or equalsIgnoreCase(value, "NETDHCP.R4P")) return 5;
    if (equalsIgnoreCase(value, "net.dns") or equalsIgnoreCase(value, "NETDNS") or equalsIgnoreCase(value, "NETDNS.R4P")) return 6;
    if (equalsIgnoreCase(value, "net.tcp") or equalsIgnoreCase(value, "NETTCP") or equalsIgnoreCase(value, "NETTCP.R4P")) return 7;
    if (equalsIgnoreCase(value, "net.serial_link") or equalsIgnoreCase(value, "NETR4SL") or equalsIgnoreCase(value, "NETR4SL.R4P") or equalsIgnoreCase(value, "R4SL")) return 8;
    return null;
}

fn protocolIndex(role: usize) usize {
    return switch (role) {
        0 => r4os.abi.net_detail_protocol_ethernet,
        1 => r4os.abi.net_detail_protocol_arp,
        2 => r4os.abi.net_detail_protocol_ipv4,
        3 => r4os.abi.net_detail_protocol_icmp,
        4 => r4os.abi.net_detail_protocol_udp,
        5 => r4os.abi.net_detail_protocol_dhcp,
        6 => r4os.abi.net_detail_protocol_dns,
        7 => r4os.abi.net_detail_protocol_tcp,
        else => r4os.abi.net_detail_protocol_serial_link,
    };
}

fn roleName(role: usize) []const u8 {
    return switch (role) {
        0 => "net.ethernet",
        1 => "net.arp",
        2 => "net.ipv4",
        3 => "net.icmp",
        4 => "net.udp",
        5 => "net.dhcp",
        6 => "net.dns",
        7 => "net.tcp",
        else => "net.serial_link",
    };
}

fn roleSource(stats: r4os.abi.NetDetailProtocolRuntime) []const u8 {
    if (stats.active_r4p != 0) return "r4p";
    if (stats.builtin_fallback != 0) return "legacy";
    return "none";
}

fn roleStateName(state: u8) []const u8 {
    return switch (state) {
        r4os.abi.net_detail_r4p_state_missing => "missing",
        r4os.abi.net_detail_r4p_state_loaded => "loaded",
        r4os.abi.net_detail_r4p_state_active => "active",
        r4os.abi.net_detail_r4p_state_blocked => "blocked",
        r4os.abi.net_detail_r4p_state_error => "error",
        r4os.abi.net_detail_r4p_state_disabled => "disabled",
        else => "unknown",
    };
}

fn fallbackPolicyName(policy: u8) []const u8 {
    return switch (policy) {
        r4os.abi.net_detail_fallback_policy_recovery_only => "legacy-policy",
        else => "none",
    };
}

fn fallbackDecisionName(decision: u8) []const u8 {
    return switch (decision) {
        r4os.abi.net_detail_fallback_decision_keep_recovery => "legacy-decision",
        else => "none",
    };
}

fn zSlice(value: [*:0]const u8) []const u8 {
    var len: usize = 0;
    while (value[len] != 0) : (len += 1) {}
    return value[0..len];
}

fn trim(value: []const u8) []const u8 {
    var start: usize = 0;
    var end = value.len;
    while (start < end and isSpace(value[start])) : (start += 1) {}
    while (end > start and isSpace(value[end - 1])) : (end -= 1) {}
    return value[start..end];
}

fn isSpace(ch: u8) bool {
    return ch == ' ' or ch == '\t' or ch == '\r' or ch == '\n';
}

fn startsWithIgnoreCase(value: []const u8, prefix: []const u8) bool {
    if (value.len < prefix.len) return false;
    var i: usize = 0;
    while (i < prefix.len) : (i += 1) {
        if (upper(value[i]) != upper(prefix[i])) return false;
    }
    return true;
}

fn equalsIgnoreCase(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |ca, cb| {
        if (upper(ca) != upper(cb)) return false;
    }
    return true;
}

fn upper(ch: u8) u8 {
    if (ch >= 'a' and ch <= 'z') return ch - 32;
    return ch;
}
