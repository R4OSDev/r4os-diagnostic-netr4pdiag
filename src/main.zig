const std = @import("std");
const r4os = @import("r4os");
const update_contract = @import("update_service_contract");

const role_count: usize = 8;

const App = struct {
    sys: r4os.r4sys.Context,
    net: r4os.r4net.Context,

    fn init(r4_app: *r4os.App2) ?App {
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

pub fn r4_app_main(r4_app: *r4os.App2) i32 {
    var app = App.init(r4_app) orelse return r4os.abi.err_no_group;
    var arg_failure: r4os.arguments.Failure = .{};
    var cursor = r4_app.argCursor(.{ .quotes = 0, .max_bytes = 4096 }, &arg_failure) catch return 2;
    const token = (cursor.next() catch return 2);
    const first_arg = if (token) |value| value.bytes(r4_app.args()) catch return 2 else "";
    // The PUT grammar owns its comma-separated path, including spaces.
    const args = if (startsWithIgnoreCase(first_arg, "/BENCHPUT=")) std.mem.trim(u8, r4_app.args(), " \t") else first_arg;
    if (!startsWithIgnoreCase(first_arg, "/BENCHPUT=") and (cursor.next() catch return 2) != null) {
        app.sys.println("NETR4P: expected one option");
        return 2;
    }
    if (equalsIgnoreCase(args, "/SERVERPROBE=UPDATES")) return serverProbe(r4_app, &app, .updates);
    if (equalsIgnoreCase(args, "/SERVERPROBE=BENCHMARKS")) return serverProbe(r4_app, &app, .benchmarks);
    if (equalsIgnoreCase(args, "/SERVERREGISTER=UPDATES")) return serverRegister(r4_app, &app, .updates);
    if (equalsIgnoreCase(args, "/SERVERREGISTER=BENCHMARKS")) return serverRegister(r4_app, &app, .benchmarks);
    if (equalsIgnoreCase(args, "/SERVERACCESS=UPDATES")) return serverAccess(r4_app, &app, .updates);
    if (equalsIgnoreCase(args, "/SERVERACCESS=BENCHMARKS")) return serverAccess(r4_app, &app, .benchmarks);
    if (equalsIgnoreCase(args, "/UPDATESEARCH")) return updateSearch(r4_app, &app);
    if (equalsIgnoreCase(args, "/BENCHREAD")) return benchmarkRead(r4_app, &app);
    if (startsWithIgnoreCase(args, "/BENCHPUT=")) return @import("benchmark_transfer.zig").run(r4_app, args["/BENCHPUT=".len..]);
    if (equalsIgnoreCase(args, "/TLSSELFTEST")) return tlsSelfTest(r4_app, &app);
    const selftest_mode = isSelfTestMode(args);
    const expected_missing = if (selftest_mode) null else expectedMissingRole(args);
    if (args.len != 0 and !selftest_mode and expected_missing == null) {
        app.sys.println("NETR4P: unknown option; use /SELFTEST or /EXPECT-MISSING=<network role>");
        return 2;
    }

    // DNS is lazy. Building a real independent R4P query activates it;
    // the DNS service family resolver alone does not exercise this module.
    if (selftest_mode and !activateDns(r4_app)) return 1;
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

fn activateDns(app: *r4os.App2) bool {
    const dev = app.devicesLowLevel() orelse return false;
    var query: r4os.abi.DnsOp = .{ .id = 0x0181, .name_len = 10 };
    @memcpy(query.name[0..10], "api81.test");
    var input: r4os.abi.ProtocolBuffer = .{ .data = &query, .len = @sizeOf(@TypeOf(query)), .capacity = @sizeOf(@TypeOf(query)) };
    var output: r4os.abi.ProtocolBuffer = .{};
    const rc = dev.protocolDispatch("net.dns", r4os.abi.dns_op_build_a_query, &input, &output);
    const expected = [_]u8{ 0x01, 0x81, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 5, 'a', 'p', 'i', '8', '1', 4, 't', 'e', 's', 't', 0, 0, 1, 0, 1 };
    const ok = rc == 0 and query.result == 0 and query.payload_len == expected.len and std.mem.eql(u8, query.payload[0..expected.len], &expected);
    app.system().println(if (ok) "NETR4P DNS query bytes: OK" else "NETR4P DNS query bytes: FAILED");
    return ok;
}

fn tlsSelfTest(r4_app: *r4os.App2, app: *const App) i32 {
    const dev = r4_app.devicesLowLevel() orelse return 1;
    var input: [1]u8 = .{0};
    var output: [512]u8 = undefined;
    const request = r4os.abi.ProtocolBuffer{ .data = &input, .len = 0, .capacity = input.len };
    var result = r4os.abi.ProtocolBuffer{ .data = &output, .len = 0, .capacity = output.len };
    const rc = dev.protocolDispatch("security.tls", 3, &request, &result);
    const expected = "R4TLS selftest OK;live=ok;client=ok;x509=ok;app_write=ok;app_read=ok";
    const ok = rc == 0 and result.len <= output.len and std.mem.eql(u8, output[0..result.len], expected);
    app.sys.write("NETR4P TLS selftest: ");
    app.sys.write(if (ok) "OK" else "FAILED");
    app.sys.write(" rc=");
    app.sys.printI32(rc);
    app.sys.println("");
    return if (ok) 0 else 1;
}

fn serverProbe(r4_app: *r4os.App2, app: *const App, component: r4os.server_targets.Component) i32 {
    const profile = r4os.server_profile.load(&app.sys) catch |err| {
        app.sys.write("NETR4P server profile: ");
        app.sys.println(@errorName(err));
        return 1;
    };
    const target = r4os.server_targets.read(&app.sys, component) catch |err| {
        app.sys.write("NETR4P server target: ");
        app.sys.println(@errorName(err));
        return 1;
    };
    var url_buffer: [96]u8 = undefined;
    const url = std.fmt.bufPrint(&url_buffer, "https://{s}:{d}/api/health", .{ target.host(), target.port }) catch return 1;
    var web = r4_app.web() orelse {
        app.sys.println("NETR4P server probe: web unavailable");
        return 1;
    };
    var raw_response: [4096]u8 = undefined;
    var body: [1024]u8 = undefined;
    var tls_scratch: [r4os.app_web.tls_scratch_bytes]u8 = undefined;
    const result = web.fetch(url, &raw_response, &body, &tls_scratch, .{
        .redirect = .error_mode,
        .redirect_limit = 0,
    });
    app.sys.write("NETR4P server probe ");
    app.sys.write(if (component == .updates) "updates " else "benchmarks ");
    app.sys.write(if (profile == .public) "PUBLIC " else "LAN ");
    app.sys.write(target.host());
    app.sys.write(":");
    app.sys.printU64(target.port);
    app.sys.write(" ");
    switch (result) {
        .response => |response| {
            app.sys.write("HTTP ");
            app.sys.printI32(response.status);
            app.sys.println(if (response.secure) " TLS" else " plaintext");
            return if (response.status == 200 and response.secure) 0 else 1;
        },
        .failure => |failure| {
            app.sys.println(@tagName(failure));
            return 1;
        },
    }
}

fn serverRegister(r4_app: *r4os.App2, app: *const App, component: r4os.server_targets.Component) i32 {
    const profile = r4os.server_profile.load(&app.sys) catch |err| {
        app.sys.write("NETR4P server profile: ");
        app.sys.println(@errorName(err));
        return 1;
    };
    const target = r4os.server_targets.read(&app.sys, component) catch |err| {
        app.sys.write("NETR4P server target: ");
        app.sys.println(@errorName(err));
        return 1;
    };
    var secret = r4os.server_credentials.load(&app.sys, .registration) catch |err| {
        app.sys.write("NETR4P server credentials: ");
        app.sys.println(@errorName(err));
        return 1;
    };
    defer secret.clear();
    var web = r4_app.web() orelse {
        app.sys.println("NETR4P server registration: web unavailable");
        return 1;
    };
    var scratch: [r4os.app_web.tls_scratch_bytes]u8 = undefined;
    const timeout = r4os.time_contract.timeoutFinite(r4os.time_contract.durationFromNanoseconds(8_000_000_000));
    const result = web.registerServer(.{
        .address = target.ip,
        .hostname = target.host(),
        .port = r4os.server_targets.registration_port,
        .tls = profile.registrationUsesTls(),
    }, secret.bytes(), &scratch, timeout);
    app.sys.write("NETR4P server registration ");
    app.sys.write(if (component == .updates) "updates " else "benchmarks ");
    app.sys.write(if (profile == .public) "PUBLIC " else "LAN ");
    switch (result) {
        .accepted => {
            app.sys.println("OK");
            return 0;
        },
        .invalid_secret => app.sys.println("InvalidSecret"),
        .invalid_reply => app.sys.println("InvalidReply"),
        .failure => |failure| app.sys.println(@tagName(failure)),
    }
    return 1;
}

fn serverAccess(r4_app: *r4os.App2, app: *const App, component: r4os.server_targets.Component) i32 {
    const services = r4_app.services() orelse {
        app.sys.println("NETR4P R4SRV: service API unavailable");
        return 1;
    };
    const client = r4os.server_access.Client{ .services = services };
    const result = client.ensure(component);
    app.sys.write("NETR4P R4SRV ");
    app.sys.write(if (component == .updates) "updates " else "benchmarks ");
    switch (result) {
        .response => |response| {
            app.sys.write("code=");
            app.sys.printI32(response.code);
            app.sys.write(" attempted=");
            app.sys.printU64(response.attempted);
            app.sys.write(" generation=");
            app.sys.printU64(response.generation);
            app.sys.println("");
            return if (response.code == @intFromEnum(r4os.server_access.Code.ok)) 0 else 1;
        },
        .unavailable => |raw| {
            app.sys.write("unavailable rc=");
            app.sys.printI32(raw);
        },
        .timed_out => app.sys.write("timed_out"),
        .malformed => app.sys.write("malformed"),
    }
    app.sys.println("");
    return 1;
}

fn updateSearch(r4_app: *r4os.App2, app: *const App) i32 {
    const services = r4_app.services() orelse return 1;
    var connection = switch (services.open(update_contract.service_name)) {
        .connection => |value| value,
        .failure => |raw| {
            app.sys.write("NETR4P update search: service unavailable rc=");
            app.sys.printI32(raw);
            app.sys.println("");
            return 1;
        },
    };
    defer _ = connection.close();
    const timeout = r4os.time_contract.timeoutFinite(r4os.time_contract.durationFromNanoseconds(5_000_000_000));
    const submit = update_contract.CommandRequest{};
    const ack = switch (connection.callTyped(update_contract.CommandRequest, update_contract.Ack, update_contract.op_search, &submit, timeout)) {
        .value => |value| value,
        else => {
            app.sys.println("NETR4P update search: submit failed");
            return 1;
        },
    };
    if (!ack.valid() or ack.result != update_contract.result_ok or ack.job_id == 0) {
        app.sys.println("NETR4P update search: rejected");
        return 1;
    }
    const deadline = app.sys.ticks() +| app.sys.ticksFromMilliseconds(45_000);
    while (app.sys.ticks() < deadline) {
        const request = update_contract.StatusRequest{ .job_id = ack.job_id };
        const status = switch (connection.callTyped(update_contract.StatusRequest, update_contract.Status, update_contract.op_status, &request, timeout)) {
            .value => |value| value,
            else => {
                app.sys.println("NETR4P update search: status failed");
                return 1;
            },
        };
        if (!status.valid() or status.job_id != ack.job_id) {
            app.sys.println("NETR4P update search: malformed status");
            return 1;
        }
        if (status.state == @intFromEnum(update_contract.State.up_to_date) or
            status.state == @intFromEnum(update_contract.State.available) or
            status.state == @intFromEnum(update_contract.State.failed))
        {
            app.sys.write("NETR4P update search: state=");
            app.sys.printU64(status.state);
            app.sys.write(" result=");
            app.sys.printI32(status.result);
            app.sys.write(" packages=");
            app.sys.printU64(status.package_count);
            app.sys.write(" reason=");
            app.sys.println(status.reasonText());
            return if (status.result == update_contract.result_ok and
                status.state != @intFromEnum(update_contract.State.failed)) 0 else 1;
        }
        app.sys.sleepTicks(5);
    }
    app.sys.println("NETR4P update search: timeout");
    return 1;
}

fn benchmarkRead(r4_app: *r4os.App2, app: *const App) i32 {
    const services = r4_app.services() orelse return 1;
    const client = r4os.server_access.Client{ .services = services };
    const target = switch (client.ensure(.benchmarks)) {
        .response => |value| value,
        else => {
            app.sys.println("NETR4P benchmark read: registration unavailable");
            return 1;
        },
    };
    if (target.code != @intFromEnum(r4os.server_access.Code.ok) or target.port == 0) {
        app.sys.write("NETR4P benchmark read: registration code=");
        app.sys.printI32(target.code);
        app.sys.println("");
        return 1;
    }
    var url_buffer: [96]u8 = undefined;
    const url = std.fmt.bufPrint(&url_buffer, "https://{d}.{d}.{d}.{d}:{d}/api/v1/hosts", .{
        target.target_ip[0], target.target_ip[1], target.target_ip[2], target.target_ip[3], target.port,
    }) catch return 1;
    var web = r4_app.web() orelse return 1;
    var raw_response: [16 * 1024]u8 = undefined;
    var body: [16 * 1024]u8 = undefined;
    var scratch: [r4os.app_web.tls_scratch_bytes]u8 = undefined;
    const result = web.fetch(url, &raw_response, &body, &scratch, .{
        .redirect = .error_mode,
        .redirect_limit = 0,
        .headers = "accept:application/json\n",
    });
    switch (result) {
        .response => |response| {
            const trimmed = std.mem.trim(u8, response.body, " \t\r\n");
            app.sys.write("NETR4P benchmark read: HTTP ");
            app.sys.printU64(response.status);
            app.sys.write(" TLS=");
            app.sys.printU64(@intFromBool(response.secure));
            app.sys.write(" bytes=");
            app.sys.printU64(response.body.len);
            app.sys.write(" registration_attempted=");
            app.sys.printU64(target.attempted);
            app.sys.write(" generation=");
            app.sys.printU64(target.generation);
            app.sys.println("");
            return if (response.status == 200 and response.secure and trimmed.len > 0 and trimmed[0] == '{') 0 else 1;
        },
        .failure => |failure| {
            app.sys.write("NETR4P benchmark read: ");
            app.sys.println(@tagName(failure));
            return 1;
        },
    }
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
        else => unreachable,
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
        else => unreachable,
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
