const std = @import("std");
const r4os = @import("r4os");

const max_path = 260;
const max_body = 64 * 1024 * 1024;
const Kind = enum { host, spectra, snes };
const Request = struct { kind: Kind, id: []const u8, path: []const u8 };

pub fn run(app: *r4os.App, args: []const u8) i32 {
    const sys = app.system();
    const request = parse(args) orelse {
        sys.println("NETR4P benchmark PUT: use /BENCHPUT=HOST|SPECTRA|SNES,ID,ABSOLUTE_PATH");
        return 2;
    };
    var source = FileSource{ .sys = sys };
    @memcpy(source.path[0..request.path.len], request.path);
    source.path_len = request.path.len;
    var info: r4os.abi.FileInfo = .{};
    const found = sys.fileInfoRaw(source.path[0..source.path_len :0].ptr, &info);
    if (found <= 0 or info.exists == 0 or info.is_dir != 0 or info.size == 0 or info.size > max_body) {
        sys.println("NETR4P benchmark PUT: file missing or outside size limit");
        return 1;
    }
    const services = app.services() orelse return fail(&sys, "service API unavailable");
    const client = r4os.server_access.Client{ .services = services };
    const target = switch (client.ensure(.benchmarks)) {
        .response => |value| value,
        else => return fail(&sys, "registration unavailable"),
    };
    if (target.code != @intFromEnum(r4os.server_access.Code.ok) or target.port == 0)
        return fail(&sys, "registration rejected");
    var bearer = r4os.server_credentials.load(&sys, .benchmark_bearer) catch return fail(&sys, "benchmark bearer missing or invalid");
    defer bearer.clear();
    var authorization: [320]u8 = undefined;
    defer std.crypto.secureZero(u8, &authorization);
    const headers = std.fmt.bufPrint(&authorization, "Authorization: Bearer {s}\n", .{bearer.bytes()}) catch return 1;
    var url_buffer: [200]u8 = undefined;
    const collection = switch (request.kind) {
        .host => "hosts",
        .spectra => "benchmark-runs",
        .snes => "subsystem-benchmark-runs",
    };
    const url = std.fmt.bufPrint(&url_buffer, "https://{d}.{d}.{d}.{d}:{d}/api/v1/{s}/{s}", .{
        target.target_ip[0], target.target_ip[1], target.target_ip[2], target.target_ip[3], target.port, collection, request.id,
    }) catch return 1;
    var web = app.web() orelse return fail(&sys, "web transport unavailable");
    var response_headers: [r4os.http.max_header_bytes]u8 = undefined;
    var io: [16 * 1024]u8 = undefined;
    var upload: [8 * 1024]u8 = undefined;
    var tls: [r4os.app_web.tls_scratch_bytes]u8 = undefined;
    var response = ResponseSink{};
    var stream: r4os.app_web.PostStream = undefined;
    const timeout = r4os.time_contract.timeoutFinite(r4os.time_contract.durationFromNanoseconds(90_000_000_000));
    var report = stream.init(&web, url, .{ .headers = &response_headers, .io = &io, .upload = &upload, .tls = &tls }, .{ .context = &response, .write = ResponseSink.write }, .{
        .request = .{ .method = .put, .redirect = .manual, .timeout = timeout, .headers = headers, .content_type = "application/json" },
        .request_length = info.size,
        .reader = FileSource.read,
        .reader_context = &source,
    });
    defer {
        if (!stream.canRelease()) _ = stream.close(timeout);
        std.crypto.secureZero(u8, &stream.headers);
    }
    if (report.state == .failed or report.state == .cancelled) return fail(&sys, "stream initialization failed");
    while (report.state == .ready or report.state == .paused) report = stream.run();
    const closed = stream.canRelease() or stream.close(timeout);
    sys.write("NETR4P benchmark PUT ");
    sys.write(switch (request.kind) {
        .host => "host ",
        .spectra => "spectra ",
        .snes => "snes ",
    });
    sys.write(request.id);
    sys.write(" HTTP=");
    sys.printU64(report.status orelse 0);
    sys.write(" sent=");
    sys.printU64(report.request_body_confirmed);
    sys.write(" response_bytes=");
    sys.printU64(response.bytes);
    sys.write(" closed=");
    sys.printU64(@intFromBool(closed));
    sys.println("");
    return if (report.state == .complete and report.http_complete and closed and
        report.request_body_confirmed == info.size and (report.status == 200 or report.status == 201)) 0 else 1;
}

const FileSource = struct {
    sys: r4os.r4sys.Context,
    path: [max_path + 1]u8 = .{0} ** (max_path + 1),
    path_len: usize = 0,

    fn read(raw: ?*anyopaque, offset: u64, output: []u8) i64 {
        const self: *@This() = @ptrCast(@alignCast(raw orelse return -3));
        if (offset > std.math.maxInt(u32)) return -3;
        const count = self.sys.fileReadAt(self.path[0..self.path_len :0].ptr, @intCast(offset), output);
        return if (count < 0) -3 else count;
    }
};

const ResponseSink = struct {
    bytes: u64 = 0,
    fn write(raw: ?*anyopaque, offset: u64, chunk: []const u8) r4os.app_web.PostStreamAction {
        const self: *@This() = @ptrCast(@alignCast(raw orelse return .fail));
        if (offset != self.bytes) return .fail;
        self.bytes +|= chunk.len;
        return .accept;
    }
};

fn parse(args: []const u8) ?Request {
    var parts = std.mem.splitScalar(u8, args, ',');
    const kind_text = parts.next() orelse return null;
    const id = parts.next() orelse return null;
    const path = parts.next() orelse return null;
    if (parts.next() != null or path.len < 4 or path.len > max_path or path[1] != ':' or path[2] != '\\') return null;
    const kind: Kind = if (std.ascii.eqlIgnoreCase(kind_text, "HOST")) .host else if (std.ascii.eqlIgnoreCase(kind_text, "SPECTRA")) .spectra else if (std.ascii.eqlIgnoreCase(kind_text, "SNES")) .snes else return null;
    if (id.len == 0 or id.len > 64) return null;
    for (id) |ch| if (!((ch >= 'a' and ch <= 'z') or (ch >= '0' and ch <= '9') or ch == '_' or ch == '-')) return null;
    for (path) |ch| if (ch < 0x20 or ch == '"' or ch == '<' or ch == '>' or ch == '|') return null;
    return .{ .kind = kind, .id = id, .path = path };
}

fn fail(sys: *const r4os.r4sys.Context, why: []const u8) i32 {
    sys.write("NETR4P benchmark PUT: ");
    sys.println(why);
    return 1;
}
