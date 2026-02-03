-- https://wiki.wireshark.org/LuaAPI
-- https://www.cnblogs.com/zzqcn/p/4827337.html#_label1_2
-- https://www.wireshark.org/docs/wsdg_html_chunked/wsluarm_modules.html
-- adb message dissector

-- =============================================================================
-- CONSTANTS
-- =============================================================================

local ADB_HEADER_SIZE = 24

-- ADB Commands (ASCII strings)
local CMD = {
    CNXN = "CNXN",  -- Connection
    AUTH = "AUTH",  -- Authentication
    STLS = "STLS",  -- TLS upgrade (API >= 29)
    OPEN = "OPEN",  -- Open stream
    OKAY = "OKAY",  -- Ready
    CLSE = "CLSE",  -- Close
    WRTE = "WRTE",  -- Write
    SYNC = "SYNC",  -- Obsolete
}

-- Command to expected magic (command ^ 0xFFFFFFFF)
local CMD_MAGIC = {
    CNXN = 0xb0b1b2b3,  -- Placeholder, calculated dynamically
}

-- AUTH types
local AUTH_TYPE = {
    [1] = "TOKEN",
    [2] = "SIGNATURE",
    [3] = "RSAPUBLICKEY",
}

-- Sync protocol commands
local SYNC_CMD = {
    ["STAT"] = true, ["LIST"] = true, ["SEND"] = true, ["RECV"] = true,
    ["DATA"] = true, ["DONE"] = true, ["OKAY"] = true, ["FAIL"] = true,
    ["DENT"] = true, ["QUIT"] = true,
    ["STA2"] = true, ["LST2"] = true, ["SND2"] = true, ["RCV2"] = true,
}

-- =============================================================================
-- PROTOCOL FIELDS
-- =============================================================================

-- Header fields
local pf_command     = ProtoField.string("adb2.command", "Command")
local pf_arg0        = ProtoField.uint32("adb2.arg0", "Arg0", base.HEX)
local pf_arg1        = ProtoField.uint32("adb2.arg1", "Arg1", base.HEX)
local pf_data_len    = ProtoField.uint32("adb2.data_len", "Data Length", base.DEC)
local pf_crc         = ProtoField.uint32("adb2.crc", "Data Checksum", base.HEX)
local pf_magic       = ProtoField.uint32("adb2.magic", "Magic", base.HEX)
local pf_data        = ProtoField.bytes("adb2.data", "Data")
local pf_data_string = ProtoField.string("adb2.data_string", "Data (String)")

-- CNXN fields
local pf_cnxn_version  = ProtoField.uint32("adb2.cnxn.version", "Version", base.HEX)
local pf_cnxn_maxdata  = ProtoField.uint32("adb2.cnxn.maxdata", "Max Data", base.DEC)
local pf_cnxn_sysident = ProtoField.string("adb2.cnxn.sysident", "System Identity")
local pf_cnxn_type     = ProtoField.string("adb2.cnxn.type", "Device Type")
local pf_cnxn_serial   = ProtoField.string("adb2.cnxn.serial", "Serial")
local pf_cnxn_banner   = ProtoField.string("adb2.cnxn.banner", "Banner")

-- AUTH fields
local pf_auth_type    = ProtoField.uint32("adb2.auth.type", "Auth Type", base.DEC)
local pf_auth_payload = ProtoField.bytes("adb2.auth.payload", "Auth Payload")

-- STLS fields
local pf_stls_type    = ProtoField.uint32("adb2.stls.type", "TLS Type", base.DEC)
local pf_stls_version = ProtoField.uint32("adb2.stls.version", "TLS Version", base.HEX)

-- OPEN fields
local pf_open_localid = ProtoField.uint32("adb2.open.local_id", "Local ID", base.HEX)
local pf_open_dest    = ProtoField.string("adb2.open.destination", "Destination")
local pf_open_service = ProtoField.string("adb2.open.service", "Service")

-- Stream fields
local pf_local_id     = ProtoField.uint32("adb2.local_id", "Local ID", base.HEX)
local pf_remote_id    = ProtoField.uint32("adb2.remote_id", "Remote ID", base.HEX)

-- Shell fields
local pf_shell_cmd    = ProtoField.string("adb2.shell.command", "Shell Command")

-- Sync fields
local pf_sync_cmd     = ProtoField.string("adb2.sync.command", "Sync Command")
local pf_sync_length  = ProtoField.uint32("adb2.sync.length", "Sync Length", base.DEC)
local pf_sync_path    = ProtoField.string("adb2.sync.path", "Path")

-- Data fragment
local pf_length_desc  = ProtoField.string("adb2.length_desc", "Length")

-- =============================================================================
-- PROTOCOL DEFINITION
-- =============================================================================

local adb = Proto("adb2", "ADB Message")
adb.fields = {
    pf_command, pf_arg0, pf_arg1, pf_data_len, pf_crc, pf_magic,
    pf_data, pf_data_string,
    pf_cnxn_version, pf_cnxn_maxdata, pf_cnxn_sysident,
    pf_cnxn_type, pf_cnxn_serial, pf_cnxn_banner,
    pf_auth_type, pf_auth_payload,
    pf_stls_type, pf_stls_version,
    pf_open_localid, pf_open_dest, pf_open_service,
    pf_local_id, pf_remote_id,
    pf_shell_cmd,
    pf_sync_cmd, pf_sync_length, pf_sync_path,
    pf_length_desc,
}

-- =============================================================================
-- HELPER FUNCTIONS
-- =============================================================================

--- XOR for magic validation (Lua 5.1 compatible)
local function bxor(a, b)
    local r = 0
    for i = 0, 31 do
        local x = a / 2 + b / 2
        if x ~= math.floor(x) then
            r = r + 2^i
        end
        a = math.floor(a / 2)
        b = math.floor(b / 2)
    end
    return r
end

--- Convert 4-byte string to little-endian uint32
local function str_to_le_uint32(s)
    return string.byte(s,1) + string.byte(s,2)*256 +
           string.byte(s,3)*65536 + string.byte(s,4)*16777216
end

--- Check if string is printable ASCII
local function is_printable(s)
    if not s or #s == 0 then return false end
    for i = 1, math.min(#s, 100) do
        local c = string.byte(s, i)
        if c ~= 0 and (c < 32 or c > 126) and c ~= 10 and c ~= 13 and c ~= 9 then
            return false
        end
    end
    return true
end

--- Parse CNXN system identity: "type:serial:banner"
local function parse_sysident(s)
    if not s then return nil end
    s = s:gsub("%z", "")
    local parts = {}
    for p in s:gmatch("[^:]+") do table.insert(parts, p) end
    return {
        type = parts[1] or "",
        serial = parts[2] or "",
        banner = parts[3] or "",
    }
end

--- Extract shell command from destination
local function extract_shell_cmd(dest)
    if not dest then return nil end
    dest = dest:gsub("%z", "")

    -- shell:command
    if dest:match("^shell:") then
        return dest:sub(7)
    end
    -- shell,v2,...:command or shell,v2,...:raw:command
    if dest:match("^shell,") then
        return dest:match(":raw:(.+)$") or dest:match(":([^,]+)$")
    end
    -- exec:command
    if dest:match("^exec:") then
        return dest:sub(6)
    end
    return nil
end

--- Get service type from destination
local function get_service_type(dest)
    if not dest then return "unknown" end
    dest = dest:gsub("%z", "")

    local patterns = {
        {"^shell[,:]", "shell"},
        {"^exec[,:]", "exec"},
        {"^sync:", "sync"},
        {"^tcp:%d", "tcp"},
        {"^udp:%d", "udp"},
        {"^local:", "local"},
        {"^localabstract:", "localabstract"},
        {"^localfilesystem:", "localfilesystem"},
        {"^jdwp:%d", "jdwp"},
        {"^track%-jdwp", "track-jdwp"},
        {"^track%-app", "track-app"},
        {"^framebuffer:", "framebuffer"},
        {"^remount:", "remount"},
        {"^reverse:", "reverse"},
        {"^abb[,:]", "abb"},
        {"^abb_exec:", "abb_exec"},
    }

    for _, p in ipairs(patterns) do
        if dest:match(p[1]) then return p[2] end
    end
    return dest:match("^([^:,]+)") or "unknown"
end

--- Detect sync protocol in data
local function detect_sync(data_str)
    if not data_str or #data_str < 4 then return nil end
    local cmd = data_str:sub(1, 4)
    return SYNC_CMD[cmd] and cmd or nil
end

-- =============================================================================
-- MAIN DISSECTOR
-- =============================================================================

function adb.dissector(tvb, pinfo, tree)
    -- Skip USB Mass Storage
    if tvb:len() >= 3 and tvb(0, 3):string() == "USB" then
        return
    end

    -- Check minimum length
    if tvb:len() < ADB_HEADER_SIZE then
        -- Data fragment
        local t = tree:add(adb, tvb())
        local actual_len = tvb:reported_len()
        pinfo.cols.protocol = "ADBData"

        local dir = ""
        if pinfo.port_type == 2 then
            pinfo.cols.info = string.format("%s→%s %d bytes", pinfo.src_port, pinfo.dst_port, actual_len)
        else
            dir = tostring(pinfo.src) == "host" and ">>>" or "<<<"
            pinfo.cols.info = string.format("%s %d bytes", dir, actual_len)
        end

        t:add(pf_length_desc, string.format("%d [%d captured]", actual_len, tvb:len()))
        t:add(pf_data, tvb())
        return
    end

    -- Parse header
    local v_cmd_str = tvb(0, 4):string()
    local v_arg0 = tvb(4, 4):le_uint()
    local v_arg1 = tvb(8, 4):le_uint()
    local v_datalen = tvb(12, 4):le_uint()
    local v_crc = tvb(16, 4):le_uint()
    local v_magic = tvb(20, 4):le_uint()

    -- Validate command
    local valid_cmds = {CNXN=1, AUTH=1, STLS=1, OPEN=1, OKAY=1, CLSE=1, WRTE=1, SYNC=1}
    if not valid_cmds[v_cmd_str] then
        -- Not a valid ADB header, treat as data
        local t = tree:add(adb, tvb())
        local actual_len = tvb:reported_len()
        pinfo.cols.protocol = "ADBData"

        local dir = tostring(pinfo.src) == "host" and ">>>" or "<<<"
        pinfo.cols.info = string.format("%s %d bytes", dir, actual_len)

        -- Check for shell/sync data patterns
        local data_str = tvb():string()
        if is_printable(data_str) then
            t:add(pf_data_string, tvb(), data_str)
            local shell_cmd = extract_shell_cmd(data_str)
            if shell_cmd then
                t:add(pf_shell_cmd, shell_cmd)
                pinfo.cols.info = string.format("%s shell: %s", dir, shell_cmd:sub(1, 40))
            end
        else
            t:add(pf_data, tvb())
        end
        return
    end

    -- Validate magic
    local v_cmd_uint = str_to_le_uint32(v_cmd_str)
    local expected_magic = bxor(v_cmd_uint, 0xFFFFFFFF)
    local magic_valid = (v_magic == expected_magic)

    -- Build tree
    local t = tree:add(adb, tvb())
    pinfo.cols.protocol = "ADB"

    -- Header fields
    local cmd_item = t:add(pf_command, tvb(0, 4))
    cmd_item:set_text("Command: " .. v_cmd_str)

    local magic_item = t:add_le(pf_magic, tvb(20, 4))
    if not magic_valid then
        magic_item:add_expert_info(PI_MALFORMED, PI_ERROR,
            string.format("Invalid magic: expected 0x%08X", expected_magic))
    end

    t:add_le(pf_data_len, tvb(12, 4))

    local crc_item = t:add_le(pf_crc, tvb(16, 4))

    -- Direction
    local dir = ""
    if pinfo.port_type ~= 2 then
        dir = tostring(pinfo.src) == "host" and ">>> " or "<<< "
    end

    -- Command-specific parsing
    local info = dir .. v_cmd_str

    if v_cmd_str == CMD.CNXN then
        -- CNXN: arg0=version, arg1=maxdata
        local ver_item = t:add_le(pf_cnxn_version, tvb(4, 4))
        if v_arg0 == 0x01000000 then
            ver_item:append_text(" (v1.0.0)")
        end

        local max_item = t:add_le(pf_cnxn_maxdata, tvb(8, 4))
        if v_arg1 >= 256*1024 then
            max_item:append_text(" (modern)")
        elseif v_arg1 <= 4096 then
            max_item:append_text(" (legacy)")
        end

        -- Parse system identity
        if v_datalen > 0 and tvb:len() >= 24 + v_datalen then
            local sysident_str = tvb(24, v_datalen):string()
            t:add(pf_cnxn_sysident, tvb(24, v_datalen), sysident_str)

            local parsed = parse_sysident(sysident_str)
            if parsed.type ~= "" then
                t:add(pf_cnxn_type, parsed.type)
                info = info .. " " .. parsed.type
            end
            if parsed.serial ~= "" then
                t:add(pf_cnxn_serial, parsed.serial)
            end
            if parsed.banner ~= "" then
                t:add(pf_cnxn_banner, parsed.banner)
            end
        end

    elseif v_cmd_str == CMD.AUTH then
        -- AUTH: arg0=type (1=TOKEN, 2=SIGNATURE, 3=RSAPUBLICKEY)
        local type_item = t:add_le(pf_auth_type, tvb(4, 4))
        local type_name = AUTH_TYPE[v_arg0] or "UNKNOWN"
        type_item:set_text("Auth Type: " .. v_arg0 .. " (" .. type_name .. ")")
        info = info .. " " .. type_name

        if v_datalen > 0 and tvb:len() >= 24 + v_datalen then
            t:add(pf_auth_payload, tvb(24, v_datalen))
        end

    elseif v_cmd_str == CMD.STLS then
        -- STLS: arg0=type, arg1=version
        t:add_le(pf_stls_type, tvb(4, 4))
        t:add_le(pf_stls_version, tvb(8, 4))
        info = info .. string.format(" v%d.%d", math.floor(v_arg1/65536), v_arg1 % 65536)

    elseif v_cmd_str == CMD.OPEN then
        -- OPEN: arg0=local_id, arg1=0
        local lid_item = t:add_le(pf_open_localid, tvb(4, 4))
        if v_arg0 == 0 then
            lid_item:add_expert_info(PI_PROTOCOL, PI_WARN, "Local ID must not be 0")
        end

        if v_datalen > 0 and tvb:len() >= 24 + v_datalen then
            local dest = tvb(24, v_datalen):string()
            t:add(pf_open_dest, tvb(24, v_datalen), dest)

            local service = get_service_type(dest)
            t:add(pf_open_service, service)

            local shell_cmd = extract_shell_cmd(dest)
            if shell_cmd then
                t:add(pf_shell_cmd, shell_cmd)
                info = info .. " shell: " .. shell_cmd:sub(1, 40)
            else
                info = info .. " " .. dest:gsub("%z", ""):sub(1, 50)
            end
        end

    elseif v_cmd_str == CMD.OKAY then
        -- OKAY: arg0=local_id, arg1=remote_id
        t:add_le(pf_local_id, tvb(4, 4))
        t:add_le(pf_remote_id, tvb(8, 4))
        info = string.format("%s%s L=%08X R=%08X", dir, v_cmd_str, v_arg0, v_arg1)

    elseif v_cmd_str == CMD.CLSE then
        -- CLSE: arg0=local_id, arg1=remote_id
        t:add_le(pf_local_id, tvb(4, 4))
        t:add_le(pf_remote_id, tvb(8, 4))
        info = string.format("%s%s L=%08X R=%08X", dir, v_cmd_str, v_arg0, v_arg1)

    elseif v_cmd_str == CMD.WRTE then
        -- WRTE: arg0=local_id, arg1=remote_id
        t:add_le(pf_local_id, tvb(4, 4))
        t:add_le(pf_remote_id, tvb(8, 4))

        if v_datalen > 0 and tvb:len() >= 24 + v_datalen then
            local payload = tvb(24, v_datalen)
            t:add(pf_data, payload)

            local data_str = payload:string()

            -- Check for sync protocol
            local sync_cmd = detect_sync(data_str)
            if sync_cmd then
                t:add(pf_sync_cmd, sync_cmd)
                if v_datalen >= 8 then
                    local sync_len = tvb(28, 4):le_uint()
                    t:add_le(pf_sync_length, tvb(28, 4))
                    if v_datalen >= 8 + sync_len and sync_len > 0 then
                        local path = tvb(32, sync_len):string()
                        t:add(pf_sync_path, tvb(32, sync_len), path)
                        info = info .. " sync:" .. sync_cmd .. " " .. path
                    else
                        info = info .. " sync:" .. sync_cmd
                    end
                end
            elseif is_printable(data_str) then
                t:add(pf_data_string, payload, data_str)
                local shell_cmd = extract_shell_cmd(data_str)
                if shell_cmd then
                    t:add(pf_shell_cmd, shell_cmd)
                    info = info .. " shell: " .. shell_cmd:sub(1, 40)
                else
                    info = info .. " " .. data_str:gsub("%z", ""):sub(1, 40)
                end
            else
                info = info .. string.format(" (%d bytes)", v_datalen)
            end
        end
    else
        -- Generic parsing for other commands
        t:add_le(pf_arg0, tvb(4, 4))
        t:add_le(pf_arg1, tvb(8, 4))
    end

    -- Validate checksum if we have payload
    if v_datalen > 0 and tvb:len() >= 24 + v_datalen then
        local calc_crc = 0
        for i = 24, 24 + v_datalen - 1 do
            calc_crc = calc_crc + tvb(i, 1):uint()
        end
        if calc_crc ~= v_crc then
            crc_item:add_expert_info(PI_CHECKSUM, PI_WARN,
                string.format("Checksum mismatch: calculated 0x%08X", calc_crc))
        end
    end

    pinfo.cols.info = info
end

-- =============================================================================
-- HEURISTIC DISSECTOR
-- =============================================================================

local function heur_dissect_adb(tvb, pinfo, tree)
    if tvb:len() < ADB_HEADER_SIZE then
        return false
    end

    -- Check for valid command
    local cmd_str = tvb(0, 4):string()
    local valid_cmds = {CNXN=1, AUTH=1, STLS=1, OPEN=1, OKAY=1, CLSE=1, WRTE=1}
    if not valid_cmds[cmd_str] then
        return false
    end

    -- Validate magic
    local cmd_uint = str_to_le_uint32(cmd_str)
    local magic = tvb(20, 4):le_uint()
    local expected = bxor(cmd_uint, 0xFFFFFFFF)

    if magic == expected then
        adb.dissector(tvb, pinfo, tree)
        return true
    end

    return false
end

-- =============================================================================
-- REGISTRATION
-- =============================================================================

-- Register heuristic for USB bulk transfers
adb:register_heuristic("usb.bulk", heur_dissect_adb)

-- Keep direct port binding for backward compatibility (but narrower range)
DissectorTable.get("tcp.port"):add(5555, adb)  -- Default ADB port
DissectorTable.get("usb.device"):add("65536-65792", adb)