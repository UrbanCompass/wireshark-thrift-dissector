-------------------------------------------------------------------------------
-- wireshark-thrift-dissector
-- This code is licensed under MIT license (see LICENSE for details)
--

-------------------------------------------------------------------------------
-------------------------------------------------------------------------------
--- lookup tables
local fieldtype_valstr = {}
fieldtype_valstr[0] = "STOP"
fieldtype_valstr[1] = "VOID"
fieldtype_valstr[2] = "BOOL"
fieldtype_valstr[3] = "BYTE"
fieldtype_valstr[4] = "DOUBLE"
fieldtype_valstr[6] = "I16"
fieldtype_valstr[8] = "I32"
fieldtype_valstr[10] = "I64"
fieldtype_valstr[11] = "STRING"
fieldtype_valstr[12] = "STRUCT"
fieldtype_valstr[13] = "MAP"
fieldtype_valstr[14] = "SET"
fieldtype_valstr[15] = "LIST"
fieldtype_valstr[16] = "UTF8"
fieldtype_valstr[17] = "UTF16"

-------------------------------------------------------------------------------
--- protocol constants
THRIFT_VERSION_MASK = -65536
THRIFT_VERSION_1 = -2147418112
THRIFT_HEADER_MAGIC = 0x0FFF
THRIFT_HEADER_TYPE_KV = 0x01
THRIFT_TYPE_MASK = 0x000000ff

-------------------------------------------------------------------------------
--- ThriftBuffer is a stateful buffer helper
ThriftBuffer = {}
function ThriftBuffer:new(buf)
    o = {
        pos = 0,
        buf = buf
    }
    setmetatable(o, self)
    self.__index = self
    return o
end

function ThriftBuffer:seek(pos)
    self.pos = pos
end

function ThriftBuffer:skip(num)
    self.pos = self.pos + num
end

function ThriftBuffer:__call(len)
    rv = self.buf(self.pos, len)
    self.pos = self.pos + len
    return rv
end

function ThriftBuffer:bool()
    local byte = self(1):int()
    return byte ~= 0
end

function ThriftBuffer:byte()
    return self(1):int()
end

function ThriftBuffer:double()
    return self(8):float()
end

function ThriftBuffer:i16()
    return self(2):int()
end

function ThriftBuffer:i32()
    return self(4):int()
end

function ThriftBuffer:i64()
    return self(8):int64()
end

function ThriftBuffer:varint()
    local res = 0
    local pos = 0
    while true do
        local b = self.buf(self.pos + pos, 1):int()
        res = bit32.bor(res, bit32.lshift(bit32.band(b, 0x7f), pos * 7))
        pos = pos + 1

        if bit32.rshift(b, 7) == 0 then
            self.pos = self.pos + pos
            return res
        end
    end
end

function ThriftBuffer:varstring()
    local size = self:varint()
    local rv = self.buf(self.pos, size):string()
    self.pos = self.pos + size
    return rv
end

function ThriftBuffer:string()
    local size = self(4):int()
    local val = self(size):string()
    return val
end

local fieldtype_readers = {
    BOOL = ThriftBuffer.bool,
    BYTE = ThriftBuffer.byte,
    DOUBLE = ThriftBuffer.double,
    I16 = ThriftBuffer.i16,
    I32 = ThriftBuffer.i32,
    I64 = ThriftBuffer.i64,
    STRING = ThriftBuffer.string,
}

-------------------------------------------------------------------------------
--- decodes a series of thrift fields until the STOP sentinel is reached
function decode_tfields(buf, tree)
    if buf:len() == 0 then
        return 0
    end

    local tbuf = ThriftBuffer:new(buf)
    local type = fieldtype_valstr[tbuf(1):int()]

    while type ~= nil and type ~= "STOP" do
        id = tbuf(2):int()
        local pos = tbuf.pos
        if type == "VOID" then
            tree:add(id, "Type: VOID")
        elseif type == "BOOL" then
            local val = tbuf:bool()
            tree:add(buf(pos, 1), id, "Type: BOOL", string.format("%s", val))
        elseif type == "BYTE" then
            local val = tbuf:byte()
            tree:add(buf(pos, 1), id, "Type: BYTE", val)
        elseif type == "DOUBLE" then
            local val = tbuf:double()
            tree:add(buf(pos, 8), id, "Type: DOUBLE", val)
        elseif type == "I16" then
            local val = tbuf:i16()
            tree:add(buf(pos, 2), id, "Type: I16", val)
        elseif type == "I32" then
            local val = tbuf:i32()
            tree:add(buf(pos, 4), id, "Type: I32", val)
        elseif type == "I64" then
            local val = tbuf:i64()
            tree:add(buf(pos, 8), id, "Type: I64", string.format("%s", val))
        elseif type == "STRING" then
            local size = tbuf(4):int()
            local val = tbuf(size):string()
            tree:add(buf(pos, 4+size), id, "Type: STRING", val)
        elseif type == "STRUCT" then
            local child_tree = tree:add(id, "Type: STRUCT")
            local len = decode_tfields(buf(pos, buf:len() - pos), child_tree)
            tbuf:skip(len)
        elseif type == "MAP" then
            local ktype = tbuf(1):int()
            local vtype = tbuf(1):int()
            local size = tbuf(4):int()
            local ktype_str = fieldtype_valstr[ktype]
            local vtype_str = fieldtype_valstr[vtype]

            if ktype_str ~= nil and vtype_str ~= nil then
                local child_tree = tree:add(id, "Type: MAP" .. string.format("<%s, %s>", ktype_str, vtype_str))
                local kreader = fieldtype_readers[ktype_str]
                for i = 1, size do
                    fieldpos = tbuf.pos
                    key = kreader(tbuf)
                    -- TODO(eac): make handling non-scalars more elegant
                    if vtype_str == "STRUCT" then
                        local elem_tree = child_tree:add(i, key)
                        child_buf = tbuf.buf(tbuf.pos)
                        local len = decode_tfields(child_buf, elem_tree)
                        tbuf:skip(len)
                    else
                        local vreader = fieldtype_readers[vtype_str]
                        val = vreader(tbuf)
                        child_tree:add(buf(fieldpos, tbuf.pos-fieldpos), key, val)
                    end
                end
            end
        elseif type == "SET" or type == "LIST" then
            local etype = tbuf(1):int()
            local size = tbuf(4):int()
            local etype_str = fieldtype_valstr[etype]
            local child_tree = tree:add(id, "Type: " .. string.format("%s<%s>", type, etype_str))

            if etype_str ~= nil then
                local ereader = fieldtype_readers[etype_str]
                for i = 1, size do
                    local fieldpos = tbuf.pos
                    -- TODO(eac): make handling non-scalars more elegant
                    if etype_str == "STRUCT" then
                        local elem_tree = child_tree:add(string.format("%s", i))
                        child_buf = tbuf.buf(tbuf.pos)
                        local len = decode_tfields(child_buf, elem_tree)
                        tbuf:skip(len)
                    else
                        elem = ereader(tbuf)
                        child_tree:add(buf(fieldpos, tbuf.pos-fieldpos), i, elem)
                    end
                end
            end
        else
            print(type .. " not implemented")
        end

        type = fieldtype_valstr[tbuf(1):int()]
    end

    if type == nil then
        return 0
    end

    return tbuf.pos
end


-------------------------------------------------------------------------------
--- protocol
local tstruct_protocol = Proto("thriftstruct", "Single Thrift Struct Encoded In Binary Protocol")

local tstruct_fields = {
    struct_name = ProtoField.string("thriftstruct.name", "Struct Name"),
    struct_bytesize = ProtoField.uint32("thriftstruct.bytesize", "Struct Serialized Size In Bytes", base.DEC),
    struct_fields = ProtoField.none("thriftstruct.fields", "Struct Fields"),
}

tstruct_protocol.fields = tstruct_fields

-------------------------------------------------------------------------------
--- root thriftstruct dissector. will dissect a unframed thriftstruct message
function tstruct_protocol.dissector(buffer, pinfo, tree)
    local subtree = tree:add(tstruct_protocol, buffer(), "Serialized Thrift Struct Data")
    -- TODO(ugo): maybe we could get this from the tree? Or, how do you deal with the pinfo?
    --subtree:add(tstruct_fields.struct_name, "ugo name:[" .. tostring(pinfo.http2.header.name) .. "] [" .. tostring(pinfo.http2.header) .. "] value:[" .. tostring(pinfo.http2.header.value) )
    subtree:add(tstruct_fields.struct_bytesize, buffer:len())
    local subsubtree = subtree:add(tstruct_fields.struct_fields)

    decode_tfields(buffer, subsubtree)
end

-------------------------------------------------------------------------------
--- dissector registration
DissectorTable.get("grpc_message_type"):set("application/grpc", tstruct_protocol)
DissectorTable.get("grpc_message_type"):add("application/grpc+thrift", tstruct_protocol)
