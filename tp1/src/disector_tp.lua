-- disector_tp.lua
-- Disector de Wireshark para el protocolo del TP1 (File Transfer, Grupo 6).
--
-- Reconoce los segmentos en el puerto 12000 (handshake) y, con un disector
-- heuristico, tambien en los puertos efimeros por donde viajan los datos.
--
-- Formato (segment.py):
--   seq (4) | ack (4) | flags (1) | largo del cuerpo (2) | n bloques SACK (1)
--   + n bloques SACK de 8 bytes [izq, der) + payload

local tp = Proto("tp_redes", "TP1 File Transfer (Stop & Wait / SACK)")

local HEADER = 12
local SERVER_PORT = 12000

local FLAG_SYN = 0x01
local FLAG_FIN = 0x02
local FLAG_OPE = 0x04
local FLAG_ACK = 0x08
local FLAG_PRO = 0x10
local FLAG_ERR = 0x20

local f_seq   = ProtoField.uint32("tp_redes.seq", "Numero de secuencia", base.DEC)
local f_ack   = ProtoField.uint32("tp_redes.ack", "Numero de ACK", base.DEC)
local f_flags = ProtoField.uint8("tp_redes.flags", "Flags", base.HEX)
local f_syn   = ProtoField.bool("tp_redes.flags.syn", "SYN", 8, nil, FLAG_SYN)
local f_fin   = ProtoField.bool("tp_redes.flags.fin", "FIN", 8, nil, FLAG_FIN)
local f_ope   = ProtoField.bool("tp_redes.flags.ope", "OPE (1 = upload)", 8, nil, FLAG_OPE)
local f_ackf  = ProtoField.bool("tp_redes.flags.ack", "ACK", 8, nil, FLAG_ACK)
local f_pro   = ProtoField.bool("tp_redes.flags.pro", "PRO (1 = SACK)", 8, nil, FLAG_PRO)
local f_err   = ProtoField.bool("tp_redes.flags.err", "ERR", 8, nil, FLAG_ERR)
local f_len   = ProtoField.uint16("tp_redes.len", "Largo del cuerpo", base.DEC)
local f_nsack = ProtoField.uint8("tp_redes.nsack", "Cantidad de bloques SACK", base.DEC)
local f_left  = ProtoField.uint32("tp_redes.sack.left", "Borde izquierdo", base.DEC)
local f_right = ProtoField.uint32("tp_redes.sack.right", "Borde derecho", base.DEC)
local f_plen  = ProtoField.uint16("tp_redes.payload_len", "Largo del payload", base.DEC)
local f_data  = ProtoField.bytes("tp_redes.payload", "Datos del archivo")
local f_name  = ProtoField.string("tp_redes.filename", "Nombre del archivo")
local f_emsg  = ProtoField.string("tp_redes.error", "Mensaje de error")

tp.fields = {
    f_seq, f_ack, f_flags, f_syn, f_fin, f_ope, f_ackf, f_pro, f_err,
    f_len, f_nsack, f_left, f_right, f_plen, f_data, f_name, f_emsg
}

-- Sin operadores de bits para que funcione con cualquier version de Lua.
local function has(value, mask)
    return math.floor(value / mask) % 2 == 1
end

-- Un datagrama es nuestro si el header es coherente con su largo real.
local function plausible(buf)
    local len = buf:len()
    if len < HEADER then return false end
    local flags = buf(8, 1):uint()
    if flags >= 0x40 then return false end          -- bits reservados en 1
    local body = buf(9, 2):uint()
    if HEADER + body ~= len then return false end   -- el largo tiene que cerrar exacto
    local n = buf(11, 1):uint()
    if n * 8 > body then return false end
    return true
end

local function dissect(buf, pinfo, tree)
    local seq   = buf(0, 4):uint()
    local ack   = buf(4, 4):uint()
    local flags = buf(8, 1):uint()
    local body  = buf(9, 2):uint()
    local n     = buf(11, 1):uint()
    local plen  = body - n * 8
    local poff  = HEADER + n * 8

    pinfo.cols.protocol = "TP_REDES"
    local sub = tree:add(tp, buf(), "TP1 File Transfer")

    sub:add(f_seq, buf(0, 4))
    sub:add(f_ack, buf(4, 4))
    local ft = sub:add(f_flags, buf(8, 1))
    ft:add(f_syn, buf(8, 1))
    ft:add(f_fin, buf(8, 1))
    ft:add(f_ope, buf(8, 1))
    ft:add(f_ackf, buf(8, 1))
    ft:add(f_pro, buf(8, 1))
    ft:add(f_err, buf(8, 1))
    sub:add(f_len, buf(9, 2))
    sub:add(f_nsack, buf(11, 1))

    local blocks = {}
    for i = 0, n - 1 do
        local off = HEADER + i * 8
        local l = buf(off, 4):uint()
        local r = buf(off + 4, 4):uint()
        local bt = sub:add(buf(off, 8), string.format("Bloque SACK %d: [%d, %d)", i + 1, l, r))
        bt:add(f_left, buf(off, 4))
        bt:add(f_right, buf(off + 4, 4))
        blocks[#blocks + 1] = string.format("[%d,%d)", l, r)
    end

    sub:add(f_plen, plen):set_generated()

    local text = ""
    if plen > 0 then
        local pr = buf(poff, plen)
        if has(flags, FLAG_SYN) then
            sub:add(f_name, pr)
            text = pr:string()
        elseif has(flags, FLAG_ERR) then
            sub:add(f_emsg, pr)
            text = pr:string()
        else
            sub:add(f_data, pr)
        end
    end

    -- Columna Info: tipo de segmento y lo importante de cada uno.
    local info
    if has(flags, FLAG_ERR) then
        info = "ERR: " .. text
    elseif has(flags, FLAG_SYN) then
        local op = has(flags, FLAG_OPE) and "upload" or "download"
        local pro = has(flags, FLAG_PRO) and "SACK" or "S&W"
        info = string.format("SYN seq=%d [%s, %s] nombre=%s", seq, op, pro, text)
    elseif has(flags, FLAG_FIN) then
        info = string.format("FIN seq=%d", seq)
    elseif has(flags, FLAG_ACK) then
        info = string.format("ACK ack=%d", ack)
        if #blocks > 0 then
            info = info .. " SACK=" .. table.concat(blocks, " ")
        end
    elseif plen > 0 then
        info = string.format("DATOS seq=%d len=%d", seq, plen)
    else
        info = string.format("seq=%d ack=%d", seq, ack)
    end
    pinfo.cols.info:set(info)
    sub:append_text(" — " .. info)

    return buf:len()
end

-- Puerto conocido del servidor (SYN, ACK del handshake y ERR de rechazo).
function tp.dissector(buf, pinfo, tree)
    if not plausible(buf) then return 0 end
    return dissect(buf, pinfo, tree)
end

-- Heuristico: los datos van por puertos efimeros, que cambian en cada conexion.
local function heuristic(buf, pinfo, tree)
    if not plausible(buf) then return false end
    dissect(buf, pinfo, tree)
    pinfo.conversation = tp   -- el resto de la conversacion se decodifica igual
    return true
end

tp:register_heuristic("udp", heuristic)
DissectorTable.get("udp.port"):add(SERVER_PORT, tp)