#include "bca/script/modules.h"

namespace bca::script {

const std::vector<EmbeddedModule> &embedded_modules()
{
    static const std::vector<EmbeddedModule> modules = [] {
        std::vector<EmbeddedModule> list;
        {
            std::string source;
            source += R"BCA(const native = globalThis.__native;
delete globalThis.__native;
export default native;
)BCA";
            list.push_back({"bedrock-client-api/native", true, std::move(source)});
        }
        {
            std::string source;
            source += R"BCA(import native from "bedrock-client-api/native";

const names = native.names();
const lowerFirst = (text) => text.charAt(0).toLowerCase() + text.slice(1);
const ids = Object.create(null);
names.forEach((name, id) => {
  if (name) ids[lowerFirst(name)] = id;
});
const nameOf = (id) => (names[id] ? lowerFirst(names[id]) : "packet" + id);

const checkId = (id) => {
  if (!Number.isInteger(id) || id < 1 || id >= names.length || !names[id]) {
    throw new RangeError("unknown packet id " + id);
  }
  return id;
};

const resolve = (target) => {
  if (Array.isArray(target)) return target.flatMap(resolve);
  if (target === "*") return Object.values(ids);
  if (typeof target === "number") return [checkId(target)];
  if (typeof target === "string") {
    const id = ids[lowerFirst(target)];
    if (id === undefined) throw new RangeError('unknown packet "' + target + '"');
    return [id];
  }
  throw new TypeError("a packet is given by name, by id, as an array of those, or as \"*\"");
};

const toBytes = (value) => {
  if (value instanceof Uint8Array) return value;
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  if (ArrayBuffer.isView(value)) return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  if (value && typeof value.toBytes === "function") return value.toBytes();
  if (Array.isArray(value)) return Uint8Array.from(value);
  throw new TypeError("expected a Uint8Array, an ArrayBuffer, an array of numbers or a BinaryWriter");
};

const hex = (value, limit) => {
  const bytes = toBytes(value);
  const count = limit === undefined ? bytes.length : Math.min(limit, bytes.length);
  let text = "";
  for (let i = 0; i < count; i++) text += (i ? " " : "") + bytes[i].toString(16).padStart(2, "0");
  return count < bytes.length ? text + " ..." : text;
};

const unhex = (text) => {
  const digits = String(text).replace(/[^0-9a-fA-F]/g, "");
  if (digits.length % 2 !== 0) throw new RangeError("odd number of hex digits");
  const bytes = new Uint8Array(digits.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(digits.substr(i * 2, 2), 16);
  return bytes;
};

const utf8Encode = (text) => native.utf8Encode(String(text));
const utf8Decode = (bytes) => native.utf8Decode(bytes);

class BinaryReader {
  constructor(value) {
    this.data = toBytes(value);
    this.view = new DataView(this.data.buffer, this.data.byteOffset, this.data.byteLength);
    this.pos = 0;
  }
  get remaining() {
    return this.data.length - this.pos;
  }
  get eof() {
    return this.pos >= this.data.length;
  }
  need(count) {
    if (this.pos + count > this.data.length) {
      throw new RangeError("read past the end: " + count + " byte(s) wanted at " + this.pos + " of " + this.data.length);
    }
  }
  u8() { this.need(1); return this.view.getUint8(this.pos++); }
  i8() { this.need(1); return this.view.getInt8(this.pos++); }
  u16() { this.need(2); const v = this.view.getUint16(this.pos, true); this.pos += 2; return v; }
  i16() { this.need(2); const v = this.view.getInt16(this.pos, true); this.pos += 2; return v; }
  u16be() { this.need(2); const v = this.view.getUint16(this.pos, false); this.pos += 2; return v; }
  u32() { this.need(4); const v = this.view.getUint32(this.pos, true); this.pos += 4; return v; }
  u32be() { this.need(4); const v = this.view.getUint32(this.pos, false); this.pos += 4; return v; }
  i32be() { this.need(4); const v = this.view.getInt32(this.pos, false); this.pos += 4; return v; }
  i32() { this.need(4); const v = this.view.getInt32(this.pos, true); this.pos += 4; return v; }
  u64() { this.need(8); const v = this.view.getBigUint64(this.pos, true); this.pos += 8; return v; }
  i64() { this.need(8); const v = this.view.getBigInt64(this.pos, true); this.pos += 8; return v; }
  f32() { this.need(4); const v = this.view.getFloat32(this.pos, true); this.pos += 4; return v; }
  f64() { this.need(8); const v = this.view.getFloat64(this.pos, true); this.pos += 8; return v; }
  bool() { return this.u8() !== 0; }
  varuint() {
    let result = 0;
    for (let shift = 0; ; shift += 7) {
      if (shift > 35) throw new RangeError("varint is too long");
      const b = this.u8();
      result += (b & 0x7f) * 2 ** shift;
      if ((b & 0x80) === 0) return result;
    }
  }
  varint() {
    const v = this.varuint();
    return v % 2 === 0 ? v / 2 : -(v + 1) / 2;
  }
  varuint64() {
    let result = 0n;
    for (let shift = 0n; ; shift += 7n) {
      if (shift > 63n) throw new RangeError("varint64 is too long");
      const b = this.u8();
      result |= BigInt(b & 0x7f) << shift;
      if ((b & 0x80) === 0) return result;
    }
  }
  varint64() {
    const v = this.varuint64();
    return (v & 1n) !== 0n ? -((v + 1n) >> 1n) : v >> 1n;
  }
  string() {
    const length = this.varuint();
    return utf8Decode(this.bytes(length));
  }
  bytes(count) {
    this.need(count);
    const out = this.data.slice(this.pos, this.pos + count);
    this.pos += count;
    return out;
  }
  rest() {
    return this.bytes(this.remaining);
  }
  skip(count) {
    this.need(count);
    this.pos += count;
    return this;
  }
}

class BinaryWriter {
  constructor() {
    this.buffer = new Uint8Array(64);
    this.view = new DataView(this.buffer.buffer);
    this.length = 0;
  }
  ensure(count) {
    const wanted = this.length + count;
    if (wanted <= this.buffer.length) return;
    let size = this.buffer.length * 2;
    while (size < wanted) size *= 2;
    const next = new Uint8Array(size);
    next.set(this.buffer.subarray(0, this.length));
    this.buffer = next;
    this.view = new DataView(next.buffer);
  }
  u8(v) { this.ensure(1); this.buffer[this.length++] = v & 0xff; return this; }
  i8(v) { return this.u8(v); }
  u16(v) { this.ensure(2); this.view.setUint16(this.length, v, true); this.length += 2; return this; }
  i16(v) { this.ensure(2); this.view.setInt16(this.length, v, true); this.length += 2; return this; }
)BCA";
            source += R"BCA(  u16be(v) { this.ensure(2); this.view.setUint16(this.length, v, false); this.length += 2; return this; }
  u32(v) { this.ensure(4); this.view.setUint32(this.length, v, true); this.length += 4; return this; }
  u32be(v) { this.ensure(4); this.view.setUint32(this.length, v, false); this.length += 4; return this; }
  i32be(v) { this.ensure(4); this.view.setInt32(this.length, v, false); this.length += 4; return this; }
  i32(v) { this.ensure(4); this.view.setInt32(this.length, v, true); this.length += 4; return this; }
  u64(v) { this.ensure(8); this.view.setBigUint64(this.length, BigInt(v), true); this.length += 8; return this; }
  i64(v) { this.ensure(8); this.view.setBigInt64(this.length, BigInt(v), true); this.length += 8; return this; }
  f32(v) { this.ensure(4); this.view.setFloat32(this.length, v, true); this.length += 4; return this; }
  f64(v) { this.ensure(8); this.view.setFloat64(this.length, v, true); this.length += 8; return this; }
  bool(v) { return this.u8(v ? 1 : 0); }
  varuint(v) {
    if (!Number.isInteger(v) || v < 0) throw new RangeError("varuint needs a non-negative integer");
    let n = v;
    while (n >= 0x80) {
      this.u8((n % 128) | 0x80);
      n = Math.floor(n / 128);
    }
    return this.u8(n);
  }
  varint(v) {
    if (!Number.isInteger(v)) throw new RangeError("varint needs an integer");
    return this.varuint(v >= 0 ? v * 2 : -v * 2 - 1);
  }
  varuint64(v) {
    let n = BigInt.asUintN(64, BigInt(v));
    while (n >= 0x80n) {
      this.u8(Number(n & 0x7fn) | 0x80);
      n >>= 7n;
    }
    return this.u8(Number(n));
  }
  varint64(v) {
    const x = BigInt.asIntN(64, BigInt(v));
    return this.varuint64((x << 1n) ^ (x >> 63n));
  }
  string(text) {
    const encoded = utf8Encode(String(text));
    this.varuint(encoded.length);
    return this.bytes(encoded);
  }
  bytes(value) {
    const data = toBytes(value);
    this.ensure(data.length);
    this.buffer.set(data, this.length);
    this.length += data.length;
    return this;
  }
  toBytes() {
    return this.buffer.slice(0, this.length);
  }
}

const simple = (read, write) => ({ read, write });
const Types = {
  bool: simple((r) => r.bool(), (w, v) => w.bool(v)),
  u8: simple((r) => r.u8(), (w, v) => w.u8(v)),
  i8: simple((r) => r.i8(), (w, v) => w.i8(v)),
  u16: simple((r) => r.u16(), (w, v) => w.u16(v)),
  i16: simple((r) => r.i16(), (w, v) => w.i16(v)),
  u32: simple((r) => r.u32(), (w, v) => w.u32(v)),
  i32: simple((r) => r.i32(), (w, v) => w.i32(v)),
  u64: simple((r) => r.u64(), (w, v) => w.u64(v)),
  i64: simple((r) => r.i64(), (w, v) => w.i64(v)),
  f32: simple((r) => r.f32(), (w, v) => w.f32(v)),
  f64: simple((r) => r.f64(), (w, v) => w.f64(v)),
  u16be: simple((r) => r.u16be(), (w, v) => w.u16be(v)),
  u32be: simple((r) => r.u32be(), (w, v) => w.u32be(v)),
  i32be: simple((r) => r.i32be(), (w, v) => w.i32be(v)),
  varuint: simple((r) => r.varuint(), (w, v) => w.varuint(v)),
  varint: simple((r) => r.varint(), (w, v) => w.varint(v)),
  varuint64: simple((r) => r.varuint64(), (w, v) => w.varuint64(v)),
  varint64: simple((r) => r.varint64(), (w, v) => w.varint64(v)),
  string: simple((r) => r.string(), (w, v) => w.string(v)),
  uuid: simple(
    (r) => {
      const wire = r.bytes(16);
      const bytes = new Uint8Array(16);
      for (let i = 0; i < 8; i++) {
        bytes[i] = wire[7 - i];
        bytes[8 + i] = wire[15 - i];
      }
      const digits = Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
      return [digits.slice(0, 8), digits.slice(8, 12), digits.slice(12, 16), digits.slice(16, 20), digits.slice(20)].join("-");
    },
    (w, v) => {
      const digits = String(v).replace(/-/g, "");
      if (!/^[0-9a-fA-F]{32}$/.test(digits)) throw new RangeError("not a UUID: " + v);
      const bytes = unhex(digits);
      const wire = new Uint8Array(16);
      for (let i = 0; i < 8; i++) {
        wire[i] = bytes[7 - i];
        wire[8 + i] = bytes[15 - i];
      }
      w.bytes(wire);
    }),
  bytes: simple((r) => r.rest(), (w, v) => w.bytes(v)),
  array(element, count = Types.varuint) {
    return simple(
      (r) => {
        const length = count.read(r);
        if (length > r.remaining) throw new RangeError("a list of " + length + " does not fit in the " + r.remaining + " bytes left");
        const out = [];
        for (let i = 0; i < length; i++) out.push(element.read(r));
        return out;
      },
      (w, v) => {
        count.write(w, v.length);
        for (const item of v) element.write(w, item);
      });
  },
  optional(element) {
    return simple(
      (r) => (r.bool() ? element.read(r) : null),
      (w, v) => {
        if (v === null || v === undefined) {
          w.bool(false);
        } else {
          w.bool(true);
          element.write(w, v);
        }
      });
  },
  enum(base, names) {
    const byValue = new Map(Object.entries(names).map(([name, value]) => [value, name]));
    return simple(
      (r) => {
        const value = base.read(r);
        return byValue.has(value) ? byValue.get(value) : value;
      },
      (w, v) => {
        if (typeof v === "string") {
          if (!(v in names)) throw new RangeError('unknown name "' + v + '"; known: ' + Object.keys(names).join(", "));
          base.write(w, names[v]);
        } else {
          base.write(w, v);
        }
      });
  },
  vec3: simple(
    (r) => ({ x: r.f32(), y: r.f32(), z: r.f32() }),
    (w, v) => w.f32(v.x).f32(v.y).f32(v.z)),
  blockPos: simple(
    (r) => ({ x: r.varint(), y: r.varint(), z: r.varint() }),
    (w, v) => w.varint(v.x).varint(v.y).varint(v.z)),
  struct(fields) {
    const entries = Object.entries(fields);
    return simple(
      (r) => Object.fromEntries(entries.map(([key, codec]) => [key, codec.read(r)])),
      (w, v) => entries.forEach(([key, codec]) => codec.write(w, v[key])));
  },
};

const registry = new Map();

const fingerprintOf = (value) =>
)BCA";
            source += R"BCA(  JSON.stringify(value, (key, item) => (typeof item === "bigint" ? item.toString() + "n" : item));

class PacketBase {
  get tail() {
    return this.tail_ ?? new Uint8Array(0);
  }
  set tail(value) {
    Object.defineProperty(this, "tail_", { value: toBytes(value), writable: true, enumerable: false, configurable: true });
  }
  clone() {
    return this.constructor.decode(this.toBytes());
  }
  fingerprint() {
    return fingerprintOf({ ...this });
  }
  toJSON() {
    return JSON.parse(fingerprintOf({ ...this }));
  }
  send(options = {}) {
    return packet.send(this, options);
  }
}

const definePacket = (name, spec) => {
  const packetName = lowerFirst(name);
  const id = ids[packetName];
  const fields = Object.entries(spec.fields ?? {});
  if (!spec.fields && !(spec.read && spec.write)) {
    throw new TypeError("definePacket needs `fields`, or both `read` and `write`");
  }
  const defaults = () => (typeof spec.defaults === "function" ? spec.defaults() : { ...(spec.defaults ?? {}) });

  const Defined = class extends PacketBase {
    constructor(values = {}) {
      super();
      Object.assign(this, defaults(), values);
    }
    static get id() {
      return id;
    }
    static get packetName() {
      return packetName;
    }
    static decode(bytes) {
      const reader = new BinaryReader(bytes);
      const result = new Defined();
      try {
        if (spec.read) spec.read(reader, result);
        else for (const [key, codec] of fields) result[key] = codec.read(reader);
      } catch (error) {
        throw new RangeError(name + ": cannot read the body (" + error.message + ")");
      }
      result.tail = reader.rest();
      return result;
    }
    toBytes() {
      const writer = new BinaryWriter();
      if (spec.write) spec.write(writer, this);
      else for (const [key, codec] of fields) codec.write(writer, this[key]);
      writer.bytes(this.tail);
      return writer.toBytes();
    }
  };
  Object.defineProperty(Defined, "name", { value: name });
  if (id !== undefined) registry.set(id, Defined);
  return Defined;
};

class RawPacket extends PacketBase {
  constructor(id, body) {
    super();
    Object.defineProperty(this, "idValue", { value: id });
    Object.defineProperty(this, "bodyValue", { value: body, writable: true });
  }
  get id() { return this.idValue; }
  get name() { return nameOf(this.idValue); }
  get body() { return this.bodyValue; }
  set body(value) { this.bodyValue = toBytes(value); }
  reader() { return new BinaryReader(this.bodyValue); }
  toBytes() { return this.bodyValue; }
  fingerprint() { return ""; }
  toJSON() { return { id: this.id, name: this.name, size: this.bodyValue.length }; }
}

const subscriptionMask = (options) => {
  const direction = options.direction ?? "both";
  const side = options.side ?? "client";
  let directions;
  if (direction === "both") directions = 3;
  else if (direction === "c2s") directions = 1;
  else if (direction === "s2c") directions = 2;
  else throw new TypeError('direction is "c2s", "s2c" or "both"');
  if (side === "client") return directions;
  if (side === "server") return directions << 2;
  if (side === "both") return directions | (directions << 2);
  throw new TypeError('side is "client", "server" or "both"');
};
const connectionKinds = { 0: "rakNet", 1: "address", 2: "address6", 3: "netherNet", 4: "invalid" };

const subscriptions = new Map();
let nextHandle = 1;

const whySendFailed = (side, direction, size) => {
  let hooks = null;
  try { hooks = typeof native.hooks === "function" ? native.hooks() : null; } catch (error) {  }
  if (hooks && side === "client" && direction === "c2s" && hooks.sendInternal === false) {
    return "this client build cannot send packets to the server (the sendInternal hook is missing, see the 'hooks:' line printed when the DLL loaded)";
  }
  if (hooks && !hooks.createPacket) return "the packet hooks are not installed (createPacket was not found in this client build)";
  if (hooks && side === "client" && direction === "s2c" && hooks.handlers === 0) {
    return "no packet handler could be hooked in this client build, so nothing can be delivered to the client";
  }
  if (hooks && side === "server" && hooks.sendInternal === false) {
    return "this client build cannot send packets to the connections of a hosted world (the sendInternal hook is missing)";
  }
  if (side === "server") return "no such connection yet, or the body is too large (" + size + " bytes)";
  return "the body is too large (" + size + " bytes), the packet id is unknown to this client, or the hooks are not installed";
};

const packet = {
  on(target, callback, options = {}) {
    if (typeof callback !== "function") throw new TypeError("packet.on needs a callback function");
    const mask = subscriptionMask(options);
    const list = resolve(target);
    const wrapped = (id, direction, body, side, player, connection) => {
      let cancelled = false;
      let replacement;
      let decoded;
      let before;
      let tracked = false;
      const decode = () => {
        if (decoded === undefined) {
          const Type = registry.get(id);
          decoded = Type ? Type.decode(body) : new RawPacket(id, body);
        }
        return decoded;
      };
      callback({
        id,
        name: nameOf(id),
        direction: direction === 0 ? "c2s" : "s2c",
        side: side === 1 ? "server" : "client",
        player: side === 1 && player >= 0 ? player : null,
        connection: side === 1 ? (connectionKinds[connection] ?? connection) : null,
        size: body.length,
        body,
        get packet() {
          const read = decode();
          if (!tracked) {
            tracked = true;
            before = read.fingerprint();
          }
          return read;
        },
        get view() {
          return decode();
        },
        cancel() { cancelled = true; },
        replace(value) { replacement = toBytes(value); },
      });
      if (cancelled) return null;
)BCA";
            source += R"BCA(      if (replacement === undefined && tracked && before !== "" && decoded.fingerprint() !== before) {
        replacement = decoded.toBytes();
      }
      return replacement;
    };
    const handle = nextHandle++;
    subscriptions.set(handle, list.map((id) => native.subscribe(id, mask, wrapped)));
    return handle;
  },
  off(handle) {
    const list = subscriptions.get(handle);
    if (!list) return false;
    list.forEach((id) => native.unsubscribe(id));
    subscriptions.delete(handle);
    return true;
  },
  send(target, body, options = {}) {
    if (target instanceof PacketBase) {
      if (!Number.isInteger(target.constructor.id)) {
        throw new Error('this client has no packet called "' + target.constructor.packetName + '"');
      }
      options = body ?? {};
      body = target;
      target = target.constructor.id;
    }
    const side = options.side ?? "client";
    if (side !== "client" && side !== "server") throw new TypeError('side is "client" or "server"');
    const direction = options.direction ?? (side === "server" ? "s2c" : "c2s");
    if (direction !== "c2s" && direction !== "s2c") throw new TypeError('direction is "c2s" or "s2c"');
    if (side === "server" && direction !== "s2c") throw new TypeError("the hosted server can only send to clients (s2c)");
    const player = options.player ?? "all";
    if (player !== "all" && !Number.isInteger(player)) throw new TypeError('player is a connection number or "all"');
    const list = resolve(target);
    if (list.length !== 1) throw new TypeError("packet.send takes exactly one packet");
    const bytes = toBytes(body);
    const sent = native.send(list[0], bytes, direction === "c2s" ? 0 : 1, side === "server" ? 1 : 0, player === "all" ? -1 : player);
    if (!sent) throw new Error("packet.send failed: " + whySendFailed(side, direction, bytes.length));
    return true;
  },
  get types() {
    return Object.freeze(Object.fromEntries([...registry.values()].map((Type) => [Type.packetName, Type])));
  },
  name: nameOf,
  id(name) {
    return resolve(name)[0];
  },
};

const base64 = Object.freeze({
  decode: (text) => native.base64Decode(String(text)),
  encode: (value, options = {}) => native.base64Encode(toBytes(value), options.url === true),
});
const jwt = Object.freeze({
  decode(token) {
    const parts = String(token).split(".");
    if (parts.length !== 3) throw new RangeError("not a JWT: expected three parts separated by dots");
    return {
      header: JSON.parse(utf8Decode(base64.decode(parts[0]))),
      payload: JSON.parse(utf8Decode(base64.decode(parts[1]))),
      signature: parts[2],
    };
  },
});

const Packets = Object.freeze({ ...ids });
const utf8 = Object.freeze({ encode: (text) => utf8Encode(text), decode: (bytes) => utf8Decode(toBytes(bytes)) });

export { packet, Packets, BinaryReader, BinaryWriter, Types, definePacket, RawPacket, PacketBase, hex, unhex, utf8, base64, jwt };
)BCA";
            list.push_back({"bedrock-client-api/core", true, std::move(source)});
        }
        {
            std::string source;
            source += R"BCA(import native from "bedrock-client-api/native";
import { definePacket, Types, BinaryReader, BinaryWriter, utf8, jwt, base64 } from "bedrock-client-api/core";

const randomUuid = () => {
  const bytes = Array.from({ length: 16 }, () => Math.floor(Math.random() * 256));
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const digits = bytes.map((b) => b.toString(16).padStart(2, "0")).join("");
  return [digits.slice(0, 8), digits.slice(8, 12), digits.slice(12, 16), digits.slice(16, 20), digits.slice(20)].join("-");
};
const addJson = (Class, field) => {
  Object.defineProperty(Class.prototype, "json", {
    get() { return this[field] === null || this[field] === undefined ? null : JSON.parse(this[field]); },
    set(value) { this[field] = value === null ? null : JSON.stringify(value); },
  });
};

const textTypes = { raw: 0, chat: 1, translation: 2, popup: 3, jukeboxPopup: 4, tip: 5, system: 6, whisper: 7,
                    announcement: 8, jsonWhisper: 9, json: 10, jsonAnnouncement: 11 };
const textCategory = { raw: 0, tip: 0, system: 0, json: 0, jsonWhisper: 0, jsonAnnouncement: 0,
                       chat: 1, whisper: 1, announcement: 1,
                       translation: 2, popup: 2, jukeboxPopup: 2 };
const textTypeNames = new Map(Object.entries(textTypes).map(([name, value]) => [value, name]));
const stringList = Types.array(Types.string);
const optionalString = Types.optional(Types.string);

const TextPacket = definePacket("TextPacket", {
  defaults: () => ({ needsTranslation: false, type: "chat", sender: "", message: "", parameters: [],
                     xuid: "", platformChatId: "", filteredMessage: null }),
  read(r, p) {
    p.needsTranslation = r.bool();
    const category = r.u8();
    const type = r.u8();
    p.type = textTypeNames.has(type) ? textTypeNames.get(type) : type;
    if (category === 1) {
      p.sender = r.string();
      p.message = r.string();
    } else if (category === 0) {
      p.message = r.string();
    } else if (category === 2) {
      p.message = r.string();
      p.parameters = stringList.read(r);
    } else {
      throw new RangeError("unknown text category " + category);
    }
    p.xuid = r.string();
    p.platformChatId = r.string();
    p.filteredMessage = optionalString.read(r);
  },
  write(w, p) {
    const name = typeof p.type === "number" ? textTypeNames.get(p.type) : p.type;
    const category = textCategory[name];
    if (category === undefined) throw new RangeError("unknown text type " + p.type);
    w.bool(p.needsTranslation).u8(category).u8(textTypes[name]);
    if (category === 1) w.string(p.sender).string(p.message);
    else if (category === 0) w.string(p.message);
    else {
      w.string(p.message);
      stringList.write(w, p.parameters);
    }
    w.string(p.xuid).string(p.platformChatId);
    optionalString.write(w, p.filteredMessage);
  },
});
Object.assign(TextPacket, {
  Type: Object.freeze({ ...textTypes }),
  chat: (message, sender = "") => new TextPacket({ type: "chat", sender, message }),
  whisper: (message, sender = "") => new TextPacket({ type: "whisper", sender, message }),
  announcement: (message, sender = "") => new TextPacket({ type: "announcement", sender, message }),
  raw: (message) => new TextPacket({ type: "raw", message }),
  tip: (message) => new TextPacket({ type: "tip", message }),
  system: (message) => new TextPacket({ type: "system", message }),
  popup: (message) => new TextPacket({ type: "popup", message }),
  translation: (key, parameters = []) => new TextPacket({ type: "translation", needsTranslation: true, message: key, parameters }),
});

const titleTypes = { clear: 0, reset: 1, title: 2, subtitle: 3, actionbar: 4, animationTimes: 5,
                     titleJson: 6, subtitleJson: 7, actionbarJson: 8 };
const SetTitlePacket = definePacket("SetTitlePacket", {
  fields: {
    type: Types.enum(Types.varint, titleTypes),
    text: Types.string,
    fadeIn: Types.varint,
    stay: Types.varint,
    fadeOut: Types.varint,
    xuid: Types.string,
    platformOnlineId: Types.string,
    filteredText: Types.string,
  },
  defaults: () => ({ type: "title", text: "", fadeIn: 0, stay: 0, fadeOut: 0, xuid: "", platformOnlineId: "", filteredText: "" }),
});
Object.assign(SetTitlePacket, {
  Type: Object.freeze({ ...titleTypes }),
  title: (text) => new SetTitlePacket({ type: "title", text }),
  subtitle: (text) => new SetTitlePacket({ type: "subtitle", text }),
  actionbar: (text) => new SetTitlePacket({ type: "actionbar", text }),
  times: (fadeIn, stay, fadeOut) => new SetTitlePacket({ type: "animationTimes", fadeIn, stay, fadeOut }),
  clear: () => new SetTitlePacket({ type: "clear" }),
});


const LoginPacket = definePacket("LoginPacket", {
  defaults: () => ({ protocol: 0, authInfoJson: "", clientDataJwt: "" }),
  read(r, p) {
    p.protocol = r.u32be();
    const request = new BinaryReader(r.bytes(r.varuint()));
    p.authInfoJson = utf8.decode(request.bytes(request.u32()));
    p.clientDataJwt = utf8.decode(request.bytes(request.u32()));
  },
  write(w, p) {
    const auth = utf8.encode(p.authInfoJson);
    const client = utf8.encode(p.clientDataJwt);
    const request = new BinaryWriter().u32(auth.length).bytes(auth).u32(client.length).bytes(client);
    w.u32be(p.protocol).varuint(request.length).bytes(request);
  },
});

const memo = (owner, key, source, compute) => {
  if (!Object.prototype.hasOwnProperty.call(owner, "memo_")) {
    Object.defineProperty(owner, "memo_", { value: {}, enumerable: false });
  }
  const entry = owner.memo_[key];
  if (entry && entry.source === source) return entry.value;
  const value = compute();
  owner.memo_[key] = { source, value };
  return value;
};
const chainTokens = (info) => {
  if (Array.isArray(info.chain)) return info.chain;
  if (typeof info.Certificate === "string") {
    const certificate = JSON.parse(info.Certificate);
    if (Array.isArray(certificate.chain)) return certificate.chain;
  }
  return [];
};
)BCA";
            source += R"BCA(const omitLong = (object) =>
  Object.fromEntries(Object.entries(object).map(([key, value]) =>
    [key, typeof value === "string" && value.length > 128 ? "[omitted: " + value.length + " characters]" : value]));

Object.defineProperties(LoginPacket.prototype, {
  authInfo: {
    get() { return memo(this, "authInfo", this.authInfoJson, () => JSON.parse(this.authInfoJson)); },
  },
  chain: {
    get() {
      return memo(this, "chain", this.authInfoJson, () => {
        const decoded = [];
        for (const token of chainTokens(this.authInfo)) {
          try { decoded.push(jwt.decode(token)); } catch (error) {  }
        }
        return decoded;
      });
    },
  },
  clientData: {
    get() { return memo(this, "clientData", this.clientDataJwt, () => jwt.decode(this.clientDataJwt).payload); },
  },
  clientDataHeader: {
    get() { return memo(this, "clientDataHeader", this.clientDataJwt, () => jwt.decode(this.clientDataJwt).header); },
  },
  identity: {
    get() {
      return memo(this, "identity", this.authInfoJson + "\n" + this.clientDataJwt, () => {
        for (const link of this.chain) {
          const extra = link.payload.extraData;
          if (extra) return { name: extra.displayName, xuid: extra.XUID, uuid: extra.identity, titleId: extra.titleId };
        }
        const token = this.authInfo.Token;
        if (typeof token === "string" && token !== "") {
          try {
            const claims = jwt.decode(token).payload;
            const name = claims.xname ?? claims.displayName ?? claims.gamertag;
            const xuid = claims.xid ?? claims.xuid ?? claims.XUID;
            if (name !== undefined || xuid !== undefined) {
              return { name, xuid, uuid: claims.identity, titleId: claims.titleId };
            }
          } catch (error) {  }
        }
        return null;
      });
    },
  },
});
Object.assign(LoginPacket.prototype, {
  setClientData(changes) {
    const parts = this.clientDataJwt.split(".");
    if (parts.length !== 3) throw new RangeError("clientDataJwt is not a JWT");
    const payload = { ...jwt.decode(this.clientDataJwt).payload, ...changes };
    parts[1] = base64.encode(utf8.encode(JSON.stringify(payload)), { url: true });
    this.clientDataJwt = parts.join(".");
    return this;
  },
  summary() {
    const { Token, ...authInfo } = this.authInfo;
    return {
      protocol: this.protocol,
      identity: this.identity,
      authInfo: omitLong(authInfo),
      clientData: omitLong(this.clientData),
      clientDataHeader: this.clientDataHeader,
    };
  },
  toJSON() {
    return {
      protocol: this.protocol,
      authInfoJson: "[omitted: " + this.authInfoJson.length + " characters]",
      clientDataJwt: "[omitted: " + this.clientDataJwt.length + " characters]",
    };
  },
});

const DisconnectPacket = definePacket("DisconnectPacket", {
  defaults: () => ({ reason: 0, message: null, filteredMessage: null }),
  read(r, p) {
    p.reason = r.varint();
    const skipMessage = r.bool();
    p.message = skipMessage ? null : r.string();
    p.filteredMessage = skipMessage ? null : r.string();
  },
  write(w, p) {
    const skipMessage = p.message === null && p.filteredMessage === null;
    w.varint(p.reason).bool(skipMessage);
    if (!skipMessage) w.string(p.message ?? "").string(p.filteredMessage ?? "");
  },
});
Object.assign(DisconnectPacket, {
  kick: (message, reason = 0) => new DisconnectPacket({ reason, message, filteredMessage: message }),
});

const CommandOrigin = Types.struct({
  type: Types.string,
  uuid: Types.uuid,
  requestId: Types.string,
  playerId: Types.i64,
});
const CommandRequestPacket = definePacket("CommandRequestPacket", {
  fields: { command: Types.string, origin: CommandOrigin, isInternal: Types.bool, version: Types.string },
  defaults: () => ({
    command: "",
    origin: { type: "player", uuid: randomUuid(), requestId: randomUuid(), playerId: 0n },
    isInternal: false,
    version: "",
  }),
});
Object.assign(CommandRequestPacket, {
  run(command, options = {}) {
    const made = new CommandRequestPacket({ command });
    if (options.like) {
      made.origin = { ...options.like.origin, requestId: randomUuid() };
      made.version = options.like.version;
      made.isInternal = options.like.isInternal;
    }
    return made;
  },
});

const ModalFormRequestPacket = definePacket("ModalFormRequestPacket", {
  fields: { formId: Types.varuint, formData: Types.string },
  defaults: () => ({ formId: 0, formData: "{}" }),
});
addJson(ModalFormRequestPacket, "formData");
Object.assign(ModalFormRequestPacket, {
  show: (formId, form) => new ModalFormRequestPacket({ formId, formData: typeof form === "string" ? form : JSON.stringify(form) }),
});

const ModalFormResponsePacket = definePacket("ModalFormResponsePacket", {
  fields: {
    formId: Types.varuint,
    formData: Types.optional(Types.string),
    cancelReason: Types.optional(Types.u8),
  },
  defaults: () => ({ formId: 0, formData: null, cancelReason: null }),
});
addJson(ModalFormResponsePacket, "formData");
Object.assign(ModalFormResponsePacket, {
  CancelReason: Object.freeze({ closed: 0, userBusy: 1 }),
  response: (formId, answer) =>
    new ModalFormResponsePacket({ formId, formData: typeof answer === "string" ? answer : JSON.stringify(answer) }),
  cancel: (formId, cancelReason = 0) => new ModalFormResponsePacket({ formId, formData: null, cancelReason }),
});

const ToastRequestPacket = definePacket("ToastRequestPacket", {
  fields: { title: Types.string, body: Types.string },
  defaults: () => ({ title: "", body: "" }),
});
Object.assign(ToastRequestPacket, {
  toast: (title, body = "") => new ToastRequestPacket({ title, body }),
});

const TransferPacket = definePacket("TransferPacket", {
  fields: { address: Types.string, port: Types.u16, reloadWorld: Types.bool },
  defaults: () => ({ address: "", port: 19132, reloadWorld: false }),
});
Object.assign(TransferPacket, {
)BCA";
            source += R"BCA(  to: (address, port = 19132, reloadWorld = false) => new TransferPacket({ address, port, reloadWorld }),
});

const PlayStatusPacket = definePacket("PlayStatusPacket", {
  fields: { status: Types.enum(Types.i32be, { loginSuccess: 0, loginFailedClient: 1, loginFailedServer: 2, playerSpawn: 3 }) },
  defaults: () => ({ status: "loginSuccess" }),
});

const SetLocalPlayerAsInitializedPacket = definePacket("SetLocalPlayerAsInitializedPacket", {
  fields: { runtimeId: Types.varuint64 },
  defaults: () => ({ runtimeId: 0n }),
});

const AnimatePacket = definePacket("AnimatePacket", {
  fields: {
    action: Types.enum(Types.u8, { swingArm: 1, stopSleep: 3, criticalHit: 4, magicalCriticalHit: 5 }),
    runtimeId: Types.varuint64,
    data: Types.f32,
    swingSource: Types.optional(Types.string),
    hand: Types.u8,
  },
  defaults: () => ({ action: "swingArm", runtimeId: 0n, data: 0, swingSource: null, hand: 0 }),
});
Object.assign(AnimatePacket, {
  swing: (runtimeId = 0n) => new AnimatePacket({ action: "swingArm", runtimeId }),
});

const codec = (read, write) => ({ read, write });
const vec2 = codec((r) => ({ x: r.f32(), y: r.f32() }), (w, v) => w.f32(v.x).f32(v.y));
const vec3 = Types.vec3;

const ItemStack = codec(
  (r) => {
    const networkId = r.varint();
    if (networkId === 0) return { networkId: 0, count: 0, metadata: 0, stackId: null, blockRuntimeId: 0, userData: new Uint8Array(0) };
    const count = r.u16();
    const metadata = r.varuint();
    const stackId = r.bool() ? r.varint() : null;
    const blockRuntimeId = r.varint();
    const userData = r.bytes(r.varuint());
    return { networkId, count, metadata, stackId, blockRuntimeId, userData };
  },
  (w, v) => {
    if (!v || !v.networkId) {
      w.varint(0);
      return;
    }
    w.varint(v.networkId).u16(v.count ?? 1).varuint(v.metadata ?? 0);
    if (v.stackId === null || v.stackId === undefined) w.bool(false);
    else w.bool(true).varint(v.stackId);
    const userData = v.userData ?? new Uint8Array(0);
    w.varint(v.blockRuntimeId ?? 0).varuint(userData.length).bytes(userData);
  });
const emptyItem = () => ({ networkId: 0, count: 0, metadata: 0, stackId: null, blockRuntimeId: 0, userData: new Uint8Array(0) });

const uniqueId = Types.varint64;
const runtimeId = Types.varuint64;
const stringArray = Types.array(Types.string);

const transactionTypes = { normal: 0, inventoryMismatch: 1, itemUse: 2, itemUseOnActor: 3, itemRelease: 4 };
const useOnActorTypes = { interact: 0, attack: 1, itemInteract: 2 };
const typeEnum = (base, names) => Types.enum(base, names);
const transactionTypeCodec = typeEnum(Types.varuint, transactionTypes);
const useOnActorCodec = typeEnum(Types.varuint, useOnActorTypes);
const InventoryAction = codec(
  (r) => {
    const sourceType = r.varuint();
    const action = { sourceType, windowId: null, sourceFlags: null, slot: 0, oldItem: null, newItem: null };
    if (sourceType === 0) action.windowId = r.varint();
    else if (sourceType === 2) action.sourceFlags = r.varuint();
    action.slot = r.varuint();
    action.oldItem = ItemStack.read(r);
    action.newItem = ItemStack.read(r);
    return action;
  },
  (w, a) => {
    w.varuint(a.sourceType);
    if (a.sourceType === 0) w.varint(a.windowId ?? 0);
    else if (a.sourceType === 2) w.varuint(a.sourceFlags ?? 0);
    w.varuint(a.slot ?? 0);
    ItemStack.write(w, a.oldItem ?? emptyItem());
    ItemStack.write(w, a.newItem ?? emptyItem());
  });
const inventoryActions = Types.array(InventoryAction);
const legacySlots = Types.array(Types.struct({ containerId: Types.u8, slots: Types.array(Types.u8) }));

const InventoryTransactionPacket = definePacket("InventoryTransactionPacket", {
  defaults: () => ({
    legacyRequestId: 0, legacySetItemSlots: null, transactionType: "itemUseOnActor", actions: [], runtimeId: 0n,
    actionType: "attack", slot: 0, hand: 0, item: emptyItem(), fromPosition: { x: 0, y: 0, z: 0 },
    hitPosition: { x: 0, y: 0, z: 0 }, detailsRead: true,
  }),
  read(r, p) {
    p.legacyRequestId = r.varint();
    p.legacySetItemSlots = p.legacyRequestId !== 0 ? legacySlots.read(r) : null;
    p.transactionType = transactionTypeCodec.read(r);
    if (p.transactionType !== "itemUseOnActor") return;
    p.actions = inventoryActions.read(r);
    p.runtimeId = runtimeId.read(r);
    p.actionType = useOnActorCodec.read(r);
    p.slot = r.varint();
    p.hand = r.u8();
    const mark = r.pos;
    try {
      p.item = ItemStack.read(r);
      p.fromPosition = vec3.read(r);
      p.hitPosition = vec3.read(r);
      p.detailsRead = true;
    } catch (error) {
      r.pos = mark;
      p.item = emptyItem();
      p.detailsRead = false;
    }
  },
  write(w, p) {
    w.varint(p.legacyRequestId);
    if (p.legacyRequestId !== 0) legacySlots.write(w, p.legacySetItemSlots ?? []);
    transactionTypeCodec.write(w, p.transactionType);
    if (p.transactionType !== "itemUseOnActor") return;
    inventoryActions.write(w, p.actions);
    runtimeId.write(w, p.runtimeId);
    useOnActorCodec.write(w, p.actionType);
    w.varint(p.slot).u8(p.hand);
    if (p.detailsRead) {
      ItemStack.write(w, p.item);
      vec3.write(w, p.fromPosition);
      vec3.write(w, p.hitPosition);
    }
  },
});
Object.assign(InventoryTransactionPacket, {
  TransactionType: Object.freeze({ ...transactionTypes }),
  ActionType: Object.freeze({ ...useOnActorTypes }),
  attack: (target, values = {}) => new InventoryTransactionPacket({ transactionType: "itemUseOnActor", actionType: "attack", runtimeId: BigInt(target), ...values }),
  interact: (target, values = {}) => new InventoryTransactionPacket({ transactionType: "itemUseOnActor", actionType: "interact", runtimeId: BigInt(target), ...values }),
});

const playerActions = {
  unknown: -1, startDestroyBlock: 0, abortDestroyBlock: 1, stopDestroyBlock: 2, startSleeping: 5, stopSleeping: 6, respawn: 7,
  startJump: 8, startSprinting: 9, stopSprinting: 10, startSneaking: 11, stopSneaking: 12, creativeDestroyBlock: 13,
)BCA";
            source += R"BCA(  changeDimensionAck: 14, startGliding: 15, stopGliding: 16, denyDestroyBlock: 17, crackBlock: 18, startSwimming: 21,
  stopSwimming: 22, startSpinAttack: 23, stopSpinAttack: 24, predictDestroyBlock: 26, continueDestroyBlock: 27,
  startItemUseOn: 28, stopItemUseOn: 29, handledTeleport: 30, missedSwing: 31, startCrawling: 32, stopCrawling: 33,
  startFlying: 34, stopFlying: 35, startUsingItem: 37, internalUpdate: 38,
};
const PlayerActionPacket = definePacket("PlayerActionPacket", {
  fields: {
    runtimeId,
    action: Types.enum(Types.varint, playerActions),
    blockPosition: Types.blockPos,
    resultPosition: Types.blockPos,
    face: Types.varint,
  },
  defaults: () => ({ runtimeId: 0n, action: "missedSwing", blockPosition: { x: 0, y: 0, z: 0 }, resultPosition: { x: 0, y: 0, z: 0 }, face: 0 }),
});
Object.assign(PlayerActionPacket, {
  Action: Object.freeze({ ...playerActions }),
  missedSwing: (id = 0n) => new PlayerActionPacket({ runtimeId: id, action: "missedSwing" }),
});

const inputFlags = {
  ascend: 0, descend: 1, jumpDown: 3, sprintDown: 4, changeHeight: 5, jumping: 6, autoJumpingInWater: 7, sneaking: 8,
  sneakDown: 9, up: 10, down: 11, left: 12, right: 13, upLeft: 14, upRight: 15, wantUp: 16, wantDown: 17, wantDownSlow: 18,
  wantUpSlow: 19, sprinting: 20, ascendBlock: 21, descendBlock: 22, sneakToggleDown: 23, persistSneak: 24,
  startSprinting: 25, stopSprinting: 26, startSneaking: 27, stopSneaking: 28, startSwimming: 29, stopSwimming: 30,
  startJumping: 31, startGliding: 32, stopGliding: 33, performItemInteraction: 34, performBlockActions: 35,
  performItemStackRequest: 36, handledTeleport: 37, emoting: 38, missedSwing: 39, startCrawling: 40, stopCrawling: 41,
  startFlying: 42, stopFlying: 43, clientAckServerData: 44, isInClientPredictedVehicle: 45, paddlingLeft: 46,
  paddlingRight: 47, blockBreakingDelayEnabled: 48, horizontalCollision: 49, verticalCollision: 50, downLeft: 51,
  downRight: 52, startUsingItem: 53, startSpinAttack: 56, stopSpinAttack: 57, isHotbarOnlyTouch: 58, jumpReleasedRaw: 59,
  jumpPressedRaw: 60, jumpCurrentRaw: 61, sneakReleasedRaw: 62, sneakPressedRaw: 63, sneakCurrentRaw: 64, swapOffhand: 65,
};
const inputFlagNames = new Map(Object.entries(inputFlags).map(([name, bit]) => [bit, name]));
const Bitset = codec(
  (r) => {
    let value = 0n;
    for (let shift = 0n; ; shift += 7n) {
      if (shift > 140n) throw new RangeError("a bit set that is too long");
      const b = r.u8();
      value |= BigInt(b & 0x7f) << shift;
      if ((b & 0x80) === 0) return value;
    }
  },
  (w, v) => {
    let n = BigInt(v);
    do {
      const low = Number(n & 0x7fn);
      n >>= 7n;
      w.u8(n > 0n ? low | 0x80 : low);
    } while (n > 0n);
  });
const PlayerAuthInputPacket = definePacket("PlayerAuthInputPacket", {
  defaults: () => ({
    rotation: { x: 0, y: 0 }, position: { x: 0, y: 0, z: 0 }, moveVector: { x: 0, y: 0 }, headRotation: 0, inputData: 0n,
    inputMode: 0, playMode: 0, interactionModel: 0, interactRotation: { x: 0, y: 0 }, clientTick: 0n,
    posDelta: { x: 0, y: 0, z: 0 }, complete: true,
  }),
  read(r, p) {
    p.rotation = vec2.read(r);
    p.position = vec3.read(r);
    p.moveVector = vec2.read(r);
    p.headRotation = r.f32();
    p.inputData = Bitset.read(r);
    const mark = r.pos;
    try {
      p.inputMode = r.varuint();
      p.playMode = r.varuint();
      p.interactionModel = r.varuint();
      p.interactRotation = vec2.read(r);
      p.clientTick = r.varuint64();
      p.posDelta = vec3.read(r);
      p.complete = true;
    } catch (error) {
      r.pos = mark;
      p.complete = false;
    }
  },
  write(w, p) {
    vec2.write(w, p.rotation);
    vec3.write(w, p.position);
    vec2.write(w, p.moveVector);
    w.f32(p.headRotation);
    Bitset.write(w, p.inputData);
    if (!p.complete) return;
    w.varuint(p.inputMode).varuint(p.playMode).varuint(p.interactionModel);
    vec2.write(w, p.interactRotation);
    w.varuint64(p.clientTick);
    vec3.write(w, p.posDelta);
  },
});
const flagBit = (flag) => {
  const bit = typeof flag === "number" ? flag : inputFlags[flag];
  if (!Number.isInteger(bit) || bit < 0) throw new RangeError('unknown input flag "' + flag + '"');
  return BigInt(bit);
};
Object.defineProperties(PlayerAuthInputPacket.prototype, {
  flags: {
    get() {
      const names = [];
      for (let bit = 0; bit < 128; bit++) if ((this.inputData >> BigInt(bit)) & 1n) names.push(inputFlagNames.get(bit) ?? bit);
      return names;
    },
  },
});
Object.assign(PlayerAuthInputPacket.prototype, {
  has(flag) { return ((this.inputData >> flagBit(flag)) & 1n) === 1n; },
  set(flag, on = true) { this.inputData = on ? this.inputData | (1n << flagBit(flag)) : this.inputData & ~(1n << flagBit(flag)); return this; },
});
Object.assign(PlayerAuthInputPacket, { InputFlag: Object.freeze({ ...inputFlags }) });

const bossEvents = { add: 0, playerAdded: 1, remove: 2, playerRemoved: 3, updatePercent: 4, updateName: 5, updateProperties: 6, updateStyle: 7, query: 8 };
const bossColors = { pink: 0, blue: 1, red: 2, green: 3, yellow: 4, purple: 5, rebeccaPurple: 6, white: 7 };
const PROGRESS = 0;
const bossEventCodec = Types.enum(Types.varuint, bossEvents);
const bossColorCodec = Types.enum(Types.varuint, bossColors);
const game = typeof native.game === "function" ? native.game() : { major: 1, minor: 26, patch: 60 };
const flatBossEvent = !(game.major === 1 && game.minor === 26 && game.patch < 60);
const BossEventPacket = definePacket("BossEventPacket", {
  defaults: () => ({ targetActorId: 0n, eventType: "add", name: "", filteredName: "", healthPercent: 1, color: "pink",
                     darkenScreen: 0, playerId: 0n }),
  read(r, p) {
    p.targetActorId = uniqueId.read(r);
    if (flatBossEvent) {
      p.eventType = Types.enum(Types.u8, bossEvents).read(r);
      p.name = r.string();
      p.filteredName = r.string();
      p.healthPercent = r.f32();
      p.color = Types.enum(Types.u8, bossColors).read(r);
)BCA";
            source += R"BCA(      Types.u8.read(r);
      return;
    }
    p.eventType = bossEventCodec.read(r);
    switch (p.eventType) {
      case "add": p.name = r.string(); p.filteredName = r.string(); p.healthPercent = r.f32(); p.darkenScreen = r.u16();
        p.color = bossColorCodec.read(r); Types.varuint.read(r); break;
      case "playerAdded": case "playerRemoved": case "query": p.playerId = uniqueId.read(r); break;
      case "updatePercent": p.healthPercent = r.f32(); break;
      case "updateName": p.name = r.string(); p.filteredName = r.string(); break;
      case "updateProperties": p.darkenScreen = r.u16(); p.color = bossColorCodec.read(r); Types.varuint.read(r); break;
      case "updateStyle": p.color = bossColorCodec.read(r); Types.varuint.read(r); break;
      default: break;
    }
  },
  write(w, p) {
    uniqueId.write(w, p.targetActorId);
    if (flatBossEvent) {
      Types.enum(Types.u8, bossEvents).write(w, p.eventType);
      w.string(p.name).string(p.filteredName).f32(p.healthPercent);
      Types.enum(Types.u8, bossColors).write(w, p.color);
      Types.u8.write(w, PROGRESS);
      return;
    }
    bossEventCodec.write(w, p.eventType);
    switch (p.eventType) {
      case "add": w.string(p.name).string(p.filteredName).f32(p.healthPercent).u16(p.darkenScreen);
        bossColorCodec.write(w, p.color); Types.varuint.write(w, PROGRESS); break;
      case "playerAdded": case "playerRemoved": case "query": uniqueId.write(w, p.playerId); break;
      case "updatePercent": w.f32(p.healthPercent); break;
      case "updateName": w.string(p.name).string(p.filteredName); break;
      case "updateProperties": w.u16(p.darkenScreen); bossColorCodec.write(w, p.color); Types.varuint.write(w, PROGRESS); break;
      case "updateStyle": bossColorCodec.write(w, p.color); Types.varuint.write(w, PROGRESS); break;
      default: break;
    }
  },
});
const bossState = (id, eventType, { name = "", percent = 1, color = "pink" } = {}) =>
  new BossEventPacket({
    targetActorId: BigInt(id), eventType, name: String(name), filteredName: String(name), healthPercent: percent, color,
  });
Object.assign(BossEventPacket, {
  EventType: Object.freeze({ ...bossEvents }),
  Color: Object.freeze({ ...bossColors }),
  add: (id, state) => bossState(id, "add", state),
  remove: (id, state) => bossState(id, "remove", state),
  updatePercent: (id, percent, state = {}) => bossState(id, "updatePercent", { ...state, percent }),
  updateName: (id, name, state = {}) => bossState(id, "updateName", { ...state, name }),
  updateStyle: (id, color, state = {}) => bossState(id, "updateStyle", { ...state, color }),
});

const ParseFlag = { valid: 0x100000, enum: 0x200000, postfix: 0x1000000, softEnum: 0x4000000 };
const ParamType = {
  int: 1, float: 3, value: 4, wildcardInt: 5, operator: 6, compareOperator: 7, target: 8, wildcardTarget: 10, filepath: 17,
  fullIntegerRange: 23, equipmentSlot: 47, string: 56, intPosition: 64, position: 65, message: 68, rawText: 70, json: 74,
  blockStates: 84, command: 87,
};
const permissionNames = { any: "Any", gameDirectors: "GameDirectors", admin: "Admin", host: "Host", owner: "Owner", internal: "Internal" };
const enumDataEntry = Types.struct({ name: Types.string, values: Types.array(Types.u32) });
const commandEntry = Types.struct({
  name: Types.string,
  description: Types.string,
  flags: Types.u16,
  permissionLevel: Types.string,
  aliasEnum: Types.i32,
  chainedSubcommandIndexes: Types.array(Types.u32),
  overloads: Types.array(Types.struct({
    isChaining: Types.bool,
    parameters: Types.array(Types.struct({ name: Types.string, parseSymbol: Types.u32, isOptional: Types.bool, options: Types.u8 })),
  })),
});
const softEnumEntry = Types.struct({ enumName: Types.string, enumOptions: stringArray });
const AvailableCommandsPacket = definePacket("AvailableCommandsPacket", {
  fields: {
    enumValues: stringArray,
    chainedSubcommandValues: stringArray,
    postFixes: stringArray,
    enumData: Types.array(enumDataEntry),
    chainedSubcommandData: Types.array(Types.struct({
      name: Types.string,
      subcommandValues: Types.array(Types.struct({ firstValue: Types.varuint, secondValue: Types.varuint })),
    })),
    commands: Types.array(commandEntry),
    softEnums: Types.array(softEnumEntry),
    constraints: Types.array(Types.struct({ enumValueSymbol: Types.u32, enumSymbol: Types.u32, constraintIndices: Types.array(Types.u8) })),
  },
  defaults: () => ({
    enumValues: [], chainedSubcommandValues: [], postFixes: [], enumData: [], chainedSubcommandData: [], commands: [],
    softEnums: [], constraints: [],
  }),
});
const indexIn = (list, value, from = 0) => {
  let at = list.indexOf(value, from);
  if (at < 0) {
    list.push(value);
    at = list.length - 1;
  }
  return at;
};
Object.assign(AvailableCommandsPacket.prototype, {
  addSoftEnum(name, options = []) {
    const found = this.softEnums.find((entry) => entry.enumName === name);
    if (found) found.enumOptions = [...options];
    else this.softEnums.push({ enumName: name, enumOptions: [...options] });
    return this;
  },
  addCommand(definition) {
    const name = String(definition.name);
    const enumIndex = (enumName, words) => {
      const indexes = words.map((word) => indexIn(this.enumValues, String(word), this.base_ ? this.base_.enumValues : 0));
      const found = this.enumData.findIndex((entry) => entry.name === enumName);
      if (found >= 0) {
        this.enumData[found].values = indexes;
        return found;
      }
      this.enumData.push({ name: enumName, values: indexes });
      return this.enumData.length - 1;
    };
    const aliases = definition.aliases ?? [];
    const aliasEnum = aliases.length > 0 ? enumIndex(name + "Aliases", [name, ...aliases]) : -1;
    const overloads = (definition.overloads ?? [[]]).map((parameters) => ({
      isChaining: false,
      parameters: parameters.map((parameter) => {
        let symbol;
        if (parameter.symbol !== undefined) {
)BCA";
            source += R"BCA(          symbol = parameter.symbol;
        } else if (parameter.enum) {
          const enumName = parameter.enumName ?? name + "_" + parameter.name;
          symbol = ParseFlag.enum | ParseFlag.valid | enumIndex(enumName, parameter.enum);
        } else if (parameter.softEnum) {
          let at = this.softEnums.findIndex((entry) => entry.enumName === parameter.softEnum);
          if (at < 0) {
            this.addSoftEnum(parameter.softEnum, []);
            at = this.softEnums.length - 1;
          }
          symbol = ParseFlag.softEnum | ParseFlag.valid | at;
        } else {
          const type = typeof parameter.type === "number" ? parameter.type : ParamType[parameter.type ?? "string"];
          if (type === undefined) throw new RangeError('unknown parameter type "' + parameter.type + '"');
          symbol = ParseFlag.valid | type;
        }
        return { name: String(parameter.name), parseSymbol: symbol >>> 0, isOptional: parameter.optional === true, options: parameter.options ?? 0 };
      }),
    }));
    const permission = definition.permission ?? "any";
    const entry = {
      name,
      description: String(definition.description ?? ""),
      flags: definition.flags ?? 0,
      permissionLevel: permissionNames[permission] ?? String(permission),
      aliasEnum,
      chainedSubcommandIndexes: [],
      overloads,
    };
    const existing = this.commands.findIndex((command) => command.name === name);
    if (existing >= 0) this.commands[existing] = entry;
    else this.commands.push(entry);
    return this;
  },
});
Object.assign(AvailableCommandsPacket, {
  ParseFlag: Object.freeze({ ...ParseFlag }),
  ParamType: Object.freeze({ ...ParamType }),
  build(commands, { softEnums = {} } = {}) {
    const made = new AvailableCommandsPacket();
    for (const [name, words] of Object.entries(softEnums)) made.addSoftEnum(name, words);
    for (const command of commands) made.addCommand(command);
    return made;
  },
});

const scanCommandTables = (data) => {
  const size = data.length;
  let pos = 0;
  const fail = () => {
    throw new RangeError("AvailableCommandsPacket: the tables do not fit the body (at " + pos + " of " + size + ")");
  };
  const varuint = () => {
    let result = 0;
    let scale = 1;
    for (;;) {
      if (pos >= size) fail();
      const b = data[pos++];
      result += (b & 0x7f) * scale;
      if (b < 0x80) return result;
      scale *= 128;
      if (scale > 34359738368) fail();
    }
  };
  const skip = (count) => {
    pos += count;
    if (pos > size) fail();
  };
  const skipString = () => skip(varuint());
  const table = (skipOne) => {
    const countFrom = pos;
    const count = varuint();
    const from = pos;
    for (let i = 0; i < count; i++) skipOne();
    return { countFrom, from, to: pos, count };
  };
  const tables = {};
  const enumWords = [];
  tables.enumValues = table(() => { const n = varuint(); const at = pos; skip(n); enumWords.push(utf8.decode(data.subarray(at, at + n))); });
  tables.chainedSubcommandValues = table(skipString);
  tables.postFixes = table(skipString);
  const enumLists = [];
  tables.enumData = table(() => {
    skipString();
    const n = varuint();
    const at = pos;
    skip(n * 4);
    const list = [];
    for (let i = 0; i < n; i++) list.push((data[at + i * 4] | (data[at + i * 4 + 1] << 8) | (data[at + i * 4 + 2] << 16) | (data[at + i * 4 + 3] << 24)) >>> 0);
    enumLists.push(list);
  });
  tables.chainedSubcommandData = table(() => { skipString(); for (let i = varuint(); i > 0; i--) { varuint(); varuint(); } });
  const names = [];
  const countFrom = pos;
  const count = varuint();
  const from = pos;
  for (let i = 0; i < count; i++) {
    const start = pos;
    const length = varuint();
    const at = pos;
    skip(length);
    names.push({ start, end: 0, name: utf8.decode(data.subarray(at, at + length)) });
    skipString();
    skip(2);
    skipString();
    skip(4);
    names[names.length - 1].alias = (data[pos - 4] | (data[pos - 3] << 8) | (data[pos - 2] << 16) | (data[pos - 1] << 24)) | 0;
    skip(varuint() * 4);
    for (let o = varuint(); o > 0; o--) {
      skip(1);
      for (let p = varuint(); p > 0; p--) {
        skipString();
        skip(6);
      }
    }
    names[names.length - 1].end = pos;
  }
  tables.commands = { countFrom, from, to: pos, count, list: names };
  tables.softEnums = table(() => { skipString(); for (let i = varuint(); i > 0; i--) skipString(); });
  tables.constraints = table(() => { skip(8); skip(varuint()); });
  tables.end = pos;
  const plain = (name) => String(name).toLowerCase().replace(/^minecraft:/, "");
  for (const entry of names) {
    const words = [plain(entry.name)];
    if (entry.alias >= 0 && entry.alias < enumLists.length) {
      for (const index of enumLists[entry.alias]) if (index < enumWords.length) words.push(plain(enumWords[index]));
    }
    entry.names = words;
  }
  return tables;
};

const concatBytes = (pieces) => {
  let total = 0;
  for (const piece of pieces) total += piece.length;
  const out = new Uint8Array(total);
  let at = 0;
  for (const piece of pieces) {
    out.set(piece, at);
    at += piece.length;
  }
  return out;
};

Object.assign(AvailableCommandsPacket, {
  namesOf(body, wanted) {
    const data = body instanceof Uint8Array ? body : new Uint8Array(body);
    const want = new Set(Array.from(wanted, (name) => String(name).toLowerCase().replace(/^minecraft:/, "")));
    const out = new Set();
    for (const entry of scanCommandTables(data).commands.list) {
      if (entry.names.some((word) => want.has(word))) for (const word of entry.names) out.add(word);
    }
    return [...out];
  },
  patch(body, commands, { softEnums = {}, remove = [] } = {}) {
    const data = body instanceof Uint8Array ? body : new Uint8Array(body);
    const found = scanCommandTables(data);
    const hole = { name: undefined, enumName: undefined };
    const scratch = new AvailableCommandsPacket();
)BCA";
            source += R"BCA(    scratch.enumValues = new Array(found.enumValues.count).fill("");
    scratch.enumData = new Array(found.enumData.count).fill(hole);
    scratch.softEnums = new Array(found.softEnums.count).fill(hole);
    Object.defineProperty(scratch, "base_", { value: { enumValues: found.enumValues.count } });
    for (const [name, words] of Object.entries(softEnums)) scratch.addSoftEnum(name, words);
    for (const command of commands) scratch.addCommand(command);

    const writer = () => new BinaryWriter();
    const strings = (list) => { const w = writer(); for (const item of list) w.string(item); return w.toBytes(); };
    const entries = (codec, list) => { const w = writer(); for (const item of list) codec.write(w, item); return w.toBytes(); };
    const count = (n) => writer().varuint(n).toBytes();
    const part = (table, start = table.countFrom) => data.subarray(start, table.to);

    const newValues = scratch.enumValues.slice(found.enumValues.count);
    const newEnums = scratch.enumData.slice(found.enumData.count);
    const newSoft = scratch.softEnums.slice(found.softEnums.count);
    const pieces = [];
    pieces.push(count(found.enumValues.count + newValues.length), data.subarray(found.enumValues.from, found.enumValues.to), strings(newValues));
    pieces.push(part(found.chainedSubcommandValues), part(found.postFixes));
    pieces.push(count(found.enumData.count + newEnums.length), data.subarray(found.enumData.from, found.enumData.to), entries(enumDataEntry, newEnums));
    pieces.push(part(found.chainedSubcommandData));

    const replaced = new Set(scratch.commands.map((command) => command.name));
    const gone = new Set(Array.from(remove, (name) => String(name).toLowerCase().replace(/^minecraft:/, "")));
    const kept = found.commands.list.filter((entry) => !replaced.has(entry.name) && !entry.names.some((word) => gone.has(word)));
    pieces.push(count(kept.length + scratch.commands.length));
    for (let i = 0; i < kept.length;) {
      let last = i;
      while (last + 1 < kept.length && kept[last + 1].start === kept[last].end) last++;
      pieces.push(data.subarray(kept[i].start, kept[last].end));
      i = last + 1;
    }
    pieces.push(entries(commandEntry, scratch.commands));
    pieces.push(count(found.softEnums.count + newSoft.length), data.subarray(found.softEnums.from, found.softEnums.to), entries(softEnumEntry, newSoft));
    pieces.push(part(found.constraints), data.subarray(found.end));
    return concatBytes(pieces);
  },
});

const UpdateSoftEnumPacket = definePacket("UpdateSoftEnumPacket", {
  fields: { enumName: Types.string, values: stringArray, updateType: Types.enum(Types.u8, { add: 0, remove: 1, replace: 2 }) },
  defaults: () => ({ enumName: "", values: [], updateType: "replace" }),
});
Object.assign(UpdateSoftEnumPacket, {
  add: (enumName, values) => new UpdateSoftEnumPacket({ enumName, values: [...values], updateType: "add" }),
  remove: (enumName, values) => new UpdateSoftEnumPacket({ enumName, values: [...values], updateType: "remove" }),
  replace: (enumName, values) => new UpdateSoftEnumPacket({ enumName, values: [...values], updateType: "replace" }),
});

const MobEquipmentPacket = definePacket("MobEquipmentPacket", {
  fields: { runtimeId, item: ItemStack, slot: Types.u8, selectedSlot: Types.u8, containerId: Types.u8 },
  defaults: () => ({ runtimeId: 0n, item: emptyItem(), slot: 0, selectedSlot: 0, containerId: 0 }),
});

const idsOfStartGame = (bytes) => {
  const reader = new BinaryReader(bytes);
  return { uniqueId: reader.varint64(), runtimeId: reader.varuint64() };
};

export {
  LoginPacket, TextPacket, SetTitlePacket, DisconnectPacket, CommandRequestPacket,
  ModalFormRequestPacket, ModalFormResponsePacket,
  ToastRequestPacket, TransferPacket, PlayStatusPacket, SetLocalPlayerAsInitializedPacket, AnimatePacket,
  InventoryTransactionPacket, PlayerActionPacket, PlayerAuthInputPacket, BossEventPacket,
  AvailableCommandsPacket, UpdateSoftEnumPacket, MobEquipmentPacket, ItemStack, emptyItem, idsOfStartGame,
};
)BCA";
            list.push_back({"bedrock-client-api/packets", true, std::move(source)});
        }
        {
            std::string source;
            source += R"BCA(export * from "bedrock-client-api/core";
export * from "bedrock-client-api/packets";
)BCA";
            list.push_back({"bedrock-client-api/packet", false, std::move(source)});
        }
        {
            std::string source;
            source += R"BCA(import native from "bedrock-client-api/native";
import { packet } from "bedrock-client-api/core";
import {
  TextPacket, SetTitlePacket, DisconnectPacket, CommandRequestPacket, ModalFormRequestPacket, ModalFormResponsePacket,
  ToastRequestPacket, TransferPacket, LoginPacket, BossEventPacket, AvailableCommandsPacket, UpdateSoftEnumPacket, idsOfStartGame,
} from "bedrock-client-api/packets";

const report = (error, label) => console.error(label + ": " + (error && error.stack ? error.stack : String(error)));
const textOf = (value) => (String(value) === "" ? " " : String(value));

const TICK_MS = 50;
const startedAt = Date.now();

class Signal {
  constructor(owner) {
    Object.defineProperty(this, "owner_", { value: owner });
    Object.defineProperty(this, "callbacks_", { value: [] });
  }
  subscribe(callback) {
    if (typeof callback !== "function") throw new TypeError("subscribe needs a function");
    this.callbacks_.push(callback);
    this.owner_.changed();
    return callback;
  }
  unsubscribe(callback) {
    const index = this.callbacks_.indexOf(callback);
    if (index < 0) return false;
    this.callbacks_.splice(index, 1);
    this.owner_.changed();
    return true;
  }
}

class GameEvent {
  constructor(ctx) {
    Object.defineProperty(this, "ctx_", { value: ctx });
    this.cancel = false;
  }
  toJSON() {
    return Object.fromEntries(this.constructor.keys.map((key) => [key, this[key]]));
  }
}

const eventClass = (name, members, methods = {}) => {
  const Class = class extends GameEvent {};
  Object.defineProperty(Class, "name", { value: name });
  Object.defineProperty(Class, "keys", { value: Object.keys(members) });
  for (const [key, member] of Object.entries(members)) {
    Object.defineProperty(Class.prototype, key, {
      enumerable: true,
      configurable: true,
      get() { return member.get(this.ctx_); },
      set: member.set ? function (value) { member.set(this.ctx_, value); } : undefined,
    });
  }
  for (const [key, method] of Object.entries(methods)) {
    Object.defineProperty(Class.prototype, key, {
      configurable: true,
      writable: true,
      value(...args) { return method(this.ctx_, this, ...args); },
    });
  }
  return Class;
};

const spec = (name, packetName, direction, accept, members, methods, prepare, attach) => ({
  name, packetName, direction, accept, prepare, attach, BeforeEvent: eventClass(name + "BeforeEvent", members, methods),
});

class EventKind {
  constructor(scope, definition) {
    this.scope = scope;
    this.definition = definition;
    this.handle = null;
    this.before = new Signal(this);
    this.after = new Signal(this);
  }
  changed() {
    const wanted = this.before.callbacks_.length + this.after.callbacks_.length > 0;
    if (wanted && this.handle === null) {
      if (this.definition.prepare) this.definition.prepare(this.scope);
      else if (this.scope.prepare) this.scope.prepare();
      if (this.definition.attach) this.handle = this.definition.attach(this.scope, (ctx) => this.fire(ctx));
      else {
        this.handle = packet.on(this.definition.packetName, (low) => this.dispatch(low),
          { side: this.scope.side, direction: this.definition.direction });
      }
    } else if (!wanted && this.handle !== null) {
      if (this.definition.attach) this.handle();
      else packet.off(this.handle);
      this.handle = null;
    }
  }
  dispatch(low) {
    const definition = this.definition;
    let body;
    try {
      body = low.packet;
    } catch (error) {
      report(error, definition.name + ": the packet cannot be read");
      return;
    }
    if (definition.accept && !definition.accept(body, this.scope)) return;
    this.fire({ low, packet: body, scope: this.scope, cache: new Map() });
  }
  fire(ctx) {
    const definition = this.definition;
    const event = new definition.BeforeEvent(ctx);
    for (const callback of [...this.before.callbacks_]) {
      try { callback(event); } catch (error) { report(error, definition.name); }
    }
    if (event.cancel) {
      if (!definition.attach) ctx.low.cancel();
      return;
    }
    if (this.after.callbacks_.length > 0) {
      const settled = Object.freeze(Object.fromEntries(definition.BeforeEvent.keys.map((key) => [key, event[key]])));
      for (const callback of [...this.after.callbacks_]) {
        try { callback(settled); } catch (error) { report(error, definition.name); }
      }
    }
  }
}


const hooksOf = () => {
  try { return typeof native.hooks === "function" ? native.hooks() : null; } catch (error) { return null; }
};
const clientSendsAreSeen = () => {
  const hooks = hooksOf();
  return hooks === null || hooks === undefined || hooks.sendInternal !== false;
};

class OwnServerLink {
  constructor() {
    this.mine = null;
    this.runtimeId = null;
    this.seen = new Set();
    this.learners = false;
  }
  ownRuntimeId() {
    if (this.runtimeId !== null) return this.runtimeId;
    try {
      const body = typeof native.startGameOf === "function" ? native.startGameOf(-1) : undefined;
      if (body && body.length > 0) this.runtimeId = idsOfStartGame(body).runtimeId;
    } catch (error) { report(error, "own connection: start game"); }
    return this.runtimeId;
  }
  learn(low) {
    if (low.player === null) return;
    this.seen.add(low.player);
    const own = this.ownRuntimeId();
    if (own === null) return;
    if (low.name !== "playerActionPacket" && low.name !== "mobEquipmentPacket" && low.name !== "animatePacket") return;
    const named = low.view.runtimeId;
    if (named === own && this.mine !== low.player) {
      this.mine = low.player;
      console.log("own connection: you are connection " + low.player + " of the world's server");
    }
  }
  isMine(low) {
    if (low.player === null) return false;
    if (this.mine !== null) return low.player === this.mine;
    if (this.ownRuntimeId() !== null) return false;
    return this.seen.size === 1 && this.seen.has(low.player);
  }
  watch(names, handler) {
)BCA";
            source += R"BCA(    if (!this.learners) {
      this.learners = true;
      for (const name of ["playerActionPacket", "mobEquipmentPacket", "animatePacket"]) {
        try { packet.on(name, (low) => { try { this.learn(low); } catch (error) { report(error, "own connection"); } }, { side: "server", direction: "c2s" }); }
        catch (error) { report(error, "own connection: cannot watch " + name); }
      }
    }
    return names.map((name) => packet.on(name, (low) => {
      try {
        this.learn(low);
        if (this.isMine(low)) handler(low);
      } catch (error) { report(error, "own connection: " + low.name); }
    }, { side: "server", direction: "c2s" }));
  }
}
const ownServerLink = new OwnServerLink();

const memo = (ctx, key, compute) => {
  if (!ctx.cache.has(key)) ctx.cache.set(key, compute());
  return ctx.cache.get(key);
};

const DEVICE_OS = { "-1": "unknown", 1: "android", 2: "ios", 3: "macos", 4: "fireos", 5: "gearvr", 6: "hololens", 7: "windows",
                    8: "win32", 9: "dedicated", 10: "tvos", 11: "playstation", 12: "switch", 13: "xbox", 14: "windowsPhone",
                    15: "linux" };
const osNumberOf = (os) => {
  if (typeof os === "number" && Number.isInteger(os)) return os;
  const wanted = String(os).toLowerCase();
  const found = Object.entries(DEVICE_OS).find(([, name]) => name.toLowerCase() === wanted);
  if (!found) throw new RangeError('unknown os "' + os + '": a number, or one of ' + Object.values(DEVICE_OS).join(", "));
  return Number(found[0]);
};
const INPUT_MODE = { 1: "mouse", 2: "touch", 3: "gamepad", 4: "motionController" };

class Player {
  constructor(id, connection) {
    this.id = id;
    this.connection = connection ?? null;
    this.name = "";
    this.xuid = "";
    this.uuid = "";
    this.protocol = 0;
    this.device = { os: "unknown", model: "", id: "" };
    this.gameVersion = "";
    this.language = "";
    this.inputMode = "unknown";
  }
  get isKnown() { return this.name !== ""; }
  get actorUniqueId() {
    return this.startGameIds_()?.uniqueId ?? null;
  }
  get actorRuntimeId() {
    return this.startGameIds_()?.runtimeId ?? null;
  }
  startGameIds_() {
    try {
      const body = typeof native.startGameOf === "function" ? native.startGameOf(this.id) : undefined;
      if (body && body.length > 0) return idsOfStartGame(body);
    } catch (error) {
      report(error, "player " + this.id + ": start game");
    }
    return null;
  }
  get scope_() { return host; }

  applyLogin(login) {
    let identity = null;
    let data = {};
    try { identity = login.identity; } catch (error) { report(error, "player " + this.id + ": identity"); }
    try { data = login.clientData ?? {}; } catch (error) { report(error, "player " + this.id + ": client data"); }
    const text = (value, fallback) => (value === undefined || value === null ? fallback : String(value));
    this.name = text(identity?.name ?? data.ThirdPartyName, this.name);
    this.xuid = text(identity?.xuid, this.xuid);
    this.uuid = text(identity?.uuid ?? data.SelfSignedId, this.uuid);
    this.protocol = login.protocol ?? this.protocol;
    this.device = {
      os: DEVICE_OS[data.DeviceOS] ?? text(data.DeviceOS, this.device.os),
      model: text(data.DeviceModel, this.device.model),
      id: text(data.DeviceId, this.device.id),
    };
    this.gameVersion = text(data.GameVersion, this.gameVersion);
    this.language = text(data.LanguageCode, this.language);
    this.inputMode = INPUT_MODE[data.CurrentInputMode] ?? text(data.CurrentInputMode, this.inputMode);
    Object.defineProperty(this, "loginPacket", { value: login, configurable: true, writable: true, enumerable: false });
    return this;
  }
  loadSavedLogin() {
    try {
      const saved = typeof native.loginOf === "function" ? native.loginOf(this.id) : null;
      if (!saved || saved.length === 0) return false;
      this.applyLogin(LoginPacket.decode(saved));
      return true;
    } catch (error) {
      report(error, "player " + this.id + ": the saved login");
      return false;
    }
  }

  sendPacket(packetObject) {
    packet.send(packetObject, { side: "server", player: this.id });
  }
  sendMessage(text) { this.sendPacket(TextPacket.raw(textOf(text))); }
  setActionBar(text) { this.sendPacket(SetTitlePacket.actionbar(String(text))); }
  showTitle(title, subtitle, times) {
    if (times) this.sendPacket(SetTitlePacket.times(times.fadeIn ?? 10, times.stay ?? 70, times.fadeOut ?? 20));
    if (subtitle !== undefined) this.sendPacket(SetTitlePacket.subtitle(String(subtitle)));
    this.sendPacket(SetTitlePacket.title(String(title)));
  }
  toast(title, body = "") { this.sendPacket(ToastRequestPacket.toast(String(title), String(body))); }
  kick(message = "", reason = 0) { this.sendPacket(DisconnectPacket.kick(String(message), reason)); }
  transfer(address, port = 19132) { this.sendPacket(TransferPacket.to(String(address), port)); }
  showForm(form) { return this.scope_.showForm(this, form); }

  toJSON() {
    return { id: this.id, connection: this.connection, name: this.name, xuid: this.xuid, uuid: this.uuid, protocol: this.protocol,
             device: this.device, gameVersion: this.gameVersion, language: this.language, inputMode: this.inputMode };
  }
  toString() { return "Player(" + this.id + (this.name === "" ? "" : ", " + this.name) + ")"; }
}

class ClientPlayer extends Player {
  constructor() {
    super(-1, "local");
    this.loadSavedLogin();
  }
  get scope_() { return client; }
  sendPacket(packetObject) { packet.send(packetObject, { side: "client", direction: "s2c" }); }
  chat(message) { TextPacket.chat(String(message)).send(); }
  runCommand(command, options) { CommandRequestPacket.run(String(command), options).send(); }
}

class Scope {
  constructor(side, definitions) {
    Object.defineProperty(this, "side", { value: side });
    this.beforeEvents = {};
    this.afterEvents = {};
    for (const definition of definitions) {
      const kind = new EventKind(this, definition);
)BCA";
            source += R"BCA(      this.beforeEvents[definition.name] = kind.before;
      this.afterEvents[definition.name] = kind.after;
    }
    Object.defineProperty(this, "formState_", { value: { tracking: false, next: 1000000, pending: new Map(), own: new Set() } });
    Object.defineProperty(this, "book_", { value: new CommandBook(this) });
    Object.defineProperty(this, "customCommandRegistry", { value: new CustomCommandRegistry([this.book_]) });
  }
  showForm(player, form) {
    return new Promise((resolve, reject) => {
      const state = this.formState_;
      this.trackForms_();
      const formId = state.next++;
      if (state.pending.size >= 256) {
        const [oldest, waiting] = state.pending.entries().next().value;
        state.pending.delete(oldest);
        waiting.resolve({ response: undefined, canceled: true, cancelReason: null });
      }
      if (state.own.size >= 4096) state.own.delete(state.own.values().next().value);
      state.own.add(formId);
      state.pending.set(formId, { player: player.id, resolve });
      try {
        player.sendPacket(ModalFormRequestPacket.show(formId, form));
      } catch (error) {
        state.pending.delete(formId);
        reject(error);
      }
    });
  }
  trackForms_() {
    const state = this.formState_;
    if (state.tracking) return;
    state.tracking = true;
    const answered = (low, who) => {
      const body = low.packet;
      const waiting = state.pending.get(body.formId);
      if (!waiting || waiting.player !== who) return;
      state.pending.delete(body.formId);
      low.cancel();
      waiting.resolve({ ...answerOf(body), cancelReason: body.cancelReason });
    };
    if (this.side === "client" && !clientSendsAreSeen()) {
      ownServerLink.watch(["modalFormResponsePacket"], (low) => answered(low, -1));
    } else {
      packet.on("modalFormResponsePacket", (low) => answered(low, low.player ?? -1), { side: this.side, direction: "c2s" });
    }
  }
}

const answerOf = (body) => {
  try { return { response: body.json, canceled: body.formData === null || body.json === null }; }
  catch (error) { return { response: undefined, canceled: true }; }
};

class Host extends Scope {
  constructor() {
    super("server", hostDefinitions);
    Object.defineProperty(this, "players_", { value: new Map() });
    Object.defineProperty(this, "tracking_", { value: false, writable: true });
  }
  get players() {
    this.prepare();
    return [...this.players_.values()];
  }
  getPlayers() { return this.players; }
  getPlayer(key) {
    this.prepare();
    if (typeof key === "number") return this.players_.get(key);
    return [...this.players_.values()].find((player) => player.name === key);
  }
  playerOf(low) {
    return this.players_.get(low.player) ?? this.addPlayer(low.player, low.connection);
  }
  addPlayer(id, connection) {
    const player = new Player(id, connection);
    this.players_.set(id, player);
    player.loadSavedLogin();
    return player;
  }
  prepare() {
    if (this.tracking_) return;
    this.tracking_ = true;
    packet.on("loginPacket", (low) => {
      try { this.playerOf(low).applyLogin(low.packet); } catch (error) { report(error, "host: login"); }
    }, { side: "server", direction: "c2s" });
    packet.on("textPacket", (low) => {
      try {
        const body = low.packet;
        if (body.type !== "chat") return;
        const player = this.playerOf(low);
        if (player.name === "" && body.sender) player.name = body.sender;
        if (player.xuid === "" && body.xuid) player.xuid = body.xuid;
      } catch (error) { report(error, "host: chat"); }
    }, { side: "server", direction: "c2s" });
    try {
      for (const id of typeof native.knownConnections === "function" ? native.knownConnections() : []) {
        if (!this.players_.has(id)) this.addPlayer(id, null);
      }
    } catch (error) { report(error, "host: known connections"); }
  }
  sendPacket(packetObject) { packet.send(packetObject, { side: "server" }); }
  sendMessage(text) { this.sendPacket(TextPacket.raw(textOf(text))); }
}

class Client extends Scope {
  constructor() {
    super("client", clientDefinitions);
    Object.defineProperty(this, "player_", { value: { player: null, triedAt: 0 }, writable: true });
    Object.defineProperty(this, "device_", { value: { change: null, hooked: false } });
  }
  setDevice({ os, model } = {}) {
    const change = {};
    if (os !== undefined) change.DeviceOS = osNumberOf(os);
    if (model !== undefined) change.DeviceModel = String(model);
    if (Object.keys(change).length === 0) throw new TypeError("setDevice({ os, model }): give an os, a model, or both");
    this.device_.change = { ...this.device_.change, ...change };
    if (this.device_.hooked) return;
    this.device_.hooked = true;
    if (!clientSendsAreSeen()) console.warn("setDevice: this client build cannot see the login it sends, so it cannot be changed");
    packet.on("loginPacket", (low) => {
      const change_ = this.device_.change;
      if (change_ === null) return;
      try { low.packet.setClientData(change_); } catch (error) { report(error, "client.setDevice"); }
    }, { side: "client", direction: "c2s" });
  }
  clearDevice() { this.device_.change = null; }
  get player() {
    const holder = this.player_;
    if (!holder.player) holder.player = new ClientPlayer();
    else if (!holder.player.isKnown && Date.now() - holder.triedAt > 1000) {
      holder.triedAt = Date.now();
      holder.player.loadSavedLogin();
    }
    return holder.player;
  }
  sendPacket(packetObject) { this.player.sendPacket(packetObject); }
  sendMessage(text) { this.player.sendMessage(text); }
  setActionBar(text) { this.player.setActionBar(text); }
  toast(title, body) { this.player.toast(title, body); }
  showTitle(title, subtitle, times) { this.player.showTitle(title, subtitle, times); }
  chat(message) { this.player.chat(message); }
  runCommand(command, options) { this.player.runCommand(command, options); }
}

const textMembers = {
)BCA";
            source += R"BCA(  type: { get: (c) => c.packet.type },
  message: { get: (c) => c.packet.message, set: (c, value) => { c.packet.message = String(value); } },
};
const senderOf = { get: (c) => c.scope.playerOf(c.low) };
const commandMember = { get: (c) => c.packet.command, set: (c, value) => { c.packet.command = String(value); } };
const notOurs = (p, scope) => !scope.formState_.own.has(p.formId);

const hostDefinitions = [
  spec("playerLogin", "loginPacket", "c2s", null, {
    player: { get: (c) => memo(c, "player", () => c.scope.playerOf(c.low).applyLogin(c.packet)) },
    login: { get: (c) => c.packet },
    protocol: { get: (c) => c.packet.protocol },
  }),
  spec("chatSend", "textPacket", "c2s", (p) => p.type === "chat", { sender: senderOf, message: textMembers.message }),
  spec("commandSend", "commandRequestPacket", "c2s", null, { sender: senderOf, command: commandMember }),
  spec("formResponse", "modalFormResponsePacket", "c2s", notOurs, {
    sender: senderOf,
    formId: { get: (c) => c.packet.formId },
    response: { get: (c) => answerOf(c.packet).response },
    canceled: { get: (c) => answerOf(c.packet).canceled },
    cancelReason: { get: (c) => c.packet.cancelReason },
  }),
];

const clientDefinitions = [
  spec("chatSend", "textPacket", "c2s", (p) => p.type === "chat", { message: textMembers.message }),
  spec("commandSend", "commandRequestPacket", "c2s", null, { command: commandMember }),
  spec("textReceive", "textPacket", "s2c", null, {
    type: textMembers.type,
    sender: { get: (c) => c.packet.sender },
    message: textMembers.message,
    parameters: { get: (c) => c.packet.parameters },
  }),
  spec("formShow", "modalFormRequestPacket", "s2c", notOurs, {
    formId: { get: (c) => c.packet.formId },
    form: { get: (c) => c.packet.json, set: (c, value) => { c.packet.json = value; } },
  }, {
    respond(c, event, answer) {
      event.cancel = true;
      ModalFormResponsePacket.response(c.packet.formId, answer).send();
    },
    close(c, event) {
      event.cancel = true;
      ModalFormResponsePacket.cancel(c.packet.formId).send();
    },
  }),
  spec("formResponseSend", "modalFormResponsePacket", "c2s", notOurs, {
    formId: { get: (c) => c.packet.formId },
    response: { get: (c) => answerOf(c.packet).response },
    canceled: { get: (c) => answerOf(c.packet).canceled },
  }),
  spec("disconnect", "disconnectPacket", "s2c", null, {
    reason: { get: (c) => c.packet.reason },
    message: { get: (c) => c.packet.message, set: (c, value) => { c.packet.message = value; } },
  }),
];

const shownBars = new Set();
let bossResetWatch = false;
const watchBossResets = () => {
  if (bossResetWatch) return;
  bossResetWatch = true;
  const targets = [["client", () => client.player], ["server", (low) => host.players_.get(low.player)]];
  for (const [side, whoIs] of targets) {
    for (const name of ["changeDimensionPacket", "respawnPacket"]) {
      try {
        packet.on(name, (low) => {
          const player = whoIs(low);
          if (!player || shownBars.size === 0) return;
          setTimeout(() => { for (const bar of [...shownBars]) bar.resend_(player); }, 250);
        }, { side, direction: "s2c" });
      } catch (error) {  }
    }
  }
};

class BossBar {
  constructor({ title = "", percent = 1, color = "pink", actorId } = {}) {
    this.actorId = actorId === undefined ? null : BigInt(actorId);
    Object.defineProperty(this, "state_", { value: { name: String(title), percent: BossBar.clamp_(percent), color } });
    Object.defineProperty(this, "ids_", { value: new Map() });
  }
  static clamp_(value) {
    const number = Number(value);
    return Number.isFinite(number) ? Math.min(1, Math.max(0, number)) : 0;
  }
  get title() { return this.state_.name; }
  set title(value) { this.state_.name = String(value); this.each_((id) => BossEventPacket.updateName(id, this.state_.name, this.state_)); }
  get percent() { return this.state_.percent; }
  set percent(value) {
    this.state_.percent = BossBar.clamp_(value);
    this.each_((id) => BossEventPacket.updatePercent(id, this.state_.percent, this.state_));
  }
  get color() { return this.state_.color; }
  set color(value) { this.state_.color = value; this.each_((id) => BossEventPacket.updateStyle(id, value, this.state_)); }
  get targets() { return [...this.ids_.keys()]; }
  each_(make) {
    let failure = null;
    for (const [target, id] of this.ids_) {
      try { target.sendPacket(make(id)); } catch (error) { failure = failure ?? error; }
    }
    if (failure) throw failure;
  }
  playersOf_(target) {
    if (target === host) return host.players;
    if (target === client) return [client.player];
    return [target];
  }
  add_(player, id) {
    player.sendPacket(BossEventPacket.add(id, this.state_));
  }
  resend_(player) {
    const id = this.ids_.get(player);
    if (id === undefined) return;
    try { this.add_(player, id); } catch (error) { report(error, "boss bar: put back"); }
  }
  show(target) {
    for (const player of this.playersOf_(target)) {
      const id = this.actorId ?? player.actorUniqueId;
      if (id === null) {
        throw new Error("the boss bar needs the actor id of " + player + ", which the game has not shown to the script yet " +
                        "(rejoin the world after the DLL is injected, or pass { actorId })");
      }
      if (this.ids_.has(player)) player.sendPacket(BossEventPacket.remove(this.ids_.get(player), this.state_));
      this.add_(player, id);
      this.ids_.set(player, id);
    }
    shownBars.add(this);
    watchBossResets();
    return this;
  }
  refresh() {
    for (const [player, id] of this.ids_) this.add_(player, id);
    return this;
  }
  hide(target) {
    if (target === undefined) return this.remove();
    for (const player of this.playersOf_(target)) {
      const id = this.ids_.get(player);
      if (id === undefined) continue;
      this.ids_.delete(player);
      player.sendPacket(BossEventPacket.remove(id, this.state_));
    }
)BCA";
            source += R"BCA(    if (this.ids_.size === 0) shownBars.delete(this);
    return this;
  }
  remove() {
    this.each_((id) => BossEventPacket.remove(id, this.state_));
    this.ids_.clear();
    shownBars.delete(this);
    return this;
  }
}

const CommandPermissionLevel = Object.freeze({ Any: 0, GameDirectors: 1, Admin: 2, Host: 3, Owner: 4 });
const permissionNames = ["Any", "GameDirectors", "Admin", "Host", "Owner"];
const CustomCommandStatus = Object.freeze({ Success: 0, Failure: 1 });
const CustomCommandParamType = Object.freeze({
  Boolean: "Boolean", Integer: "Integer", Float: "Float", String: "String", EntitySelector: "EntitySelector",
  PlayerSelector: "PlayerSelector", Location: "Location", BlockType: "BlockType", ItemType: "ItemType", Enum: "Enum", Message: "Message",
});
const paramWire = { Integer: { type: "int" }, Float: { type: "float" }, String: { type: "string" }, EntitySelector: { type: "target" },
                    PlayerSelector: { type: "target" }, Location: { type: "position" }, BlockType: { type: "string" },
                    ItemType: { type: "string" }, Message: { type: "message" }, Boolean: { enum: ["true", "false"], enumName: "bca:boolean" } };

const wordsOf = (text) => [...text.matchAll(/"((?:[^"\\]|\\.)*)"|(\S+)/g)].map((m) => ({ text: m[1] !== undefined ? m[1].replace(/\\(.)/g, "$1") : m[2], start: m.index }));
const coordinate = (word) => (/^[~^]/.test(word) ? word : Number(word));

const parseArguments = (definition, enums, line) => {
  const words = wordsOf(line);
  const params = [...definition.mandatoryParameters, ...definition.optionalParameters];
  const args = [];
  let at = 0;
  for (const [index, param] of params.entries()) {
    const optional = index >= definition.mandatoryParameters.length;
    if (at >= words.length) {
      if (optional) { args.push(undefined); continue; }
      return { error: "missing the argument \"" + param.name + "\"" };
    }
    const word = words[at].text;
    switch (param.type) {
      case "Integer":
        if (!/^-?\d+$/.test(word)) return { error: "\"" + param.name + "\" must be a whole number, not \"" + word + "\"" };
        args.push(Number(word));
        break;
      case "Float":
        if (word === "" || !Number.isFinite(Number(word))) return { error: "\"" + param.name + "\" must be a number, not \"" + word + "\"" };
        args.push(Number(word));
        break;
      case "Boolean":
        if (word !== "true" && word !== "false") return { error: "\"" + param.name + "\" is true or false, not \"" + word + "\"" };
        args.push(word === "true");
        break;
      case "Enum": {
        const values = enums.get(param.enumName) ?? [];
        const found = values.find((value) => value.toLowerCase() === word.toLowerCase());
        if (found === undefined) return { error: "\"" + param.name + "\" is one of: " + values.join(", ") };
        args.push(found);
        break;
      }
      case "Location": {
        if (at + 2 >= words.length) return { error: "\"" + param.name + "\" needs three coordinates" };
        args.push({ x: coordinate(words[at].text), y: coordinate(words[at + 1].text), z: coordinate(words[at + 2].text) });
        at += 2;
        break;
      }
      case "Message":
        args.push(line.slice(words[at].start));
        at = words.length - 1;
        break;
      default:
        args.push(word);
    }
    at++;
  }
  if (at < words.length) return { error: "too many arguments" };
  return { args };
};

const usageOf = (definition) => "/" + definition.name + [
  ...definition.mandatoryParameters.map((p) => " <" + p.name + ": " + p.type + ">"),
  ...definition.optionalParameters.map((p) => " [" + p.name + ": " + p.type + "]"),
].join("");

class CommandBook {
  constructor(scope) {
    Object.defineProperty(this, "scope_", { value: scope });
    Object.defineProperty(this, "resend_", { value: { timer: null } });
    this.commands = new Map();
    this.enums = new Map();
    this.hidden = new Map();
    this.hooked = false;
  }
  hook() {
    if (this.hooked) return;
    this.hooked = true;
    const side = this.scope_.side;
    if (side === "client" && !clientSendsAreSeen()) {
      ownServerLink.watch(["commandRequestPacket"], (low) => this.onRequest(low));
    } else {
      packet.on("commandRequestPacket", (low) => this.onRequest(low), { side, direction: "c2s" });
    }
    packet.on("availableCommandsPacket", (low) => this.onList(low), { side, direction: "s2c" });
  }
  senderOf(low) {
    return this.scope_ === client ? client.player : host.playerOf(low);
  }
  onRequest(low) {
    if (this.scope_ === host && !clientSendsAreSeen()) {
      try { ownServerLink.learn(low); } catch (error) { report(error, "own connection"); }
      if (ownServerLink.isMine(low)) return;
    }
    let body;
    try { body = low.packet; } catch (error) { return; }
    const line = String(body.command).trim().replace(/^\//, "");
    const space = line.search(/\s/);
    const word = (space < 0 ? line : line.slice(0, space)).toLowerCase();
    const entry = this.commands.get(word);
    if (!entry) {
      if (this.hidden.get(word.replace(/^minecraft:/, "")) === true) {
        low.cancel();
        this.senderOf(low).sendMessage("§cUnknown command: " + word + ". Please check that the command exists and that you have permission to use it.");
      }
      return;
    }
    low.cancel();
    const sender = this.senderOf(low);
    const answer = (result) => {
      if (!result || result.message === undefined || result.message === "") return;
      sender.sendMessage((result.status === CustomCommandStatus.Failure ? "§c" : "") + result.message);
    };
    const parsed = parseArguments(entry.definition, this.enums, space < 0 ? "" : line.slice(space + 1));
    if (parsed.error) {
      answer({ status: CustomCommandStatus.Failure, message: "Syntax error: " + parsed.error + "\nUsage: " + usageOf(entry.definition) });
      return;
    }
    const fail = (error) => {
)BCA";
            source += R"BCA(      report(error, "command " + entry.definition.name);
      answer({ status: CustomCommandStatus.Failure, message: "The command failed" });
    };
    try {
      const result = entry.callback({ sourceType: "Entity", sourceEntity: sender }, ...parsed.args);
      if (result && typeof result.then === "function") result.then(answer, fail);
      else answer(result);
    } catch (error) {
      fail(error);
    }
  }
  wireCommands_() {
    const wire = (param) => ({
      name: param.name, optional: param.optional,
      ...(param.type === "Enum" ? { enum: this.enums.get(param.enumName), enumName: param.enumName } : paramWire[param.type]),
    });
    return [...this.commands.values()].map(({ definition }) => ({
      name: definition.name, description: definition.description, permission: permissionNames[definition.permissionLevel] ?? "Any",
      overloads: [[...definition.mandatoryParameters.map((p) => wire({ ...p, optional: false })),
                   ...definition.optionalParameters.map((p) => wire({ ...p, optional: true }))]],
    }));
  }
  onList(low) {
    if (this.commands.size === 0 && this.hidden.size === 0) return;
    try {
      this.original_ = low.body;
      this.spreadHidden_(low.body);
      low.replace(AvailableCommandsPacket.patch(low.body, this.wireCommands_(), { remove: [...this.hidden.keys()] }));
    } catch (error) {
      report(error, "commands: the command list could not be extended");
    }
  }
  spreadHidden_(body) {
    if (this.hidden.size === 0) return;
    const block = [...this.hidden.values()].some((value) => value === true);
    const known = new Map(this.hidden);
    for (const word of AvailableCommandsPacket.namesOf(body, [...known.keys()])) {
      if (known.has(word)) continue;
      const from = [...known.keys()].find((key) => AvailableCommandsPacket.namesOf(body, [key]).includes(word));
      this.hidden.set(word, from === undefined ? block : known.get(from));
    }
  }
  changed() {
    if (this.scope_.side !== "client" || this.resend_.timer !== null) return;
    this.resend_.timer = setTimeout(() => {
      this.resend_.timer = null;
      try {
        const original = this.original_ ?? (typeof native.lastPacket === "function" ? native.lastPacket(packet.id("availableCommandsPacket")) : undefined);
        if (!original || original.length === 0) return;
        this.original_ = original;
        this.spreadHidden_(original);
        packet.send("availableCommandsPacket", AvailableCommandsPacket.patch(original, this.wireCommands_(), { remove: [...this.hidden.keys()] }), { side: "client", direction: "s2c" });
      } catch (error) {
        report(error, "commands: the command list could not be sent again");
      }
    }, TICK_MS);
  }
}

const checkParams = (list, kind, enums) => {
  if (list !== undefined && !Array.isArray(list)) throw new TypeError(kind + " is a list of { name, type }");
  return (list ?? []).map((param) => {
    if (!param || typeof param.name !== "string" || param.name === "") throw new TypeError("every parameter has a name");
    if (!(param.type in CustomCommandParamType)) throw new RangeError('unknown parameter type "' + param.type + '" (CustomCommandParamType)');
    if (param.type === "Enum" && !enums.has(param.enumName)) throw new RangeError('register the enum "' + param.enumName + '" first (registerEnum)');
    return { name: param.name, type: param.type, enumName: param.enumName };
  });
};

class CustomCommandRegistry {
  constructor(books) {
    Object.defineProperty(this, "books_", { value: books });
  }
  registerEnum(name, values) {
    if (typeof name !== "string" || name === "") throw new TypeError("an enum needs a name");
    if (!Array.isArray(values) || values.length === 0) throw new TypeError("an enum needs a list of words");
    for (const book of this.books_) book.enums.set(name, values.map(String));
  }
  registerCommand(command, callback) {
    if (!command || typeof command.name !== "string" || command.name === "" || /\s/.test(command.name)) throw new TypeError("a command needs a name without spaces");
    if (typeof callback !== "function") throw new TypeError("registerCommand needs a callback function");
    const key = command.name.toLowerCase();
    const made = this.books_.map((book) => {
      if (book.commands.has(key)) throw new Error('the command "' + command.name + '" is already registered');
      return {
        book,
        definition: {
          name: command.name, description: String(command.description ?? ""), permissionLevel: command.permissionLevel ?? CommandPermissionLevel.Any,
          mandatoryParameters: checkParams(command.mandatoryParameters, "mandatoryParameters", book.enums),
          optionalParameters: checkParams(command.optionalParameters, "optionalParameters", book.enums),
        },
      };
    });
    for (const { book, definition } of made) {
      book.commands.set(key, { definition, callback });
      book.hook();
      book.changed();
    }
  }
  unregisterCommand(name) {
    const key = String(name).toLowerCase();
    let removed = false;
    for (const book of this.books_) {
      if (book.commands.delete(key)) {
        removed = true;
        book.changed();
      }
    }
    return removed;
  }
  hideCommand(name, options = {}) {
    if (typeof name !== "string" || name === "" || /\s/.test(name)) throw new TypeError("a command needs a name without spaces");
    const key = name.toLowerCase().replace(/^minecraft:/, "");
    const block = options.block !== false;
    for (const book of this.books_) {
      book.hidden.set(key, block);
      book.hook();
      book.changed();
    }
  }
  showCommand(name) {
    const key = String(name).toLowerCase().replace(/^minecraft:/, "");
    let shown = false;
    for (const book of this.books_) {
      let group = [key];
      try { if (book.original_) group = AvailableCommandsPacket.namesOf(book.original_, [key]).concat(key); } catch (error) {  }
      let any = false;
)BCA";
            source += R"BCA(      for (const word of group) if (book.hidden.delete(word)) any = true;
      if (any) {
        shown = true;
        book.changed();
      }
    }
    return shown;
  }
}

const host = new Host();
const client = new Client();
const startupRegistry = new CustomCommandRegistry([client.book_, host.book_]);
const startupSignal = Object.freeze({
  subscribe(callback) {
    if (typeof callback !== "function") throw new TypeError("subscribe needs a function");
    Promise.resolve().then(() => {
      try { callback({ customCommandRegistry: startupRegistry }); } catch (error) { report(error, "startup"); }
    });
    return callback;
  },
  unsubscribe: () => false,
});
const system = Object.freeze({
  get currentTick() { return Math.floor((Date.now() - startedAt) / TICK_MS); },
  run: (callback) => setTimeout(callback, TICK_MS),
  runTimeout: (callback, ticks = 1) => setTimeout(callback, Math.max(1, ticks) * TICK_MS),
  runInterval: (callback, ticks = 1) => setInterval(callback, Math.max(1, ticks) * TICK_MS),
  clearRun: (id) => clearTimeout(id),
  waitTicks: (ticks = 1) => new Promise((resolve) => setTimeout(resolve, Math.max(1, ticks) * TICK_MS)),
  beforeEvents: Object.freeze({ startup: startupSignal }),
});

export { system, host, client, Player, ClientPlayer, BossBar, CommandPermissionLevel, CustomCommandParamType, CustomCommandStatus };
)BCA";
            list.push_back({"bedrock-client-api", false, std::move(source)});
        }
        {
            std::string source;
            source += R"BCA(
class ActionFormData {
  constructor() { this.form_ = { type: "form", title: "", content: "", buttons: [] }; }
  title(text) { this.form_.title = String(text); return this; }
  body(text) { this.form_.content = String(text); return this; }
  button(text, iconPath) {
    const button = { text: String(text) };
    if (iconPath !== undefined) button.image = { type: /^https?:/.test(iconPath) ? "url" : "path", data: String(iconPath) };
    this.form_.buttons.push(button);
    return this;
  }
  toJSON() { return this.form_; }
  async show(player) {
    const answer = await player.showForm(this);
    return { canceled: answer.canceled, cancelReason: answer.cancelReason ?? undefined,
             selection: answer.canceled ? undefined : answer.response };
  }
}

class ModalFormData {
  constructor() { this.form_ = { type: "custom_form", title: "", content: [] }; }
  title(text) { this.form_.title = String(text); return this; }
  label(text) { this.form_.content.push({ type: "label", text: String(text) }); return this; }
  textField(label, placeholder = "", defaultValue = "") {
    this.form_.content.push({ type: "input", text: String(label), placeholder: String(placeholder), default: String(defaultValue) });
    return this;
  }
  toggle(label, defaultValue = false) {
    this.form_.content.push({ type: "toggle", text: String(label), default: Boolean(defaultValue) });
    return this;
  }
  slider(label, min, max, step = 1, defaultValue = min) {
    this.form_.content.push({ type: "slider", text: String(label), min, max, step, default: defaultValue });
    return this;
  }
  dropdown(label, options, defaultIndex = 0) {
    this.form_.content.push({ type: "dropdown", text: String(label), options: options.map(String), default: defaultIndex });
    return this;
  }
  toJSON() { return this.form_; }
  async show(player) {
    const answer = await player.showForm(this);
    return { canceled: answer.canceled, cancelReason: answer.cancelReason ?? undefined,
             formValues: answer.canceled ? undefined : answer.response };
  }
}

class MessageFormData {
  constructor() { this.form_ = { type: "modal", title: "", content: "", button1: "", button2: "" }; }
  title(text) { this.form_.title = String(text); return this; }
  body(text) { this.form_.content = String(text); return this; }
  button1(text) { this.form_.button1 = String(text); return this; }
  button2(text) { this.form_.button2 = String(text); return this; }
  toJSON() { return this.form_; }
  async show(player) {
    const answer = await player.showForm(this);
    return { canceled: answer.canceled, cancelReason: answer.cancelReason ?? undefined,
             selection: answer.canceled ? undefined : (answer.response === true ? 0 : 1) };
  }
}

export { ActionFormData, ModalFormData, MessageFormData };
)BCA";
            list.push_back({"bedrock-client-api/ui", false, std::move(source)});
        }
        {
            std::string source;
            source += R"BCA(import native from "bedrock-client-api/native";
import { utf8 } from "bedrock-client-api/core";

if (!native.permitted("fs")) {
  throw new Error(`fs: the script "${native.scriptName()}" is not allowed to use files. Add the line "${native.scriptName()} = fs" to scripts/permissions.txt`);
}

const call = (fn, ...args) => {
  try {
    return fn(...args);
  } catch (error) {
    const code = /^([A-Z]+):/.exec(String(error && error.message));
    if (code) error.code = code[1];
    throw error;
  }
};

const toBytes = (data) => {
  if (typeof data === "string") return utf8.encode(data);
  if (data instanceof Uint8Array) return data;
  if (data instanceof ArrayBuffer) return new Uint8Array(data);
  if (ArrayBuffer.isView(data)) return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
  throw new TypeError("fs: data must be a string, a Uint8Array or an ArrayBuffer");
};
const encodingOf = (options) => (typeof options === "string" ? options : options && options.encoding);

function readFileSync(path, options) {
  const encoding = encodingOf(options);
  if (encoding !== undefined && encoding !== null && String(encoding).toLowerCase().replace("-", "") !== "utf8") {
    throw new TypeError('fs: the only encoding is "utf8"');
  }
  const bytes = call(native.fsRead, String(path));
  return encoding === undefined || encoding === null ? bytes : utf8.decode(bytes);
}
function writeFileSync(path, data) {
  call(native.fsWrite, String(path), toBytes(data), false);
}
function appendFileSync(path, data) {
  call(native.fsWrite, String(path), toBytes(data), true);
}
function existsSync(path) {
  try { return native.fsExists(String(path)); } catch (error) { return false; }
}
function mkdirSync(path, options) {
  call(native.fsMkdir, String(path), Boolean(options && options.recursive));
}
function readdirSync(path = "/") {
  return call(native.fsList, String(path));
}
function rmSync(path, options) {
  call(native.fsRemove, String(path), Boolean(options && options.recursive), Boolean(options && options.force));
}
const unlinkSync = (path) => rmSync(path);
function statSync(path) {
  const info = call(native.fsStat, String(path));
  if (info === null) {
    const error = new Error(`ENOENT: no such file or directory, stat '${path}'`);
    error.code = "ENOENT";
    throw error;
  }
  return { size: info.size, mtimeMs: info.mtimeMs, isFile: () => info.isFile, isDirectory: () => info.isDirectory };
}

const readJsonSync = (path) => JSON.parse(readFileSync(path, "utf8"));
const writeJsonSync = (path, value) => writeFileSync(path, JSON.stringify(value, null, 2));

const promises = Object.freeze({
  readFile: async (...args) => readFileSync(...args),
  writeFile: async (...args) => writeFileSync(...args),
  appendFile: async (...args) => appendFileSync(...args),
  mkdir: async (...args) => mkdirSync(...args),
  readdir: async (...args) => readdirSync(...args),
  rm: async (...args) => rmSync(...args),
  unlink: async (...args) => unlinkSync(...args),
  stat: async (...args) => statSync(...args),
  readJson: async (...args) => readJsonSync(...args),
  writeJson: async (...args) => writeJsonSync(...args),
});

const fs = { readFileSync, writeFileSync, appendFileSync, existsSync, mkdirSync, readdirSync, rmSync, unlinkSync, statSync,
             readJsonSync, writeJsonSync, promises };
export { readFileSync, writeFileSync, appendFileSync, existsSync, mkdirSync, readdirSync, rmSync, unlinkSync, statSync,
         readJsonSync, writeJsonSync, promises };
export default fs;
)BCA";
            list.push_back({"fs", false, std::move(source)});
        }
        {
            std::string source;
            source += R"BCA(
const sep = "/";
const delimiter = ":";

function normalize(path) {
  path = String(path);
  if (path === "") return ".";
  const absolute = path.startsWith("/");
  const trailing = path.endsWith("/");
  const out = [];
  for (const part of path.split("/")) {
    if (part === "" || part === ".") continue;
    if (part === "..") {
      if (out.length > 0 && out[out.length - 1] !== "..") out.pop();
      else if (!absolute) out.push("..");
    } else {
      out.push(part);
    }
  }
  let result = out.join("/");
  if (result === "" && !absolute) return trailing ? "./" : ".";
  if (result !== "" && trailing) result += "/";
  return (absolute ? "/" : "") + result;
}

function join(...parts) {
  const joined = parts.map(String).filter((part) => part !== "").join("/");
  return joined === "" ? "." : normalize(joined);
}

function resolve(...parts) {
  let resolved = "";
  for (let i = parts.length - 1; i >= 0 && !resolved.startsWith("/"); i--) {
    const part = String(parts[i]);
    if (part !== "") resolved = resolved === "" ? part : part + "/" + resolved;
  }
  if (!resolved.startsWith("/")) resolved = "/" + resolved;
  const normalized = normalize(resolved);
  return normalized.length > 1 && normalized.endsWith("/") ? normalized.slice(0, -1) : normalized;
}

function isAbsolute(path) {
  return String(path).startsWith("/");
}

function dirname(path) {
  path = String(path);
  if (path === "") return ".";
  const trimmed = path.length > 1 ? path.replace(/\/+$/, "") : path;
  const index = trimmed.lastIndexOf("/");
  if (index < 0) return ".";
  if (index === 0) return "/";
  return trimmed.slice(0, index);
}

function basename(path, extension) {
  const trimmed = String(path).replace(/\/+$/, "");
  let base = trimmed.slice(trimmed.lastIndexOf("/") + 1);
  if (extension && base.endsWith(extension) && base !== extension) base = base.slice(0, -extension.length);
  return base;
}

function extname(path) {
  const base = basename(path);
  const index = base.lastIndexOf(".");
  return index <= 0 ? "" : base.slice(index);
}

function relative(from, to) {
  const a = resolve(from).split("/").filter(Boolean);
  const b = resolve(to).split("/").filter(Boolean);
  let common = 0;
  while (common < a.length && common < b.length && a[common] === b[common]) common++;
  return [...a.slice(common).map(() => ".."), ...b.slice(common)].join("/");
}

function parse(path) {
  path = String(path);
  const base = basename(path);
  const extension = extname(path);
  const dir = dirname(path);
  return {
    root: path.startsWith("/") ? "/" : "",
    dir: dir === "." && !path.includes("/") ? "" : dir,
    base,
    ext: extension,
    name: extension === "" ? base : base.slice(0, -extension.length),
  };
}

function format(parts) {
  const dir = parts.dir ?? parts.root ?? "";
  const base = parts.base ?? (parts.name ?? "") + (parts.ext ?? "");
  if (dir === "") return base;
  return dir === parts.root ? dir + base : dir + "/" + base;
}

const path = { sep, delimiter, normalize, join, resolve, isAbsolute, dirname, basename, extname, relative, parse, format };
path.posix = path;

export { sep, delimiter, normalize, join, resolve, isAbsolute, dirname, basename, extname, relative, parse, format };
export const posix = path;
export default path;
)BCA";
            list.push_back({"path", false, std::move(source)});
        }
        {
            std::string source;
            source += R"BCA(import native from "bedrock-client-api/native";
import { utf8 } from "bedrock-client-api/core";

if (!native.permitted("http")) {
  throw new Error(`http: the script "${native.scriptName()}" is not allowed to use the network. Add the line "${native.scriptName()} = http" to scripts/permissions.txt`);
}

class Response {
  constructor(raw, url) {
    this.url = url;
    this.status = raw.status;
    this.ok = raw.status >= 200 && raw.status < 300;
    this.headers = {};
    for (let i = 0; i + 1 < raw.headers.length; i += 2) {
      const name = raw.headers[i].toLowerCase();
      this.headers[name] = name in this.headers ? this.headers[name] + ", " + raw.headers[i + 1] : raw.headers[i + 1];
    }
    Object.defineProperty(this, "body_", { value: raw.body });
  }
  async bytes() { return this.body_; }
  async arrayBuffer() { return this.body_.buffer.slice(this.body_.byteOffset, this.body_.byteOffset + this.body_.byteLength); }
  async text() { return utf8.decode(this.body_); }
  async json() { return JSON.parse(utf8.decode(this.body_)); }
}

async function fetch(url, init = {}) {
  const headers = {};
  for (const [name, value] of Object.entries(init.headers ?? {})) headers[name] = String(value);
  let body = init.body ?? null;
  if (body !== null) {
    if (typeof body === "string") body = utf8.encode(body);
    else if (body instanceof ArrayBuffer) body = new Uint8Array(body);
    else if (ArrayBuffer.isView(body)) body = new Uint8Array(body.buffer, body.byteOffset, body.byteLength);
    else {
      body = utf8.encode(JSON.stringify(body));
      if (!Object.keys(headers).some((name) => name.toLowerCase() === "content-type")) headers["Content-Type"] = "application/json";
    }
  }
  const raw = await native.httpRequest({
    url: String(url), method: String(init.method ?? (body === null ? "GET" : "POST")).toUpperCase(), headers: Object.entries(headers).flat(), body,
    timeout: init.timeout ?? 15000,
  });
  return new Response(raw, String(url));
}
const get = (url, init = {}) => fetch(url, { ...init, method: "GET" });
const post = (url, body, init = {}) => fetch(url, { ...init, method: "POST", body });

export { fetch, get, post, Response };
export default { fetch, get, post, Response };
)BCA";
            list.push_back({"http", false, std::move(source)});
        }
        {
            std::string source;
            source += R"BCA(import native from "bedrock-client-api/native";

if (!native.permitted("websocket")) {
  throw new Error(`websocket: the script "${native.scriptName()}" is not allowed to use sockets. Add the line "${native.scriptName()} = websocket" to scripts/permissions.txt`);
}

const TYPES = ["open", "message", "close", "error"];

class WebSocket {
  static CONNECTING = 0;
  static OPEN = 1;
  static CLOSING = 2;
  static CLOSED = 3;

  constructor(url, options = {}) {
    this.url = String(url);
    this.readyState = WebSocket.CONNECTING;
    this.bufferedAmount = 0;
    for (const type of TYPES) this["on" + type] = null;
    Object.defineProperty(this, "listeners_", { value: { open: [], message: [], close: [], error: [] } });
    const headers = {};
    for (const [name, value] of Object.entries(options.headers ?? {})) headers[name] = String(value);
    Object.defineProperty(this, "id_", {
      value: native.wsOpen(this.url, Object.entries(headers).flat(), (type, first, second) => this.dispatch_(type, first, second)),
    });
  }

  addEventListener(type, listener) {
    if (!(type in this.listeners_)) throw new TypeError("WebSocket events are open, message, close and error");
    this.listeners_[type].push(listener);
  }
  removeEventListener(type, listener) {
    const list = this.listeners_[type];
    if (list && list.includes(listener)) list.splice(list.indexOf(listener), 1);
  }

  send(data) {
    if (this.readyState !== WebSocket.OPEN) throw new Error("WebSocket is not open");
    native.wsSend(this.id_, typeof data === "string" ? data : data instanceof ArrayBuffer ? new Uint8Array(data) : data);
  }
  close(code = 1000, reason = "") {
    if (this.readyState >= WebSocket.CLOSING) return;
    this.readyState = WebSocket.CLOSING;
    native.wsClose(this.id_, code, String(reason));
  }

  dispatch_(type, first, second) {
    let event;
    if (type === "open") {
      this.readyState = WebSocket.OPEN;
      event = { type, target: this };
    } else if (type === "message") {
      event = { type, target: this, data: first };
    } else if (type === "close") {
      this.readyState = WebSocket.CLOSED;
      event = { type, target: this, code: first, reason: second };
    } else if (type === "error") {
      event = { type, target: this, message: first };
    } else {
      return;
    }
    const handlers = [this["on" + type], ...this.listeners_[type]].filter((handler) => typeof handler === "function");
    for (const handler of handlers) {
      try { handler.call(this, event); } catch (error) { console.error("websocket " + type + ":", error && error.stack ? error.stack : error); }
    }
  }
}

export { WebSocket };
export default WebSocket;
)BCA";
            list.push_back({"websocket", false, std::move(source)});
        }
        return list;
    }();
    return modules;
}

}