import { fileURLToPath } from 'url';
import { createRequire as topLevelCreateRequire } from 'module';
import { dirname as pathDirname } from 'path';
const require = topLevelCreateRequire(import.meta.url);
const __filename = fileURLToPath(import.meta.url);
const __dirname = pathDirname(__filename);

var __create = Object.create;
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __getProtoOf = Object.getPrototypeOf;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __require = /* @__PURE__ */ ((x) => typeof require !== "undefined" ? require : typeof Proxy !== "undefined" ? new Proxy(x, {
  get: (a, b) => (typeof require !== "undefined" ? require : a)[b]
}) : x)(function(x) {
  if (typeof require !== "undefined")
    return require.apply(this, arguments);
  throw Error('Dynamic require of "' + x + '" is not supported');
});
var __esm = (fn, res) => function __init() {
  return fn && (res = (0, fn[__getOwnPropNames(fn)[0]])(fn = 0)), res;
};
var __commonJS = (cb, mod) => function __require2() {
  return mod || (0, cb[__getOwnPropNames(cb)[0]])((mod = { exports: {} }).exports, mod), mod.exports;
};
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toESM = (mod, isNodeMode, target) => (target = mod != null ? __create(__getProtoOf(mod)) : {}, __copyProps(
  // If the importer is in node compatibility mode or this is not an ESM
  // file that has been converted to a CommonJS file using a Babel-
  // compatible transform (i.e. "__esModule" has not been set), then set
  // "default" to the CommonJS "module.exports" for node compatibility.
  isNodeMode || !mod || !mod.__esModule ? __defProp(target, "default", { value: mod, enumerable: true }) : target,
  mod
));
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// node_modules/.pnpm/@actions+core@1.10.1/node_modules/@actions/core/lib/utils.js
var require_utils = __commonJS({
  "node_modules/.pnpm/@actions+core@1.10.1/node_modules/@actions/core/lib/utils.js"(exports) {
    "use strict";
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.toCommandProperties = exports.toCommandValue = void 0;
    function toCommandValue(input) {
      if (input === null || input === void 0) {
        return "";
      } else if (typeof input === "string" || input instanceof String) {
        return input;
      }
      return JSON.stringify(input);
    }
    exports.toCommandValue = toCommandValue;
    function toCommandProperties(annotationProperties) {
      if (!Object.keys(annotationProperties).length) {
        return {};
      }
      return {
        title: annotationProperties.title,
        file: annotationProperties.file,
        line: annotationProperties.startLine,
        endLine: annotationProperties.endLine,
        col: annotationProperties.startColumn,
        endColumn: annotationProperties.endColumn
      };
    }
    exports.toCommandProperties = toCommandProperties;
  }
});

// node_modules/.pnpm/@actions+core@1.10.1/node_modules/@actions/core/lib/command.js
var require_command = __commonJS({
  "node_modules/.pnpm/@actions+core@1.10.1/node_modules/@actions/core/lib/command.js"(exports) {
    "use strict";
    var __createBinding = exports && exports.__createBinding || (Object.create ? function(o, m, k, k2) {
      if (k2 === void 0)
        k2 = k;
      Object.defineProperty(o, k2, { enumerable: true, get: function() {
        return m[k];
      } });
    } : function(o, m, k, k2) {
      if (k2 === void 0)
        k2 = k;
      o[k2] = m[k];
    });
    var __setModuleDefault = exports && exports.__setModuleDefault || (Object.create ? function(o, v) {
      Object.defineProperty(o, "default", { enumerable: true, value: v });
    } : function(o, v) {
      o["default"] = v;
    });
    var __importStar = exports && exports.__importStar || function(mod) {
      if (mod && mod.__esModule)
        return mod;
      var result = {};
      if (mod != null) {
        for (var k in mod)
          if (k !== "default" && Object.hasOwnProperty.call(mod, k))
            __createBinding(result, mod, k);
      }
      __setModuleDefault(result, mod);
      return result;
    };
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.issue = exports.issueCommand = void 0;
    var os = __importStar(__require("os"));
    var utils_1 = require_utils();
    function issueCommand(command, properties, message) {
      const cmd = new Command(command, properties, message);
      process.stdout.write(cmd.toString() + os.EOL);
    }
    exports.issueCommand = issueCommand;
    function issue(name, message = "") {
      issueCommand(name, {}, message);
    }
    exports.issue = issue;
    var CMD_STRING = "::";
    var Command = class {
      constructor(command, properties, message) {
        if (!command) {
          command = "missing.command";
        }
        this.command = command;
        this.properties = properties;
        this.message = message;
      }
      toString() {
        let cmdStr = CMD_STRING + this.command;
        if (this.properties && Object.keys(this.properties).length > 0) {
          cmdStr += " ";
          let first = true;
          for (const key in this.properties) {
            if (this.properties.hasOwnProperty(key)) {
              const val = this.properties[key];
              if (val) {
                if (first) {
                  first = false;
                } else {
                  cmdStr += ",";
                }
                cmdStr += `${key}=${escapeProperty(val)}`;
              }
            }
          }
        }
        cmdStr += `${CMD_STRING}${escapeData(this.message)}`;
        return cmdStr;
      }
    };
    function escapeData(s) {
      return utils_1.toCommandValue(s).replace(/%/g, "%25").replace(/\r/g, "%0D").replace(/\n/g, "%0A");
    }
    function escapeProperty(s) {
      return utils_1.toCommandValue(s).replace(/%/g, "%25").replace(/\r/g, "%0D").replace(/\n/g, "%0A").replace(/:/g, "%3A").replace(/,/g, "%2C");
    }
  }
});

// node_modules/.pnpm/uuid@8.3.2/node_modules/uuid/dist/esm-node/rng.js
import crypto from "crypto";
function rng() {
  if (poolPtr > rnds8Pool.length - 16) {
    crypto.randomFillSync(rnds8Pool);
    poolPtr = 0;
  }
  return rnds8Pool.slice(poolPtr, poolPtr += 16);
}
var rnds8Pool, poolPtr;
var init_rng = __esm({
  "node_modules/.pnpm/uuid@8.3.2/node_modules/uuid/dist/esm-node/rng.js"() {
    rnds8Pool = new Uint8Array(256);
    poolPtr = rnds8Pool.length;
  }
});

// node_modules/.pnpm/uuid@8.3.2/node_modules/uuid/dist/esm-node/regex.js
var regex_default;
var init_regex = __esm({
  "node_modules/.pnpm/uuid@8.3.2/node_modules/uuid/dist/esm-node/regex.js"() {
    regex_default = /^(?:[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}|00000000-0000-0000-0000-000000000000)$/i;
  }
});

// node_modules/.pnpm/uuid@8.3.2/node_modules/uuid/dist/esm-node/validate.js
function validate(uuid) {
  return typeof uuid === "string" && regex_default.test(uuid);
}
var validate_default;
var init_validate = __esm({
  "node_modules/.pnpm/uuid@8.3.2/node_modules/uuid/dist/esm-node/validate.js"() {
    init_regex();
    validate_default = validate;
  }
});

// node_modules/.pnpm/uuid@8.3.2/node_modules/uuid/dist/esm-node/stringify.js
function stringify(arr, offset = 0) {
  const uuid = (byteToHex[arr[offset + 0]] + byteToHex[arr[offset + 1]] + byteToHex[arr[offset + 2]] + byteToHex[arr[offset + 3]] + "-" + byteToHex[arr[offset + 4]] + byteToHex[arr[offset + 5]] + "-" + byteToHex[arr[offset + 6]] + byteToHex[arr[offset + 7]] + "-" + byteToHex[arr[offset + 8]] + byteToHex[arr[offset + 9]] + "-" + byteToHex[arr[offset + 10]] + byteToHex[arr[offset + 11]] + byteToHex[arr[offset + 12]] + byteToHex[arr[offset + 13]] + byteToHex[arr[offset + 14]] + byteToHex[arr[offset + 15]]).toLowerCase();
  if (!validate_default(uuid)) {
    throw TypeError("Stringified UUID is invalid");
  }
  return uuid;
}
var byteToHex, stringify_default;
var init_stringify = __esm({
  "node_modules/.pnpm/uuid@8.3.2/node_modules/uuid/dist/esm-node/stringify.js"() {
    init_validate();
    byteToHex = [];
    for (let i = 0; i < 256; ++i) {
      byteToHex.push((i + 256).toString(16).substr(1));
    }
    stringify_default = stringify;
  }
});

// node_modules/.pnpm/uuid@8.3.2/node_modules/uuid/dist/esm-node/v1.js
function v1(options, buf, offset) {
  let i = buf && offset || 0;
  const b = buf || new Array(16);
  options = options || {};
  let node = options.node || _nodeId;
  let clockseq = options.clockseq !== void 0 ? options.clockseq : _clockseq;
  if (node == null || clockseq == null) {
    const seedBytes = options.random || (options.rng || rng)();
    if (node == null) {
      node = _nodeId = [seedBytes[0] | 1, seedBytes[1], seedBytes[2], seedBytes[3], seedBytes[4], seedBytes[5]];
    }
    if (clockseq == null) {
      clockseq = _clockseq = (seedBytes[6] << 8 | seedBytes[7]) & 16383;
    }
  }
  let msecs = options.msecs !== void 0 ? options.msecs : Date.now();
  let nsecs = options.nsecs !== void 0 ? options.nsecs : _lastNSecs + 1;
  const dt = msecs - _lastMSecs + (nsecs - _lastNSecs) / 1e4;
  if (dt < 0 && options.clockseq === void 0) {
    clockseq = clockseq + 1 & 16383;
  }
  if ((dt < 0 || msecs > _lastMSecs) && options.nsecs === void 0) {
    nsecs = 0;
  }
  if (nsecs >= 1e4) {
    throw new Error("uuid.v1(): Can't create more than 10M uuids/sec");
  }
  _lastMSecs = msecs;
  _lastNSecs = nsecs;
  _clockseq = clockseq;
  msecs += 122192928e5;
  const tl = ((msecs & 268435455) * 1e4 + nsecs) % 4294967296;
  b[i++] = tl >>> 24 & 255;
  b[i++] = tl >>> 16 & 255;
  b[i++] = tl >>> 8 & 255;
  b[i++] = tl & 255;
  const tmh = msecs / 4294967296 * 1e4 & 268435455;
  b[i++] = tmh >>> 8 & 255;
  b[i++] = tmh & 255;
  b[i++] = tmh >>> 24 & 15 | 16;
  b[i++] = tmh >>> 16 & 255;
  b[i++] = clockseq >>> 8 | 128;
  b[i++] = clockseq & 255;
  for (let n = 0; n < 6; ++n) {
    b[i + n] = node[n];
  }
  return buf || stringify_default(b);
}
var _nodeId, _clockseq, _lastMSecs, _lastNSecs, v1_default;
var init_v1 = __esm({
  "node_modules/.pnpm/uuid@8.3.2/node_modules/uuid/dist/esm-node/v1.js"() {
    init_rng();
    init_stringify();
    _lastMSecs = 0;
    _lastNSecs = 0;
    v1_default = v1;
  }
});

// node_modules/.pnpm/uuid@8.3.2/node_modules/uuid/dist/esm-node/parse.js
function parse(uuid) {
  if (!validate_default(uuid)) {
    throw TypeError("Invalid UUID");
  }
  let v;
  const arr = new Uint8Array(16);
  arr[0] = (v = parseInt(uuid.slice(0, 8), 16)) >>> 24;
  arr[1] = v >>> 16 & 255;
  arr[2] = v >>> 8 & 255;
  arr[3] = v & 255;
  arr[4] = (v = parseInt(uuid.slice(9, 13), 16)) >>> 8;
  arr[5] = v & 255;
  arr[6] = (v = parseInt(uuid.slice(14, 18), 16)) >>> 8;
  arr[7] = v & 255;
  arr[8] = (v = parseInt(uuid.slice(19, 23), 16)) >>> 8;
  arr[9] = v & 255;
  arr[10] = (v = parseInt(uuid.slice(24, 36), 16)) / 1099511627776 & 255;
  arr[11] = v / 4294967296 & 255;
  arr[12] = v >>> 24 & 255;
  arr[13] = v >>> 16 & 255;
  arr[14] = v >>> 8 & 255;
  arr[15] = v & 255;
  return arr;
}
var parse_default;
var init_parse = __esm({
  "node_modules/.pnpm/uuid@8.3.2/node_modules/uuid/dist/esm-node/parse.js"() {
    init_validate();
    parse_default = parse;
  }
});

// node_modules/.pnpm/uuid@8.3.2/node_modules/uuid/dist/esm-node/v35.js
function stringToBytes(str) {
  str = unescape(encodeURIComponent(str));
  const bytes = [];
  for (let i = 0; i < str.length; ++i) {
    bytes.push(str.charCodeAt(i));
  }
  return bytes;
}
function v35_default(name, version2, hashfunc) {
  function generateUUID(value, namespace, buf, offset) {
    if (typeof value === "string") {
      value = stringToBytes(value);
    }
    if (typeof namespace === "string") {
      namespace = parse_default(namespace);
    }
    if (namespace.length !== 16) {
      throw TypeError("Namespace must be array-like (16 iterable integer values, 0-255)");
    }
    let bytes = new Uint8Array(16 + value.length);
    bytes.set(namespace);
    bytes.set(value, namespace.length);
    bytes = hashfunc(bytes);
    bytes[6] = bytes[6] & 15 | version2;
    bytes[8] = bytes[8] & 63 | 128;
    if (buf) {
      offset = offset || 0;
      for (let i = 0; i < 16; ++i) {
        buf[offset + i] = bytes[i];
      }
      return buf;
    }
    return stringify_default(bytes);
  }
  try {
    generateUUID.name = name;
  } catch (err) {
  }
  generateUUID.DNS = DNS;
  generateUUID.URL = URL2;
  return generateUUID;
}
var DNS, URL2;
var init_v35 = __esm({
  "node_modules/.pnpm/uuid@8.3.2/node_modules/uuid/dist/esm-node/v35.js"() {
    init_stringify();
    init_parse();
    DNS = "6ba7b810-9dad-11d1-80b4-00c04fd430c8";
    URL2 = "6ba7b811-9dad-11d1-80b4-00c04fd430c8";
  }
});

// node_modules/.pnpm/uuid@8.3.2/node_modules/uuid/dist/esm-node/md5.js
import crypto2 from "crypto";
function md5(bytes) {
  if (Array.isArray(bytes)) {
    bytes = Buffer.from(bytes);
  } else if (typeof bytes === "string") {
    bytes = Buffer.from(bytes, "utf8");
  }
  return crypto2.createHash("md5").update(bytes).digest();
}
var md5_default;
var init_md5 = __esm({
  "node_modules/.pnpm/uuid@8.3.2/node_modules/uuid/dist/esm-node/md5.js"() {
    md5_default = md5;
  }
});

// node_modules/.pnpm/uuid@8.3.2/node_modules/uuid/dist/esm-node/v3.js
var v3, v3_default;
var init_v3 = __esm({
  "node_modules/.pnpm/uuid@8.3.2/node_modules/uuid/dist/esm-node/v3.js"() {
    init_v35();
    init_md5();
    v3 = v35_default("v3", 48, md5_default);
    v3_default = v3;
  }
});

// node_modules/.pnpm/uuid@8.3.2/node_modules/uuid/dist/esm-node/v4.js
function v4(options, buf, offset) {
  options = options || {};
  const rnds = options.random || (options.rng || rng)();
  rnds[6] = rnds[6] & 15 | 64;
  rnds[8] = rnds[8] & 63 | 128;
  if (buf) {
    offset = offset || 0;
    for (let i = 0; i < 16; ++i) {
      buf[offset + i] = rnds[i];
    }
    return buf;
  }
  return stringify_default(rnds);
}
var v4_default;
var init_v4 = __esm({
  "node_modules/.pnpm/uuid@8.3.2/node_modules/uuid/dist/esm-node/v4.js"() {
    init_rng();
    init_stringify();
    v4_default = v4;
  }
});

// node_modules/.pnpm/uuid@8.3.2/node_modules/uuid/dist/esm-node/sha1.js
import crypto3 from "crypto";
function sha1(bytes) {
  if (Array.isArray(bytes)) {
    bytes = Buffer.from(bytes);
  } else if (typeof bytes === "string") {
    bytes = Buffer.from(bytes, "utf8");
  }
  return crypto3.createHash("sha1").update(bytes).digest();
}
var sha1_default;
var init_sha1 = __esm({
  "node_modules/.pnpm/uuid@8.3.2/node_modules/uuid/dist/esm-node/sha1.js"() {
    sha1_default = sha1;
  }
});

// node_modules/.pnpm/uuid@8.3.2/node_modules/uuid/dist/esm-node/v5.js
var v5, v5_default;
var init_v5 = __esm({
  "node_modules/.pnpm/uuid@8.3.2/node_modules/uuid/dist/esm-node/v5.js"() {
    init_v35();
    init_sha1();
    v5 = v35_default("v5", 80, sha1_default);
    v5_default = v5;
  }
});

// node_modules/.pnpm/uuid@8.3.2/node_modules/uuid/dist/esm-node/nil.js
var nil_default;
var init_nil = __esm({
  "node_modules/.pnpm/uuid@8.3.2/node_modules/uuid/dist/esm-node/nil.js"() {
    nil_default = "00000000-0000-0000-0000-000000000000";
  }
});

// node_modules/.pnpm/uuid@8.3.2/node_modules/uuid/dist/esm-node/version.js
function version(uuid) {
  if (!validate_default(uuid)) {
    throw TypeError("Invalid UUID");
  }
  return parseInt(uuid.substr(14, 1), 16);
}
var version_default;
var init_version = __esm({
  "node_modules/.pnpm/uuid@8.3.2/node_modules/uuid/dist/esm-node/version.js"() {
    init_validate();
    version_default = version;
  }
});

// node_modules/.pnpm/uuid@8.3.2/node_modules/uuid/dist/esm-node/index.js
var esm_node_exports = {};
__export(esm_node_exports, {
  NIL: () => nil_default,
  parse: () => parse_default,
  stringify: () => stringify_default,
  v1: () => v1_default,
  v3: () => v3_default,
  v4: () => v4_default,
  v5: () => v5_default,
  validate: () => validate_default,
  version: () => version_default
});
var init_esm_node = __esm({
  "node_modules/.pnpm/uuid@8.3.2/node_modules/uuid/dist/esm-node/index.js"() {
    init_v1();
    init_v3();
    init_v4();
    init_v5();
    init_nil();
    init_version();
    init_validate();
    init_stringify();
    init_parse();
  }
});

// node_modules/.pnpm/@actions+core@1.10.1/node_modules/@actions/core/lib/file-command.js
var require_file_command = __commonJS({
  "node_modules/.pnpm/@actions+core@1.10.1/node_modules/@actions/core/lib/file-command.js"(exports) {
    "use strict";
    var __createBinding = exports && exports.__createBinding || (Object.create ? function(o, m, k, k2) {
      if (k2 === void 0)
        k2 = k;
      Object.defineProperty(o, k2, { enumerable: true, get: function() {
        return m[k];
      } });
    } : function(o, m, k, k2) {
      if (k2 === void 0)
        k2 = k;
      o[k2] = m[k];
    });
    var __setModuleDefault = exports && exports.__setModuleDefault || (Object.create ? function(o, v) {
      Object.defineProperty(o, "default", { enumerable: true, value: v });
    } : function(o, v) {
      o["default"] = v;
    });
    var __importStar = exports && exports.__importStar || function(mod) {
      if (mod && mod.__esModule)
        return mod;
      var result = {};
      if (mod != null) {
        for (var k in mod)
          if (k !== "default" && Object.hasOwnProperty.call(mod, k))
            __createBinding(result, mod, k);
      }
      __setModuleDefault(result, mod);
      return result;
    };
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.prepareKeyValueMessage = exports.issueFileCommand = void 0;
    var fs = __importStar(__require("fs"));
    var os = __importStar(__require("os"));
    var uuid_1 = (init_esm_node(), __toCommonJS(esm_node_exports));
    var utils_1 = require_utils();
    function issueFileCommand(command, message) {
      const filePath = process.env[`GITHUB_${command}`];
      if (!filePath) {
        throw new Error(`Unable to find environment variable for file command ${command}`);
      }
      if (!fs.existsSync(filePath)) {
        throw new Error(`Missing file at path: ${filePath}`);
      }
      fs.appendFileSync(filePath, `${utils_1.toCommandValue(message)}${os.EOL}`, {
        encoding: "utf8"
      });
    }
    exports.issueFileCommand = issueFileCommand;
    function prepareKeyValueMessage(key, value) {
      const delimiter = `ghadelimiter_${uuid_1.v4()}`;
      const convertedValue = utils_1.toCommandValue(value);
      if (key.includes(delimiter)) {
        throw new Error(`Unexpected input: name should not contain the delimiter "${delimiter}"`);
      }
      if (convertedValue.includes(delimiter)) {
        throw new Error(`Unexpected input: value should not contain the delimiter "${delimiter}"`);
      }
      return `${key}<<${delimiter}${os.EOL}${convertedValue}${os.EOL}${delimiter}`;
    }
    exports.prepareKeyValueMessage = prepareKeyValueMessage;
  }
});

// node_modules/.pnpm/@actions+http-client@2.1.1/node_modules/@actions/http-client/lib/proxy.js
var require_proxy = __commonJS({
  "node_modules/.pnpm/@actions+http-client@2.1.1/node_modules/@actions/http-client/lib/proxy.js"(exports) {
    "use strict";
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.checkBypass = exports.getProxyUrl = void 0;
    function getProxyUrl(reqUrl) {
      const usingSsl = reqUrl.protocol === "https:";
      if (checkBypass(reqUrl)) {
        return void 0;
      }
      const proxyVar = (() => {
        if (usingSsl) {
          return process.env["https_proxy"] || process.env["HTTPS_PROXY"];
        } else {
          return process.env["http_proxy"] || process.env["HTTP_PROXY"];
        }
      })();
      if (proxyVar) {
        try {
          return new URL(proxyVar);
        } catch (_a) {
          if (!proxyVar.startsWith("http://") && !proxyVar.startsWith("https://"))
            return new URL(`http://${proxyVar}`);
        }
      } else {
        return void 0;
      }
    }
    exports.getProxyUrl = getProxyUrl;
    function checkBypass(reqUrl) {
      if (!reqUrl.hostname) {
        return false;
      }
      const reqHost = reqUrl.hostname;
      if (isLoopbackAddress(reqHost)) {
        return true;
      }
      const noProxy = process.env["no_proxy"] || process.env["NO_PROXY"] || "";
      if (!noProxy) {
        return false;
      }
      let reqPort;
      if (reqUrl.port) {
        reqPort = Number(reqUrl.port);
      } else if (reqUrl.protocol === "http:") {
        reqPort = 80;
      } else if (reqUrl.protocol === "https:") {
        reqPort = 443;
      }
      const upperReqHosts = [reqUrl.hostname.toUpperCase()];
      if (typeof reqPort === "number") {
        upperReqHosts.push(`${upperReqHosts[0]}:${reqPort}`);
      }
      for (const upperNoProxyItem of noProxy.split(",").map((x) => x.trim().toUpperCase()).filter((x) => x)) {
        if (upperNoProxyItem === "*" || upperReqHosts.some((x) => x === upperNoProxyItem || x.endsWith(`.${upperNoProxyItem}`) || upperNoProxyItem.startsWith(".") && x.endsWith(`${upperNoProxyItem}`))) {
          return true;
        }
      }
      return false;
    }
    exports.checkBypass = checkBypass;
    function isLoopbackAddress(host) {
      const hostLower = host.toLowerCase();
      return hostLower === "localhost" || hostLower.startsWith("127.") || hostLower.startsWith("[::1]") || hostLower.startsWith("[0:0:0:0:0:0:0:1]");
    }
  }
});

// node_modules/.pnpm/tunnel@0.0.6/node_modules/tunnel/lib/tunnel.js
var require_tunnel = __commonJS({
  "node_modules/.pnpm/tunnel@0.0.6/node_modules/tunnel/lib/tunnel.js"(exports) {
    "use strict";
    var net = __require("net");
    var tls = __require("tls");
    var http = __require("http");
    var https = __require("https");
    var events = __require("events");
    var assert = __require("assert");
    var util = __require("util");
    exports.httpOverHttp = httpOverHttp;
    exports.httpsOverHttp = httpsOverHttp;
    exports.httpOverHttps = httpOverHttps;
    exports.httpsOverHttps = httpsOverHttps;
    function httpOverHttp(options) {
      var agent = new TunnelingAgent(options);
      agent.request = http.request;
      return agent;
    }
    function httpsOverHttp(options) {
      var agent = new TunnelingAgent(options);
      agent.request = http.request;
      agent.createSocket = createSecureSocket;
      agent.defaultPort = 443;
      return agent;
    }
    function httpOverHttps(options) {
      var agent = new TunnelingAgent(options);
      agent.request = https.request;
      return agent;
    }
    function httpsOverHttps(options) {
      var agent = new TunnelingAgent(options);
      agent.request = https.request;
      agent.createSocket = createSecureSocket;
      agent.defaultPort = 443;
      return agent;
    }
    function TunnelingAgent(options) {
      var self = this;
      self.options = options || {};
      self.proxyOptions = self.options.proxy || {};
      self.maxSockets = self.options.maxSockets || http.Agent.defaultMaxSockets;
      self.requests = [];
      self.sockets = [];
      self.on("free", function onFree(socket, host, port, localAddress) {
        var options2 = toOptions(host, port, localAddress);
        for (var i = 0, len = self.requests.length; i < len; ++i) {
          var pending = self.requests[i];
          if (pending.host === options2.host && pending.port === options2.port) {
            self.requests.splice(i, 1);
            pending.request.onSocket(socket);
            return;
          }
        }
        socket.destroy();
        self.removeSocket(socket);
      });
    }
    util.inherits(TunnelingAgent, events.EventEmitter);
    TunnelingAgent.prototype.addRequest = function addRequest(req, host, port, localAddress) {
      var self = this;
      var options = mergeOptions({ request: req }, self.options, toOptions(host, port, localAddress));
      if (self.sockets.length >= this.maxSockets) {
        self.requests.push(options);
        return;
      }
      self.createSocket(options, function(socket) {
        socket.on("free", onFree);
        socket.on("close", onCloseOrRemove);
        socket.on("agentRemove", onCloseOrRemove);
        req.onSocket(socket);
        function onFree() {
          self.emit("free", socket, options);
        }
        function onCloseOrRemove(err) {
          self.removeSocket(socket);
          socket.removeListener("free", onFree);
          socket.removeListener("close", onCloseOrRemove);
          socket.removeListener("agentRemove", onCloseOrRemove);
        }
      });
    };
    TunnelingAgent.prototype.createSocket = function createSocket(options, cb) {
      var self = this;
      var placeholder = {};
      self.sockets.push(placeholder);
      var connectOptions = mergeOptions({}, self.proxyOptions, {
        method: "CONNECT",
        path: options.host + ":" + options.port,
        agent: false,
        headers: {
          host: options.host + ":" + options.port
        }
      });
      if (options.localAddress) {
        connectOptions.localAddress = options.localAddress;
      }
      if (connectOptions.proxyAuth) {
        connectOptions.headers = connectOptions.headers || {};
        connectOptions.headers["Proxy-Authorization"] = "Basic " + new Buffer(connectOptions.proxyAuth).toString("base64");
      }
      debug3("making CONNECT request");
      var connectReq = self.request(connectOptions);
      connectReq.useChunkedEncodingByDefault = false;
      connectReq.once("response", onResponse);
      connectReq.once("upgrade", onUpgrade);
      connectReq.once("connect", onConnect);
      connectReq.once("error", onError);
      connectReq.end();
      function onResponse(res) {
        res.upgrade = true;
      }
      function onUpgrade(res, socket, head) {
        process.nextTick(function() {
          onConnect(res, socket, head);
        });
      }
      function onConnect(res, socket, head) {
        connectReq.removeAllListeners();
        socket.removeAllListeners();
        if (res.statusCode !== 200) {
          debug3(
            "tunneling socket could not be established, statusCode=%d",
            res.statusCode
          );
          socket.destroy();
          var error = new Error("tunneling socket could not be established, statusCode=" + res.statusCode);
          error.code = "ECONNRESET";
          options.request.emit("error", error);
          self.removeSocket(placeholder);
          return;
        }
        if (head.length > 0) {
          debug3("got illegal response body from proxy");
          socket.destroy();
          var error = new Error("got illegal response body from proxy");
          error.code = "ECONNRESET";
          options.request.emit("error", error);
          self.removeSocket(placeholder);
          return;
        }
        debug3("tunneling connection has established");
        self.sockets[self.sockets.indexOf(placeholder)] = socket;
        return cb(socket);
      }
      function onError(cause) {
        connectReq.removeAllListeners();
        debug3(
          "tunneling socket could not be established, cause=%s\n",
          cause.message,
          cause.stack
        );
        var error = new Error("tunneling socket could not be established, cause=" + cause.message);
        error.code = "ECONNRESET";
        options.request.emit("error", error);
        self.removeSocket(placeholder);
      }
    };
    TunnelingAgent.prototype.removeSocket = function removeSocket(socket) {
      var pos = this.sockets.indexOf(socket);
      if (pos === -1) {
        return;
      }
      this.sockets.splice(pos, 1);
      var pending = this.requests.shift();
      if (pending) {
        this.createSocket(pending, function(socket2) {
          pending.request.onSocket(socket2);
        });
      }
    };
    function createSecureSocket(options, cb) {
      var self = this;
      TunnelingAgent.prototype.createSocket.call(self, options, function(socket) {
        var hostHeader = options.request.getHeader("host");
        var tlsOptions = mergeOptions({}, self.options, {
          socket,
          servername: hostHeader ? hostHeader.replace(/:.*$/, "") : options.host
        });
        var secureSocket = tls.connect(0, tlsOptions);
        self.sockets[self.sockets.indexOf(socket)] = secureSocket;
        cb(secureSocket);
      });
    }
    function toOptions(host, port, localAddress) {
      if (typeof host === "string") {
        return {
          host,
          port,
          localAddress
        };
      }
      return host;
    }
    function mergeOptions(target) {
      for (var i = 1, len = arguments.length; i < len; ++i) {
        var overrides = arguments[i];
        if (typeof overrides === "object") {
          var keys = Object.keys(overrides);
          for (var j = 0, keyLen = keys.length; j < keyLen; ++j) {
            var k = keys[j];
            if (overrides[k] !== void 0) {
              target[k] = overrides[k];
            }
          }
        }
      }
      return target;
    }
    var debug3;
    if (process.env.NODE_DEBUG && /\btunnel\b/.test(process.env.NODE_DEBUG)) {
      debug3 = function() {
        var args = Array.prototype.slice.call(arguments);
        if (typeof args[0] === "string") {
          args[0] = "TUNNEL: " + args[0];
        } else {
          args.unshift("TUNNEL:");
        }
        console.error.apply(console, args);
      };
    } else {
      debug3 = function() {
      };
    }
    exports.debug = debug3;
  }
});

// node_modules/.pnpm/tunnel@0.0.6/node_modules/tunnel/index.js
var require_tunnel2 = __commonJS({
  "node_modules/.pnpm/tunnel@0.0.6/node_modules/tunnel/index.js"(exports, module) {
    module.exports = require_tunnel();
  }
});

// node_modules/.pnpm/@actions+http-client@2.1.1/node_modules/@actions/http-client/lib/index.js
var require_lib = __commonJS({
  "node_modules/.pnpm/@actions+http-client@2.1.1/node_modules/@actions/http-client/lib/index.js"(exports) {
    "use strict";
    var __createBinding = exports && exports.__createBinding || (Object.create ? function(o, m, k, k2) {
      if (k2 === void 0)
        k2 = k;
      Object.defineProperty(o, k2, { enumerable: true, get: function() {
        return m[k];
      } });
    } : function(o, m, k, k2) {
      if (k2 === void 0)
        k2 = k;
      o[k2] = m[k];
    });
    var __setModuleDefault = exports && exports.__setModuleDefault || (Object.create ? function(o, v) {
      Object.defineProperty(o, "default", { enumerable: true, value: v });
    } : function(o, v) {
      o["default"] = v;
    });
    var __importStar = exports && exports.__importStar || function(mod) {
      if (mod && mod.__esModule)
        return mod;
      var result = {};
      if (mod != null) {
        for (var k in mod)
          if (k !== "default" && Object.hasOwnProperty.call(mod, k))
            __createBinding(result, mod, k);
      }
      __setModuleDefault(result, mod);
      return result;
    };
    var __awaiter = exports && exports.__awaiter || function(thisArg, _arguments, P, generator) {
      function adopt(value) {
        return value instanceof P ? value : new P(function(resolve2) {
          resolve2(value);
        });
      }
      return new (P || (P = Promise))(function(resolve2, reject) {
        function fulfilled(value) {
          try {
            step(generator.next(value));
          } catch (e) {
            reject(e);
          }
        }
        function rejected(value) {
          try {
            step(generator["throw"](value));
          } catch (e) {
            reject(e);
          }
        }
        function step(result) {
          result.done ? resolve2(result.value) : adopt(result.value).then(fulfilled, rejected);
        }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
      });
    };
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.HttpClient = exports.isHttps = exports.HttpClientResponse = exports.HttpClientError = exports.getProxyUrl = exports.MediaTypes = exports.Headers = exports.HttpCodes = void 0;
    var http = __importStar(__require("http"));
    var https = __importStar(__require("https"));
    var pm = __importStar(require_proxy());
    var tunnel = __importStar(require_tunnel2());
    var HttpCodes;
    (function(HttpCodes2) {
      HttpCodes2[HttpCodes2["OK"] = 200] = "OK";
      HttpCodes2[HttpCodes2["MultipleChoices"] = 300] = "MultipleChoices";
      HttpCodes2[HttpCodes2["MovedPermanently"] = 301] = "MovedPermanently";
      HttpCodes2[HttpCodes2["ResourceMoved"] = 302] = "ResourceMoved";
      HttpCodes2[HttpCodes2["SeeOther"] = 303] = "SeeOther";
      HttpCodes2[HttpCodes2["NotModified"] = 304] = "NotModified";
      HttpCodes2[HttpCodes2["UseProxy"] = 305] = "UseProxy";
      HttpCodes2[HttpCodes2["SwitchProxy"] = 306] = "SwitchProxy";
      HttpCodes2[HttpCodes2["TemporaryRedirect"] = 307] = "TemporaryRedirect";
      HttpCodes2[HttpCodes2["PermanentRedirect"] = 308] = "PermanentRedirect";
      HttpCodes2[HttpCodes2["BadRequest"] = 400] = "BadRequest";
      HttpCodes2[HttpCodes2["Unauthorized"] = 401] = "Unauthorized";
      HttpCodes2[HttpCodes2["PaymentRequired"] = 402] = "PaymentRequired";
      HttpCodes2[HttpCodes2["Forbidden"] = 403] = "Forbidden";
      HttpCodes2[HttpCodes2["NotFound"] = 404] = "NotFound";
      HttpCodes2[HttpCodes2["MethodNotAllowed"] = 405] = "MethodNotAllowed";
      HttpCodes2[HttpCodes2["NotAcceptable"] = 406] = "NotAcceptable";
      HttpCodes2[HttpCodes2["ProxyAuthenticationRequired"] = 407] = "ProxyAuthenticationRequired";
      HttpCodes2[HttpCodes2["RequestTimeout"] = 408] = "RequestTimeout";
      HttpCodes2[HttpCodes2["Conflict"] = 409] = "Conflict";
      HttpCodes2[HttpCodes2["Gone"] = 410] = "Gone";
      HttpCodes2[HttpCodes2["TooManyRequests"] = 429] = "TooManyRequests";
      HttpCodes2[HttpCodes2["InternalServerError"] = 500] = "InternalServerError";
      HttpCodes2[HttpCodes2["NotImplemented"] = 501] = "NotImplemented";
      HttpCodes2[HttpCodes2["BadGateway"] = 502] = "BadGateway";
      HttpCodes2[HttpCodes2["ServiceUnavailable"] = 503] = "ServiceUnavailable";
      HttpCodes2[HttpCodes2["GatewayTimeout"] = 504] = "GatewayTimeout";
    })(HttpCodes = exports.HttpCodes || (exports.HttpCodes = {}));
    var Headers;
    (function(Headers2) {
      Headers2["Accept"] = "accept";
      Headers2["ContentType"] = "content-type";
    })(Headers = exports.Headers || (exports.Headers = {}));
    var MediaTypes;
    (function(MediaTypes2) {
      MediaTypes2["ApplicationJson"] = "application/json";
    })(MediaTypes = exports.MediaTypes || (exports.MediaTypes = {}));
    function getProxyUrl(serverUrl) {
      const proxyUrl = pm.getProxyUrl(new URL(serverUrl));
      return proxyUrl ? proxyUrl.href : "";
    }
    exports.getProxyUrl = getProxyUrl;
    var HttpRedirectCodes = [
      HttpCodes.MovedPermanently,
      HttpCodes.ResourceMoved,
      HttpCodes.SeeOther,
      HttpCodes.TemporaryRedirect,
      HttpCodes.PermanentRedirect
    ];
    var HttpResponseRetryCodes = [
      HttpCodes.BadGateway,
      HttpCodes.ServiceUnavailable,
      HttpCodes.GatewayTimeout
    ];
    var RetryableHttpVerbs = ["OPTIONS", "GET", "DELETE", "HEAD"];
    var ExponentialBackoffCeiling = 10;
    var ExponentialBackoffTimeSlice = 5;
    var HttpClientError = class _HttpClientError extends Error {
      constructor(message, statusCode) {
        super(message);
        this.name = "HttpClientError";
        this.statusCode = statusCode;
        Object.setPrototypeOf(this, _HttpClientError.prototype);
      }
    };
    exports.HttpClientError = HttpClientError;
    var HttpClientResponse = class {
      constructor(message) {
        this.message = message;
      }
      readBody() {
        return __awaiter(this, void 0, void 0, function* () {
          return new Promise((resolve2) => __awaiter(this, void 0, void 0, function* () {
            let output = Buffer.alloc(0);
            this.message.on("data", (chunk) => {
              output = Buffer.concat([output, chunk]);
            });
            this.message.on("end", () => {
              resolve2(output.toString());
            });
          }));
        });
      }
      readBodyBuffer() {
        return __awaiter(this, void 0, void 0, function* () {
          return new Promise((resolve2) => __awaiter(this, void 0, void 0, function* () {
            const chunks = [];
            this.message.on("data", (chunk) => {
              chunks.push(chunk);
            });
            this.message.on("end", () => {
              resolve2(Buffer.concat(chunks));
            });
          }));
        });
      }
    };
    exports.HttpClientResponse = HttpClientResponse;
    function isHttps(requestUrl) {
      const parsedUrl = new URL(requestUrl);
      return parsedUrl.protocol === "https:";
    }
    exports.isHttps = isHttps;
    var HttpClient = class {
      constructor(userAgent, handlers, requestOptions) {
        this._ignoreSslError = false;
        this._allowRedirects = true;
        this._allowRedirectDowngrade = false;
        this._maxRedirects = 50;
        this._allowRetries = false;
        this._maxRetries = 1;
        this._keepAlive = false;
        this._disposed = false;
        this.userAgent = userAgent;
        this.handlers = handlers || [];
        this.requestOptions = requestOptions;
        if (requestOptions) {
          if (requestOptions.ignoreSslError != null) {
            this._ignoreSslError = requestOptions.ignoreSslError;
          }
          this._socketTimeout = requestOptions.socketTimeout;
          if (requestOptions.allowRedirects != null) {
            this._allowRedirects = requestOptions.allowRedirects;
          }
          if (requestOptions.allowRedirectDowngrade != null) {
            this._allowRedirectDowngrade = requestOptions.allowRedirectDowngrade;
          }
          if (requestOptions.maxRedirects != null) {
            this._maxRedirects = Math.max(requestOptions.maxRedirects, 0);
          }
          if (requestOptions.keepAlive != null) {
            this._keepAlive = requestOptions.keepAlive;
          }
          if (requestOptions.allowRetries != null) {
            this._allowRetries = requestOptions.allowRetries;
          }
          if (requestOptions.maxRetries != null) {
            this._maxRetries = requestOptions.maxRetries;
          }
        }
      }
      options(requestUrl, additionalHeaders) {
        return __awaiter(this, void 0, void 0, function* () {
          return this.request("OPTIONS", requestUrl, null, additionalHeaders || {});
        });
      }
      get(requestUrl, additionalHeaders) {
        return __awaiter(this, void 0, void 0, function* () {
          return this.request("GET", requestUrl, null, additionalHeaders || {});
        });
      }
      del(requestUrl, additionalHeaders) {
        return __awaiter(this, void 0, void 0, function* () {
          return this.request("DELETE", requestUrl, null, additionalHeaders || {});
        });
      }
      post(requestUrl, data, additionalHeaders) {
        return __awaiter(this, void 0, void 0, function* () {
          return this.request("POST", requestUrl, data, additionalHeaders || {});
        });
      }
      patch(requestUrl, data, additionalHeaders) {
        return __awaiter(this, void 0, void 0, function* () {
          return this.request("PATCH", requestUrl, data, additionalHeaders || {});
        });
      }
      put(requestUrl, data, additionalHeaders) {
        return __awaiter(this, void 0, void 0, function* () {
          return this.request("PUT", requestUrl, data, additionalHeaders || {});
        });
      }
      head(requestUrl, additionalHeaders) {
        return __awaiter(this, void 0, void 0, function* () {
          return this.request("HEAD", requestUrl, null, additionalHeaders || {});
        });
      }
      sendStream(verb, requestUrl, stream, additionalHeaders) {
        return __awaiter(this, void 0, void 0, function* () {
          return this.request(verb, requestUrl, stream, additionalHeaders);
        });
      }
      /**
       * Gets a typed object from an endpoint
       * Be aware that not found returns a null.  Other errors (4xx, 5xx) reject the promise
       */
      getJson(requestUrl, additionalHeaders = {}) {
        return __awaiter(this, void 0, void 0, function* () {
          additionalHeaders[Headers.Accept] = this._getExistingOrDefaultHeader(additionalHeaders, Headers.Accept, MediaTypes.ApplicationJson);
          const res = yield this.get(requestUrl, additionalHeaders);
          return this._processResponse(res, this.requestOptions);
        });
      }
      postJson(requestUrl, obj, additionalHeaders = {}) {
        return __awaiter(this, void 0, void 0, function* () {
          const data = JSON.stringify(obj, null, 2);
          additionalHeaders[Headers.Accept] = this._getExistingOrDefaultHeader(additionalHeaders, Headers.Accept, MediaTypes.ApplicationJson);
          additionalHeaders[Headers.ContentType] = this._getExistingOrDefaultHeader(additionalHeaders, Headers.ContentType, MediaTypes.ApplicationJson);
          const res = yield this.post(requestUrl, data, additionalHeaders);
          return this._processResponse(res, this.requestOptions);
        });
      }
      putJson(requestUrl, obj, additionalHeaders = {}) {
        return __awaiter(this, void 0, void 0, function* () {
          const data = JSON.stringify(obj, null, 2);
          additionalHeaders[Headers.Accept] = this._getExistingOrDefaultHeader(additionalHeaders, Headers.Accept, MediaTypes.ApplicationJson);
          additionalHeaders[Headers.ContentType] = this._getExistingOrDefaultHeader(additionalHeaders, Headers.ContentType, MediaTypes.ApplicationJson);
          const res = yield this.put(requestUrl, data, additionalHeaders);
          return this._processResponse(res, this.requestOptions);
        });
      }
      patchJson(requestUrl, obj, additionalHeaders = {}) {
        return __awaiter(this, void 0, void 0, function* () {
          const data = JSON.stringify(obj, null, 2);
          additionalHeaders[Headers.Accept] = this._getExistingOrDefaultHeader(additionalHeaders, Headers.Accept, MediaTypes.ApplicationJson);
          additionalHeaders[Headers.ContentType] = this._getExistingOrDefaultHeader(additionalHeaders, Headers.ContentType, MediaTypes.ApplicationJson);
          const res = yield this.patch(requestUrl, data, additionalHeaders);
          return this._processResponse(res, this.requestOptions);
        });
      }
      /**
       * Makes a raw http request.
       * All other methods such as get, post, patch, and request ultimately call this.
       * Prefer get, del, post and patch
       */
      request(verb, requestUrl, data, headers) {
        return __awaiter(this, void 0, void 0, function* () {
          if (this._disposed) {
            throw new Error("Client has already been disposed.");
          }
          const parsedUrl = new URL(requestUrl);
          let info2 = this._prepareRequest(verb, parsedUrl, headers);
          const maxTries = this._allowRetries && RetryableHttpVerbs.includes(verb) ? this._maxRetries + 1 : 1;
          let numTries = 0;
          let response;
          do {
            response = yield this.requestRaw(info2, data);
            if (response && response.message && response.message.statusCode === HttpCodes.Unauthorized) {
              let authenticationHandler;
              for (const handler of this.handlers) {
                if (handler.canHandleAuthentication(response)) {
                  authenticationHandler = handler;
                  break;
                }
              }
              if (authenticationHandler) {
                return authenticationHandler.handleAuthentication(this, info2, data);
              } else {
                return response;
              }
            }
            let redirectsRemaining = this._maxRedirects;
            while (response.message.statusCode && HttpRedirectCodes.includes(response.message.statusCode) && this._allowRedirects && redirectsRemaining > 0) {
              const redirectUrl = response.message.headers["location"];
              if (!redirectUrl) {
                break;
              }
              const parsedRedirectUrl = new URL(redirectUrl);
              if (parsedUrl.protocol === "https:" && parsedUrl.protocol !== parsedRedirectUrl.protocol && !this._allowRedirectDowngrade) {
                throw new Error("Redirect from HTTPS to HTTP protocol. This downgrade is not allowed for security reasons. If you want to allow this behavior, set the allowRedirectDowngrade option to true.");
              }
              yield response.readBody();
              if (parsedRedirectUrl.hostname !== parsedUrl.hostname) {
                for (const header in headers) {
                  if (header.toLowerCase() === "authorization") {
                    delete headers[header];
                  }
                }
              }
              info2 = this._prepareRequest(verb, parsedRedirectUrl, headers);
              response = yield this.requestRaw(info2, data);
              redirectsRemaining--;
            }
            if (!response.message.statusCode || !HttpResponseRetryCodes.includes(response.message.statusCode)) {
              return response;
            }
            numTries += 1;
            if (numTries < maxTries) {
              yield response.readBody();
              yield this._performExponentialBackoff(numTries);
            }
          } while (numTries < maxTries);
          return response;
        });
      }
      /**
       * Needs to be called if keepAlive is set to true in request options.
       */
      dispose() {
        if (this._agent) {
          this._agent.destroy();
        }
        this._disposed = true;
      }
      /**
       * Raw request.
       * @param info
       * @param data
       */
      requestRaw(info2, data) {
        return __awaiter(this, void 0, void 0, function* () {
          return new Promise((resolve2, reject) => {
            function callbackForResult(err, res) {
              if (err) {
                reject(err);
              } else if (!res) {
                reject(new Error("Unknown error"));
              } else {
                resolve2(res);
              }
            }
            this.requestRawWithCallback(info2, data, callbackForResult);
          });
        });
      }
      /**
       * Raw request with callback.
       * @param info
       * @param data
       * @param onResult
       */
      requestRawWithCallback(info2, data, onResult) {
        if (typeof data === "string") {
          if (!info2.options.headers) {
            info2.options.headers = {};
          }
          info2.options.headers["Content-Length"] = Buffer.byteLength(data, "utf8");
        }
        let callbackCalled = false;
        function handleResult(err, res) {
          if (!callbackCalled) {
            callbackCalled = true;
            onResult(err, res);
          }
        }
        const req = info2.httpModule.request(info2.options, (msg) => {
          const res = new HttpClientResponse(msg);
          handleResult(void 0, res);
        });
        let socket;
        req.on("socket", (sock) => {
          socket = sock;
        });
        req.setTimeout(this._socketTimeout || 3 * 6e4, () => {
          if (socket) {
            socket.end();
          }
          handleResult(new Error(`Request timeout: ${info2.options.path}`));
        });
        req.on("error", function(err) {
          handleResult(err);
        });
        if (data && typeof data === "string") {
          req.write(data, "utf8");
        }
        if (data && typeof data !== "string") {
          data.on("close", function() {
            req.end();
          });
          data.pipe(req);
        } else {
          req.end();
        }
      }
      /**
       * Gets an http agent. This function is useful when you need an http agent that handles
       * routing through a proxy server - depending upon the url and proxy environment variables.
       * @param serverUrl  The server URL where the request will be sent. For example, https://api.github.com
       */
      getAgent(serverUrl) {
        const parsedUrl = new URL(serverUrl);
        return this._getAgent(parsedUrl);
      }
      _prepareRequest(method, requestUrl, headers) {
        const info2 = {};
        info2.parsedUrl = requestUrl;
        const usingSsl = info2.parsedUrl.protocol === "https:";
        info2.httpModule = usingSsl ? https : http;
        const defaultPort = usingSsl ? 443 : 80;
        info2.options = {};
        info2.options.host = info2.parsedUrl.hostname;
        info2.options.port = info2.parsedUrl.port ? parseInt(info2.parsedUrl.port) : defaultPort;
        info2.options.path = (info2.parsedUrl.pathname || "") + (info2.parsedUrl.search || "");
        info2.options.method = method;
        info2.options.headers = this._mergeHeaders(headers);
        if (this.userAgent != null) {
          info2.options.headers["user-agent"] = this.userAgent;
        }
        info2.options.agent = this._getAgent(info2.parsedUrl);
        if (this.handlers) {
          for (const handler of this.handlers) {
            handler.prepareRequest(info2.options);
          }
        }
        return info2;
      }
      _mergeHeaders(headers) {
        if (this.requestOptions && this.requestOptions.headers) {
          return Object.assign({}, lowercaseKeys(this.requestOptions.headers), lowercaseKeys(headers || {}));
        }
        return lowercaseKeys(headers || {});
      }
      _getExistingOrDefaultHeader(additionalHeaders, header, _default) {
        let clientHeader;
        if (this.requestOptions && this.requestOptions.headers) {
          clientHeader = lowercaseKeys(this.requestOptions.headers)[header];
        }
        return additionalHeaders[header] || clientHeader || _default;
      }
      _getAgent(parsedUrl) {
        let agent;
        const proxyUrl = pm.getProxyUrl(parsedUrl);
        const useProxy = proxyUrl && proxyUrl.hostname;
        if (this._keepAlive && useProxy) {
          agent = this._proxyAgent;
        }
        if (this._keepAlive && !useProxy) {
          agent = this._agent;
        }
        if (agent) {
          return agent;
        }
        const usingSsl = parsedUrl.protocol === "https:";
        let maxSockets = 100;
        if (this.requestOptions) {
          maxSockets = this.requestOptions.maxSockets || http.globalAgent.maxSockets;
        }
        if (proxyUrl && proxyUrl.hostname) {
          const agentOptions = {
            maxSockets,
            keepAlive: this._keepAlive,
            proxy: Object.assign(Object.assign({}, (proxyUrl.username || proxyUrl.password) && {
              proxyAuth: `${proxyUrl.username}:${proxyUrl.password}`
            }), { host: proxyUrl.hostname, port: proxyUrl.port })
          };
          let tunnelAgent;
          const overHttps = proxyUrl.protocol === "https:";
          if (usingSsl) {
            tunnelAgent = overHttps ? tunnel.httpsOverHttps : tunnel.httpsOverHttp;
          } else {
            tunnelAgent = overHttps ? tunnel.httpOverHttps : tunnel.httpOverHttp;
          }
          agent = tunnelAgent(agentOptions);
          this._proxyAgent = agent;
        }
        if (this._keepAlive && !agent) {
          const options = { keepAlive: this._keepAlive, maxSockets };
          agent = usingSsl ? new https.Agent(options) : new http.Agent(options);
          this._agent = agent;
        }
        if (!agent) {
          agent = usingSsl ? https.globalAgent : http.globalAgent;
        }
        if (usingSsl && this._ignoreSslError) {
          agent.options = Object.assign(agent.options || {}, {
            rejectUnauthorized: false
          });
        }
        return agent;
      }
      _performExponentialBackoff(retryNumber) {
        return __awaiter(this, void 0, void 0, function* () {
          retryNumber = Math.min(ExponentialBackoffCeiling, retryNumber);
          const ms = ExponentialBackoffTimeSlice * Math.pow(2, retryNumber);
          return new Promise((resolve2) => setTimeout(() => resolve2(), ms));
        });
      }
      _processResponse(res, options) {
        return __awaiter(this, void 0, void 0, function* () {
          return new Promise((resolve2, reject) => __awaiter(this, void 0, void 0, function* () {
            const statusCode = res.message.statusCode || 0;
            const response = {
              statusCode,
              result: null,
              headers: {}
            };
            if (statusCode === HttpCodes.NotFound) {
              resolve2(response);
            }
            function dateTimeDeserializer(key, value) {
              if (typeof value === "string") {
                const a = new Date(value);
                if (!isNaN(a.valueOf())) {
                  return a;
                }
              }
              return value;
            }
            let obj;
            let contents;
            try {
              contents = yield res.readBody();
              if (contents && contents.length > 0) {
                if (options && options.deserializeDates) {
                  obj = JSON.parse(contents, dateTimeDeserializer);
                } else {
                  obj = JSON.parse(contents);
                }
                response.result = obj;
              }
              response.headers = res.message.headers;
            } catch (err) {
            }
            if (statusCode > 299) {
              let msg;
              if (obj && obj.message) {
                msg = obj.message;
              } else if (contents && contents.length > 0) {
                msg = contents;
              } else {
                msg = `Failed request: (${statusCode})`;
              }
              const err = new HttpClientError(msg, statusCode);
              err.result = response.result;
              reject(err);
            } else {
              resolve2(response);
            }
          }));
        });
      }
    };
    exports.HttpClient = HttpClient;
    var lowercaseKeys = (obj) => Object.keys(obj).reduce((c, k) => (c[k.toLowerCase()] = obj[k], c), {});
  }
});

// node_modules/.pnpm/@actions+http-client@2.1.1/node_modules/@actions/http-client/lib/auth.js
var require_auth = __commonJS({
  "node_modules/.pnpm/@actions+http-client@2.1.1/node_modules/@actions/http-client/lib/auth.js"(exports) {
    "use strict";
    var __awaiter = exports && exports.__awaiter || function(thisArg, _arguments, P, generator) {
      function adopt(value) {
        return value instanceof P ? value : new P(function(resolve2) {
          resolve2(value);
        });
      }
      return new (P || (P = Promise))(function(resolve2, reject) {
        function fulfilled(value) {
          try {
            step(generator.next(value));
          } catch (e) {
            reject(e);
          }
        }
        function rejected(value) {
          try {
            step(generator["throw"](value));
          } catch (e) {
            reject(e);
          }
        }
        function step(result) {
          result.done ? resolve2(result.value) : adopt(result.value).then(fulfilled, rejected);
        }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
      });
    };
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.PersonalAccessTokenCredentialHandler = exports.BearerCredentialHandler = exports.BasicCredentialHandler = void 0;
    var BasicCredentialHandler = class {
      constructor(username, password) {
        this.username = username;
        this.password = password;
      }
      prepareRequest(options) {
        if (!options.headers) {
          throw Error("The request has no headers");
        }
        options.headers["Authorization"] = `Basic ${Buffer.from(`${this.username}:${this.password}`).toString("base64")}`;
      }
      // This handler cannot handle 401
      canHandleAuthentication() {
        return false;
      }
      handleAuthentication() {
        return __awaiter(this, void 0, void 0, function* () {
          throw new Error("not implemented");
        });
      }
    };
    exports.BasicCredentialHandler = BasicCredentialHandler;
    var BearerCredentialHandler = class {
      constructor(token) {
        this.token = token;
      }
      // currently implements pre-authorization
      // TODO: support preAuth = false where it hooks on 401
      prepareRequest(options) {
        if (!options.headers) {
          throw Error("The request has no headers");
        }
        options.headers["Authorization"] = `Bearer ${this.token}`;
      }
      // This handler cannot handle 401
      canHandleAuthentication() {
        return false;
      }
      handleAuthentication() {
        return __awaiter(this, void 0, void 0, function* () {
          throw new Error("not implemented");
        });
      }
    };
    exports.BearerCredentialHandler = BearerCredentialHandler;
    var PersonalAccessTokenCredentialHandler = class {
      constructor(token) {
        this.token = token;
      }
      // currently implements pre-authorization
      // TODO: support preAuth = false where it hooks on 401
      prepareRequest(options) {
        if (!options.headers) {
          throw Error("The request has no headers");
        }
        options.headers["Authorization"] = `Basic ${Buffer.from(`PAT:${this.token}`).toString("base64")}`;
      }
      // This handler cannot handle 401
      canHandleAuthentication() {
        return false;
      }
      handleAuthentication() {
        return __awaiter(this, void 0, void 0, function* () {
          throw new Error("not implemented");
        });
      }
    };
    exports.PersonalAccessTokenCredentialHandler = PersonalAccessTokenCredentialHandler;
  }
});

// node_modules/.pnpm/@actions+core@1.10.1/node_modules/@actions/core/lib/oidc-utils.js
var require_oidc_utils = __commonJS({
  "node_modules/.pnpm/@actions+core@1.10.1/node_modules/@actions/core/lib/oidc-utils.js"(exports) {
    "use strict";
    var __awaiter = exports && exports.__awaiter || function(thisArg, _arguments, P, generator) {
      function adopt(value) {
        return value instanceof P ? value : new P(function(resolve2) {
          resolve2(value);
        });
      }
      return new (P || (P = Promise))(function(resolve2, reject) {
        function fulfilled(value) {
          try {
            step(generator.next(value));
          } catch (e) {
            reject(e);
          }
        }
        function rejected(value) {
          try {
            step(generator["throw"](value));
          } catch (e) {
            reject(e);
          }
        }
        function step(result) {
          result.done ? resolve2(result.value) : adopt(result.value).then(fulfilled, rejected);
        }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
      });
    };
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.OidcClient = void 0;
    var http_client_1 = require_lib();
    var auth_1 = require_auth();
    var core_1 = require_core();
    var OidcClient = class _OidcClient {
      static createHttpClient(allowRetry = true, maxRetry = 10) {
        const requestOptions = {
          allowRetries: allowRetry,
          maxRetries: maxRetry
        };
        return new http_client_1.HttpClient("actions/oidc-client", [new auth_1.BearerCredentialHandler(_OidcClient.getRequestToken())], requestOptions);
      }
      static getRequestToken() {
        const token = process.env["ACTIONS_ID_TOKEN_REQUEST_TOKEN"];
        if (!token) {
          throw new Error("Unable to get ACTIONS_ID_TOKEN_REQUEST_TOKEN env variable");
        }
        return token;
      }
      static getIDTokenUrl() {
        const runtimeUrl = process.env["ACTIONS_ID_TOKEN_REQUEST_URL"];
        if (!runtimeUrl) {
          throw new Error("Unable to get ACTIONS_ID_TOKEN_REQUEST_URL env variable");
        }
        return runtimeUrl;
      }
      static getCall(id_token_url) {
        var _a;
        return __awaiter(this, void 0, void 0, function* () {
          const httpclient = _OidcClient.createHttpClient();
          const res = yield httpclient.getJson(id_token_url).catch((error) => {
            throw new Error(`Failed to get ID Token. 
 
        Error Code : ${error.statusCode}
 
        Error Message: ${error.message}`);
          });
          const id_token = (_a = res.result) === null || _a === void 0 ? void 0 : _a.value;
          if (!id_token) {
            throw new Error("Response json body do not have ID Token field");
          }
          return id_token;
        });
      }
      static getIDToken(audience) {
        return __awaiter(this, void 0, void 0, function* () {
          try {
            let id_token_url = _OidcClient.getIDTokenUrl();
            if (audience) {
              const encodedAudience = encodeURIComponent(audience);
              id_token_url = `${id_token_url}&audience=${encodedAudience}`;
            }
            core_1.debug(`ID token url is ${id_token_url}`);
            const id_token = yield _OidcClient.getCall(id_token_url);
            core_1.setSecret(id_token);
            return id_token;
          } catch (error) {
            throw new Error(`Error message: ${error.message}`);
          }
        });
      }
    };
    exports.OidcClient = OidcClient;
  }
});

// node_modules/.pnpm/@actions+core@1.10.1/node_modules/@actions/core/lib/summary.js
var require_summary = __commonJS({
  "node_modules/.pnpm/@actions+core@1.10.1/node_modules/@actions/core/lib/summary.js"(exports) {
    "use strict";
    var __awaiter = exports && exports.__awaiter || function(thisArg, _arguments, P, generator) {
      function adopt(value) {
        return value instanceof P ? value : new P(function(resolve2) {
          resolve2(value);
        });
      }
      return new (P || (P = Promise))(function(resolve2, reject) {
        function fulfilled(value) {
          try {
            step(generator.next(value));
          } catch (e) {
            reject(e);
          }
        }
        function rejected(value) {
          try {
            step(generator["throw"](value));
          } catch (e) {
            reject(e);
          }
        }
        function step(result) {
          result.done ? resolve2(result.value) : adopt(result.value).then(fulfilled, rejected);
        }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
      });
    };
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.summary = exports.markdownSummary = exports.SUMMARY_DOCS_URL = exports.SUMMARY_ENV_VAR = void 0;
    var os_1 = __require("os");
    var fs_1 = __require("fs");
    var { access, appendFile, writeFile } = fs_1.promises;
    exports.SUMMARY_ENV_VAR = "GITHUB_STEP_SUMMARY";
    exports.SUMMARY_DOCS_URL = "https://docs.github.com/actions/using-workflows/workflow-commands-for-github-actions#adding-a-job-summary";
    var Summary = class {
      constructor() {
        this._buffer = "";
      }
      /**
       * Finds the summary file path from the environment, rejects if env var is not found or file does not exist
       * Also checks r/w permissions.
       *
       * @returns step summary file path
       */
      filePath() {
        return __awaiter(this, void 0, void 0, function* () {
          if (this._filePath) {
            return this._filePath;
          }
          const pathFromEnv = process.env[exports.SUMMARY_ENV_VAR];
          if (!pathFromEnv) {
            throw new Error(`Unable to find environment variable for $${exports.SUMMARY_ENV_VAR}. Check if your runtime environment supports job summaries.`);
          }
          try {
            yield access(pathFromEnv, fs_1.constants.R_OK | fs_1.constants.W_OK);
          } catch (_a) {
            throw new Error(`Unable to access summary file: '${pathFromEnv}'. Check if the file has correct read/write permissions.`);
          }
          this._filePath = pathFromEnv;
          return this._filePath;
        });
      }
      /**
       * Wraps content in an HTML tag, adding any HTML attributes
       *
       * @param {string} tag HTML tag to wrap
       * @param {string | null} content content within the tag
       * @param {[attribute: string]: string} attrs key-value list of HTML attributes to add
       *
       * @returns {string} content wrapped in HTML element
       */
      wrap(tag, content, attrs = {}) {
        const htmlAttrs = Object.entries(attrs).map(([key, value]) => ` ${key}="${value}"`).join("");
        if (!content) {
          return `<${tag}${htmlAttrs}>`;
        }
        return `<${tag}${htmlAttrs}>${content}</${tag}>`;
      }
      /**
       * Writes text in the buffer to the summary buffer file and empties buffer. Will append by default.
       *
       * @param {SummaryWriteOptions} [options] (optional) options for write operation
       *
       * @returns {Promise<Summary>} summary instance
       */
      write(options) {
        return __awaiter(this, void 0, void 0, function* () {
          const overwrite = !!(options === null || options === void 0 ? void 0 : options.overwrite);
          const filePath = yield this.filePath();
          const writeFunc = overwrite ? writeFile : appendFile;
          yield writeFunc(filePath, this._buffer, { encoding: "utf8" });
          return this.emptyBuffer();
        });
      }
      /**
       * Clears the summary buffer and wipes the summary file
       *
       * @returns {Summary} summary instance
       */
      clear() {
        return __awaiter(this, void 0, void 0, function* () {
          return this.emptyBuffer().write({ overwrite: true });
        });
      }
      /**
       * Returns the current summary buffer as a string
       *
       * @returns {string} string of summary buffer
       */
      stringify() {
        return this._buffer;
      }
      /**
       * If the summary buffer is empty
       *
       * @returns {boolen} true if the buffer is empty
       */
      isEmptyBuffer() {
        return this._buffer.length === 0;
      }
      /**
       * Resets the summary buffer without writing to summary file
       *
       * @returns {Summary} summary instance
       */
      emptyBuffer() {
        this._buffer = "";
        return this;
      }
      /**
       * Adds raw text to the summary buffer
       *
       * @param {string} text content to add
       * @param {boolean} [addEOL=false] (optional) append an EOL to the raw text (default: false)
       *
       * @returns {Summary} summary instance
       */
      addRaw(text, addEOL = false) {
        this._buffer += text;
        return addEOL ? this.addEOL() : this;
      }
      /**
       * Adds the operating system-specific end-of-line marker to the buffer
       *
       * @returns {Summary} summary instance
       */
      addEOL() {
        return this.addRaw(os_1.EOL);
      }
      /**
       * Adds an HTML codeblock to the summary buffer
       *
       * @param {string} code content to render within fenced code block
       * @param {string} lang (optional) language to syntax highlight code
       *
       * @returns {Summary} summary instance
       */
      addCodeBlock(code, lang) {
        const attrs = Object.assign({}, lang && { lang });
        const element = this.wrap("pre", this.wrap("code", code), attrs);
        return this.addRaw(element).addEOL();
      }
      /**
       * Adds an HTML list to the summary buffer
       *
       * @param {string[]} items list of items to render
       * @param {boolean} [ordered=false] (optional) if the rendered list should be ordered or not (default: false)
       *
       * @returns {Summary} summary instance
       */
      addList(items, ordered = false) {
        const tag = ordered ? "ol" : "ul";
        const listItems = items.map((item) => this.wrap("li", item)).join("");
        const element = this.wrap(tag, listItems);
        return this.addRaw(element).addEOL();
      }
      /**
       * Adds an HTML table to the summary buffer
       *
       * @param {SummaryTableCell[]} rows table rows
       *
       * @returns {Summary} summary instance
       */
      addTable(rows) {
        const tableBody = rows.map((row) => {
          const cells = row.map((cell) => {
            if (typeof cell === "string") {
              return this.wrap("td", cell);
            }
            const { header, data, colspan, rowspan } = cell;
            const tag = header ? "th" : "td";
            const attrs = Object.assign(Object.assign({}, colspan && { colspan }), rowspan && { rowspan });
            return this.wrap(tag, data, attrs);
          }).join("");
          return this.wrap("tr", cells);
        }).join("");
        const element = this.wrap("table", tableBody);
        return this.addRaw(element).addEOL();
      }
      /**
       * Adds a collapsable HTML details element to the summary buffer
       *
       * @param {string} label text for the closed state
       * @param {string} content collapsable content
       *
       * @returns {Summary} summary instance
       */
      addDetails(label, content) {
        const element = this.wrap("details", this.wrap("summary", label) + content);
        return this.addRaw(element).addEOL();
      }
      /**
       * Adds an HTML image tag to the summary buffer
       *
       * @param {string} src path to the image you to embed
       * @param {string} alt text description of the image
       * @param {SummaryImageOptions} options (optional) addition image attributes
       *
       * @returns {Summary} summary instance
       */
      addImage(src, alt, options) {
        const { width, height } = options || {};
        const attrs = Object.assign(Object.assign({}, width && { width }), height && { height });
        const element = this.wrap("img", null, Object.assign({ src, alt }, attrs));
        return this.addRaw(element).addEOL();
      }
      /**
       * Adds an HTML section heading element
       *
       * @param {string} text heading text
       * @param {number | string} [level=1] (optional) the heading level, default: 1
       *
       * @returns {Summary} summary instance
       */
      addHeading(text, level) {
        const tag = `h${level}`;
        const allowedTag = ["h1", "h2", "h3", "h4", "h5", "h6"].includes(tag) ? tag : "h1";
        const element = this.wrap(allowedTag, text);
        return this.addRaw(element).addEOL();
      }
      /**
       * Adds an HTML thematic break (<hr>) to the summary buffer
       *
       * @returns {Summary} summary instance
       */
      addSeparator() {
        const element = this.wrap("hr", null);
        return this.addRaw(element).addEOL();
      }
      /**
       * Adds an HTML line break (<br>) to the summary buffer
       *
       * @returns {Summary} summary instance
       */
      addBreak() {
        const element = this.wrap("br", null);
        return this.addRaw(element).addEOL();
      }
      /**
       * Adds an HTML blockquote to the summary buffer
       *
       * @param {string} text quote text
       * @param {string} cite (optional) citation url
       *
       * @returns {Summary} summary instance
       */
      addQuote(text, cite) {
        const attrs = Object.assign({}, cite && { cite });
        const element = this.wrap("blockquote", text, attrs);
        return this.addRaw(element).addEOL();
      }
      /**
       * Adds an HTML anchor tag to the summary buffer
       *
       * @param {string} text link text/content
       * @param {string} href hyperlink
       *
       * @returns {Summary} summary instance
       */
      addLink(text, href) {
        const element = this.wrap("a", text, { href });
        return this.addRaw(element).addEOL();
      }
    };
    var _summary = new Summary();
    exports.markdownSummary = _summary;
    exports.summary = _summary;
  }
});

// node_modules/.pnpm/@actions+core@1.10.1/node_modules/@actions/core/lib/path-utils.js
var require_path_utils = __commonJS({
  "node_modules/.pnpm/@actions+core@1.10.1/node_modules/@actions/core/lib/path-utils.js"(exports) {
    "use strict";
    var __createBinding = exports && exports.__createBinding || (Object.create ? function(o, m, k, k2) {
      if (k2 === void 0)
        k2 = k;
      Object.defineProperty(o, k2, { enumerable: true, get: function() {
        return m[k];
      } });
    } : function(o, m, k, k2) {
      if (k2 === void 0)
        k2 = k;
      o[k2] = m[k];
    });
    var __setModuleDefault = exports && exports.__setModuleDefault || (Object.create ? function(o, v) {
      Object.defineProperty(o, "default", { enumerable: true, value: v });
    } : function(o, v) {
      o["default"] = v;
    });
    var __importStar = exports && exports.__importStar || function(mod) {
      if (mod && mod.__esModule)
        return mod;
      var result = {};
      if (mod != null) {
        for (var k in mod)
          if (k !== "default" && Object.hasOwnProperty.call(mod, k))
            __createBinding(result, mod, k);
      }
      __setModuleDefault(result, mod);
      return result;
    };
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.toPlatformPath = exports.toWin32Path = exports.toPosixPath = void 0;
    var path = __importStar(__require("path"));
    function toPosixPath(pth) {
      return pth.replace(/[\\]/g, "/");
    }
    exports.toPosixPath = toPosixPath;
    function toWin32Path(pth) {
      return pth.replace(/[/]/g, "\\");
    }
    exports.toWin32Path = toWin32Path;
    function toPlatformPath(pth) {
      return pth.replace(/[/\\]/g, path.sep);
    }
    exports.toPlatformPath = toPlatformPath;
  }
});

// node_modules/.pnpm/@actions+core@1.10.1/node_modules/@actions/core/lib/core.js
var require_core = __commonJS({
  "node_modules/.pnpm/@actions+core@1.10.1/node_modules/@actions/core/lib/core.js"(exports) {
    "use strict";
    var __createBinding = exports && exports.__createBinding || (Object.create ? function(o, m, k, k2) {
      if (k2 === void 0)
        k2 = k;
      Object.defineProperty(o, k2, { enumerable: true, get: function() {
        return m[k];
      } });
    } : function(o, m, k, k2) {
      if (k2 === void 0)
        k2 = k;
      o[k2] = m[k];
    });
    var __setModuleDefault = exports && exports.__setModuleDefault || (Object.create ? function(o, v) {
      Object.defineProperty(o, "default", { enumerable: true, value: v });
    } : function(o, v) {
      o["default"] = v;
    });
    var __importStar = exports && exports.__importStar || function(mod) {
      if (mod && mod.__esModule)
        return mod;
      var result = {};
      if (mod != null) {
        for (var k in mod)
          if (k !== "default" && Object.hasOwnProperty.call(mod, k))
            __createBinding(result, mod, k);
      }
      __setModuleDefault(result, mod);
      return result;
    };
    var __awaiter = exports && exports.__awaiter || function(thisArg, _arguments, P, generator) {
      function adopt(value) {
        return value instanceof P ? value : new P(function(resolve2) {
          resolve2(value);
        });
      }
      return new (P || (P = Promise))(function(resolve2, reject) {
        function fulfilled(value) {
          try {
            step(generator.next(value));
          } catch (e) {
            reject(e);
          }
        }
        function rejected(value) {
          try {
            step(generator["throw"](value));
          } catch (e) {
            reject(e);
          }
        }
        function step(result) {
          result.done ? resolve2(result.value) : adopt(result.value).then(fulfilled, rejected);
        }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
      });
    };
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.getIDToken = exports.getState = exports.saveState = exports.group = exports.endGroup = exports.startGroup = exports.info = exports.notice = exports.warning = exports.error = exports.debug = exports.isDebug = exports.setFailed = exports.setCommandEcho = exports.setOutput = exports.getBooleanInput = exports.getMultilineInput = exports.getInput = exports.addPath = exports.setSecret = exports.exportVariable = exports.ExitCode = void 0;
    var command_1 = require_command();
    var file_command_1 = require_file_command();
    var utils_1 = require_utils();
    var os = __importStar(__require("os"));
    var path = __importStar(__require("path"));
    var oidc_utils_1 = require_oidc_utils();
    var ExitCode;
    (function(ExitCode2) {
      ExitCode2[ExitCode2["Success"] = 0] = "Success";
      ExitCode2[ExitCode2["Failure"] = 1] = "Failure";
    })(ExitCode = exports.ExitCode || (exports.ExitCode = {}));
    function exportVariable(name, val) {
      const convertedVal = utils_1.toCommandValue(val);
      process.env[name] = convertedVal;
      const filePath = process.env["GITHUB_ENV"] || "";
      if (filePath) {
        return file_command_1.issueFileCommand("ENV", file_command_1.prepareKeyValueMessage(name, val));
      }
      command_1.issueCommand("set-env", { name }, convertedVal);
    }
    exports.exportVariable = exportVariable;
    function setSecret(secret) {
      command_1.issueCommand("add-mask", {}, secret);
    }
    exports.setSecret = setSecret;
    function addPath(inputPath) {
      const filePath = process.env["GITHUB_PATH"] || "";
      if (filePath) {
        file_command_1.issueFileCommand("PATH", inputPath);
      } else {
        command_1.issueCommand("add-path", {}, inputPath);
      }
      process.env["PATH"] = `${inputPath}${path.delimiter}${process.env["PATH"]}`;
    }
    exports.addPath = addPath;
    function getInput2(name, options) {
      const val = process.env[`INPUT_${name.replace(/ /g, "_").toUpperCase()}`] || "";
      if (options && options.required && !val) {
        throw new Error(`Input required and not supplied: ${name}`);
      }
      if (options && options.trimWhitespace === false) {
        return val;
      }
      return val.trim();
    }
    exports.getInput = getInput2;
    function getMultilineInput2(name, options) {
      const inputs = getInput2(name, options).split("\n").filter((x) => x !== "");
      if (options && options.trimWhitespace === false) {
        return inputs;
      }
      return inputs.map((input) => input.trim());
    }
    exports.getMultilineInput = getMultilineInput2;
    function getBooleanInput(name, options) {
      const trueValue = ["true", "True", "TRUE"];
      const falseValue = ["false", "False", "FALSE"];
      const val = getInput2(name, options);
      if (trueValue.includes(val))
        return true;
      if (falseValue.includes(val))
        return false;
      throw new TypeError(`Input does not meet YAML 1.2 "Core Schema" specification: ${name}
Support boolean input list: \`true | True | TRUE | false | False | FALSE\``);
    }
    exports.getBooleanInput = getBooleanInput;
    function setOutput(name, value) {
      const filePath = process.env["GITHUB_OUTPUT"] || "";
      if (filePath) {
        return file_command_1.issueFileCommand("OUTPUT", file_command_1.prepareKeyValueMessage(name, value));
      }
      process.stdout.write(os.EOL);
      command_1.issueCommand("set-output", { name }, utils_1.toCommandValue(value));
    }
    exports.setOutput = setOutput;
    function setCommandEcho(enabled) {
      command_1.issue("echo", enabled ? "on" : "off");
    }
    exports.setCommandEcho = setCommandEcho;
    function setFailed2(message) {
      process.exitCode = ExitCode.Failure;
      error(message);
    }
    exports.setFailed = setFailed2;
    function isDebug() {
      return process.env["RUNNER_DEBUG"] === "1";
    }
    exports.isDebug = isDebug;
    function debug3(message) {
      command_1.issueCommand("debug", {}, message);
    }
    exports.debug = debug3;
    function error(message, properties = {}) {
      command_1.issueCommand("error", utils_1.toCommandProperties(properties), message instanceof Error ? message.toString() : message);
    }
    exports.error = error;
    function warning2(message, properties = {}) {
      command_1.issueCommand("warning", utils_1.toCommandProperties(properties), message instanceof Error ? message.toString() : message);
    }
    exports.warning = warning2;
    function notice(message, properties = {}) {
      command_1.issueCommand("notice", utils_1.toCommandProperties(properties), message instanceof Error ? message.toString() : message);
    }
    exports.notice = notice;
    function info2(message) {
      process.stdout.write(message + os.EOL);
    }
    exports.info = info2;
    function startGroup(name) {
      command_1.issue("group", name);
    }
    exports.startGroup = startGroup;
    function endGroup() {
      command_1.issue("endgroup");
    }
    exports.endGroup = endGroup;
    function group(name, fn) {
      return __awaiter(this, void 0, void 0, function* () {
        startGroup(name);
        let result;
        try {
          result = yield fn();
        } finally {
          endGroup();
        }
        return result;
      });
    }
    exports.group = group;
    function saveState(name, value) {
      const filePath = process.env["GITHUB_STATE"] || "";
      if (filePath) {
        return file_command_1.issueFileCommand("STATE", file_command_1.prepareKeyValueMessage(name, value));
      }
      command_1.issueCommand("save-state", { name }, utils_1.toCommandValue(value));
    }
    exports.saveState = saveState;
    function getState(name) {
      return process.env[`STATE_${name}`] || "";
    }
    exports.getState = getState;
    function getIDToken(aud) {
      return __awaiter(this, void 0, void 0, function* () {
        return yield oidc_utils_1.OidcClient.getIDToken(aud);
      });
    }
    exports.getIDToken = getIDToken;
    var summary_1 = require_summary();
    Object.defineProperty(exports, "summary", { enumerable: true, get: function() {
      return summary_1.summary;
    } });
    var summary_2 = require_summary();
    Object.defineProperty(exports, "markdownSummary", { enumerable: true, get: function() {
      return summary_2.markdownSummary;
    } });
    var path_utils_1 = require_path_utils();
    Object.defineProperty(exports, "toPosixPath", { enumerable: true, get: function() {
      return path_utils_1.toPosixPath;
    } });
    Object.defineProperty(exports, "toWin32Path", { enumerable: true, get: function() {
      return path_utils_1.toWin32Path;
    } });
    Object.defineProperty(exports, "toPlatformPath", { enumerable: true, get: function() {
      return path_utils_1.toPlatformPath;
    } });
  }
});

// node_modules/.pnpm/console-table-printer@2.12.0/node_modules/console-table-printer/dist/src/utils/colored-console-line.js
var require_colored_console_line = __commonJS({
  "node_modules/.pnpm/console-table-printer@2.12.0/node_modules/console-table-printer/dist/src/utils/colored-console-line.js"(exports) {
    "use strict";
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.DEFAULT_COLOR_MAP = void 0;
    exports.DEFAULT_COLOR_MAP = {
      red: "\x1B[31m",
      green: "\x1B[32m",
      yellow: "\x1B[33m",
      blue: "\x1B[34m",
      magenta: "\x1B[35m",
      cyan: "\x1B[36m",
      white: "\x1B[37m",
      white_bold: "\x1B[01m",
      reset: "\x1B[0m"
    };
    var ColoredConsoleLine = class {
      constructor(colorMap = exports.DEFAULT_COLOR_MAP) {
        this.text = "";
        this.colorMap = colorMap;
      }
      addCharsWithColor(color, text) {
        const colorAnsi = this.colorMap[color];
        this.text += colorAnsi !== void 0 ? `${colorAnsi}${text}${this.colorMap.reset}` : text;
      }
      renderConsole() {
        return this.text;
      }
    };
    exports.default = ColoredConsoleLine;
  }
});

// node_modules/.pnpm/console-table-printer@2.12.0/node_modules/console-table-printer/dist/src/utils/table-constants.js
var require_table_constants = __commonJS({
  "node_modules/.pnpm/console-table-printer@2.12.0/node_modules/console-table-printer/dist/src/utils/table-constants.js"(exports) {
    "use strict";
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.DEFAULT_HEADER_ALIGNMENT = exports.DEFAULT_ROW_ALIGNMENT = exports.DEFAULT_HEADER_FONT_COLOR = exports.DEFAULT_ROW_FONT_COLOR = exports.COLORS = exports.ALIGNMENTS = exports.DEFAULT_TABLE_STYLE = exports.DEFAULT_ROW_SEPARATOR = exports.DEFAULT_COLUMN_LEN = void 0;
    exports.DEFAULT_COLUMN_LEN = 20;
    exports.DEFAULT_ROW_SEPARATOR = false;
    exports.DEFAULT_TABLE_STYLE = {
      /*
          Default Style
          ┌────────────┬─────┬──────┐
          │ foo        │ bar │ baz  │
          │ frobnicate │ bar │ quuz │
          └────────────┴─────┴──────┘
          */
      headerTop: {
        left: "\u250C",
        mid: "\u252C",
        right: "\u2510",
        other: "\u2500"
      },
      headerBottom: {
        left: "\u251C",
        mid: "\u253C",
        right: "\u2524",
        other: "\u2500"
      },
      tableBottom: {
        left: "\u2514",
        mid: "\u2534",
        right: "\u2518",
        other: "\u2500"
      },
      vertical: "\u2502",
      rowSeparator: {
        left: "\u251C",
        mid: "\u253C",
        right: "\u2524",
        other: "\u2500"
      }
    };
    exports.ALIGNMENTS = ["right", "left", "center"];
    exports.COLORS = [
      "red",
      "green",
      "yellow",
      "white",
      "blue",
      "magenta",
      "cyan",
      "white_bold",
      "reset"
    ];
    exports.DEFAULT_ROW_FONT_COLOR = "white";
    exports.DEFAULT_HEADER_FONT_COLOR = "white_bold";
    exports.DEFAULT_ROW_ALIGNMENT = "right";
    exports.DEFAULT_HEADER_ALIGNMENT = "center";
  }
});

// node_modules/.pnpm/console-table-printer@2.12.0/node_modules/console-table-printer/dist/src/internalTable/input-converter.js
var require_input_converter = __commonJS({
  "node_modules/.pnpm/console-table-printer@2.12.0/node_modules/console-table-printer/dist/src/internalTable/input-converter.js"(exports) {
    "use strict";
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.rawColumnToInternalColumn = exports.objIfExists = void 0;
    var table_constants_1 = require_table_constants();
    var objIfExists = (key, val) => {
      if (!val) {
        return {};
      }
      return {
        [key]: val
      };
    };
    exports.objIfExists = objIfExists;
    var rawColumnToInternalColumn = (column) => {
      var _a;
      return Object.assign(Object.assign(Object.assign(Object.assign({ name: column.name, title: (_a = column.title) !== null && _a !== void 0 ? _a : column.name }, (0, exports.objIfExists)("color", column.color)), (0, exports.objIfExists)("maxLen", column.maxLen)), (0, exports.objIfExists)("minLen", column.minLen)), { alignment: column.alignment || table_constants_1.DEFAULT_ROW_ALIGNMENT });
    };
    exports.rawColumnToInternalColumn = rawColumnToInternalColumn;
  }
});

// node_modules/.pnpm/simple-wcswidth@1.0.1/node_modules/simple-wcswidth/dist/src/non-spacing-chars.js
var require_non_spacing_chars = __commonJS({
  "node_modules/.pnpm/simple-wcswidth@1.0.1/node_modules/simple-wcswidth/dist/src/non-spacing-chars.js"(exports) {
    "use strict";
    Object.defineProperty(exports, "__esModule", { value: true });
    var combining = [
      { first: 768, last: 879 },
      { first: 1155, last: 1158 },
      { first: 1160, last: 1161 },
      { first: 1425, last: 1469 },
      { first: 1471, last: 1471 },
      { first: 1473, last: 1474 },
      { first: 1476, last: 1477 },
      { first: 1479, last: 1479 },
      { first: 1536, last: 1539 },
      { first: 1552, last: 1557 },
      { first: 1611, last: 1630 },
      { first: 1648, last: 1648 },
      { first: 1750, last: 1764 },
      { first: 1767, last: 1768 },
      { first: 1770, last: 1773 },
      { first: 1807, last: 1807 },
      { first: 1809, last: 1809 },
      { first: 1840, last: 1866 },
      { first: 1958, last: 1968 },
      { first: 2027, last: 2035 },
      { first: 2305, last: 2306 },
      { first: 2364, last: 2364 },
      { first: 2369, last: 2376 },
      { first: 2381, last: 2381 },
      { first: 2385, last: 2388 },
      { first: 2402, last: 2403 },
      { first: 2433, last: 2433 },
      { first: 2492, last: 2492 },
      { first: 2497, last: 2500 },
      { first: 2509, last: 2509 },
      { first: 2530, last: 2531 },
      { first: 2561, last: 2562 },
      { first: 2620, last: 2620 },
      { first: 2625, last: 2626 },
      { first: 2631, last: 2632 },
      { first: 2635, last: 2637 },
      { first: 2672, last: 2673 },
      { first: 2689, last: 2690 },
      { first: 2748, last: 2748 },
      { first: 2753, last: 2757 },
      { first: 2759, last: 2760 },
      { first: 2765, last: 2765 },
      { first: 2786, last: 2787 },
      { first: 2817, last: 2817 },
      { first: 2876, last: 2876 },
      { first: 2879, last: 2879 },
      { first: 2881, last: 2883 },
      { first: 2893, last: 2893 },
      { first: 2902, last: 2902 },
      { first: 2946, last: 2946 },
      { first: 3008, last: 3008 },
      { first: 3021, last: 3021 },
      { first: 3134, last: 3136 },
      { first: 3142, last: 3144 },
      { first: 3146, last: 3149 },
      { first: 3157, last: 3158 },
      { first: 3260, last: 3260 },
      { first: 3263, last: 3263 },
      { first: 3270, last: 3270 },
      { first: 3276, last: 3277 },
      { first: 3298, last: 3299 },
      { first: 3393, last: 3395 },
      { first: 3405, last: 3405 },
      { first: 3530, last: 3530 },
      { first: 3538, last: 3540 },
      { first: 3542, last: 3542 },
      { first: 3633, last: 3633 },
      { first: 3636, last: 3642 },
      { first: 3655, last: 3662 },
      { first: 3761, last: 3761 },
      { first: 3764, last: 3769 },
      { first: 3771, last: 3772 },
      { first: 3784, last: 3789 },
      { first: 3864, last: 3865 },
      { first: 3893, last: 3893 },
      { first: 3895, last: 3895 },
      { first: 3897, last: 3897 },
      { first: 3953, last: 3966 },
      { first: 3968, last: 3972 },
      { first: 3974, last: 3975 },
      { first: 3984, last: 3991 },
      { first: 3993, last: 4028 },
      { first: 4038, last: 4038 },
      { first: 4141, last: 4144 },
      { first: 4146, last: 4146 },
      { first: 4150, last: 4151 },
      { first: 4153, last: 4153 },
      { first: 4184, last: 4185 },
      { first: 4448, last: 4607 },
      { first: 4959, last: 4959 },
      { first: 5906, last: 5908 },
      { first: 5938, last: 5940 },
      { first: 5970, last: 5971 },
      { first: 6002, last: 6003 },
      { first: 6068, last: 6069 },
      { first: 6071, last: 6077 },
      { first: 6086, last: 6086 },
      { first: 6089, last: 6099 },
      { first: 6109, last: 6109 },
      { first: 6155, last: 6157 },
      { first: 6313, last: 6313 },
      { first: 6432, last: 6434 },
      { first: 6439, last: 6440 },
      { first: 6450, last: 6450 },
      { first: 6457, last: 6459 },
      { first: 6679, last: 6680 },
      { first: 6912, last: 6915 },
      { first: 6964, last: 6964 },
      { first: 6966, last: 6970 },
      { first: 6972, last: 6972 },
      { first: 6978, last: 6978 },
      { first: 7019, last: 7027 },
      { first: 7616, last: 7626 },
      { first: 7678, last: 7679 },
      { first: 8203, last: 8207 },
      { first: 8234, last: 8238 },
      { first: 8288, last: 8291 },
      { first: 8298, last: 8303 },
      { first: 8400, last: 8431 },
      { first: 12330, last: 12335 },
      { first: 12441, last: 12442 },
      { first: 43014, last: 43014 },
      { first: 43019, last: 43019 },
      { first: 43045, last: 43046 },
      { first: 64286, last: 64286 },
      { first: 65024, last: 65039 },
      { first: 65056, last: 65059 },
      { first: 65279, last: 65279 },
      { first: 65529, last: 65531 },
      { first: 68097, last: 68099 },
      { first: 68101, last: 68102 },
      { first: 68108, last: 68111 },
      { first: 68152, last: 68154 },
      { first: 68159, last: 68159 },
      { first: 119143, last: 119145 },
      { first: 119155, last: 119170 },
      { first: 119173, last: 119179 },
      { first: 119210, last: 119213 },
      { first: 119362, last: 119364 },
      { first: 917505, last: 917505 },
      { first: 917536, last: 917631 },
      { first: 917760, last: 917999 }
    ];
    exports.default = combining;
  }
});

// node_modules/.pnpm/simple-wcswidth@1.0.1/node_modules/simple-wcswidth/dist/src/binary-search.js
var require_binary_search = __commonJS({
  "node_modules/.pnpm/simple-wcswidth@1.0.1/node_modules/simple-wcswidth/dist/src/binary-search.js"(exports) {
    "use strict";
    Object.defineProperty(exports, "__esModule", { value: true });
    var bisearch = (ucs, table, tableSize) => {
      let min = 0;
      let mid;
      let max = tableSize;
      if (ucs < table[0].first || ucs > table[max].last)
        return 0;
      while (max >= min) {
        mid = Math.floor((min + max) / 2);
        if (ucs > table[mid].last) {
          min = mid + 1;
        } else if (ucs < table[mid].first) {
          max = mid - 1;
        } else {
          return 1;
        }
      }
      return 0;
    };
    exports.default = bisearch;
  }
});

// node_modules/.pnpm/simple-wcswidth@1.0.1/node_modules/simple-wcswidth/dist/src/wcwidth.js
var require_wcwidth = __commonJS({
  "node_modules/.pnpm/simple-wcswidth@1.0.1/node_modules/simple-wcswidth/dist/src/wcwidth.js"(exports) {
    "use strict";
    var __importDefault = exports && exports.__importDefault || function(mod) {
      return mod && mod.__esModule ? mod : { "default": mod };
    };
    Object.defineProperty(exports, "__esModule", { value: true });
    var non_spacing_chars_1 = __importDefault(require_non_spacing_chars());
    var binary_search_1 = __importDefault(require_binary_search());
    var mk_wcwidth = (ucs) => {
      if (ucs === 0) {
        return 0;
      }
      if (ucs < 32 || ucs >= 127 && ucs < 160) {
        return -1;
      }
      if (binary_search_1.default(ucs, non_spacing_chars_1.default, non_spacing_chars_1.default.length - 1)) {
        return 0;
      }
      return 1 + Number(ucs >= 4352 && (ucs <= 4447 || ucs === 9001 || ucs === 9002 || ucs >= 11904 && ucs <= 42191 && ucs !== 12351 || ucs >= 44032 && ucs <= 55203 || ucs >= 63744 && ucs <= 64255 || ucs >= 65040 && ucs <= 65049 || ucs >= 65072 && ucs <= 65135 || ucs >= 65280 && ucs <= 65376 || ucs >= 65504 && ucs <= 65510 || ucs >= 131072 && ucs <= 196605 || ucs >= 196608 && ucs <= 262141));
    };
    exports.default = mk_wcwidth;
  }
});

// node_modules/.pnpm/simple-wcswidth@1.0.1/node_modules/simple-wcswidth/dist/src/wcswidth.js
var require_wcswidth = __commonJS({
  "node_modules/.pnpm/simple-wcswidth@1.0.1/node_modules/simple-wcswidth/dist/src/wcswidth.js"(exports) {
    "use strict";
    var __importDefault = exports && exports.__importDefault || function(mod) {
      return mod && mod.__esModule ? mod : { "default": mod };
    };
    Object.defineProperty(exports, "__esModule", { value: true });
    var wcwidth_1 = __importDefault(require_wcwidth());
    var mk_wcswidth = (pwcs) => {
      let width = 0;
      for (let i = 0; i < pwcs.length; i++) {
        const charCode = pwcs.charCodeAt(i);
        const w = wcwidth_1.default(charCode);
        if (w < 0) {
          return -1;
        }
        width += w;
      }
      return width;
    };
    exports.default = mk_wcswidth;
  }
});

// node_modules/.pnpm/simple-wcswidth@1.0.1/node_modules/simple-wcswidth/dist/index.js
var require_dist = __commonJS({
  "node_modules/.pnpm/simple-wcswidth@1.0.1/node_modules/simple-wcswidth/dist/index.js"(exports) {
    "use strict";
    var __importDefault = exports && exports.__importDefault || function(mod) {
      return mod && mod.__esModule ? mod : { "default": mod };
    };
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.wcswidth = exports.wcwidth = void 0;
    var wcswidth_1 = __importDefault(require_wcswidth());
    exports.wcswidth = wcswidth_1.default;
    var wcwidth_1 = __importDefault(require_wcwidth());
    exports.wcwidth = wcwidth_1.default;
  }
});

// node_modules/.pnpm/console-table-printer@2.12.0/node_modules/console-table-printer/dist/src/utils/console-utils.js
var require_console_utils = __commonJS({
  "node_modules/.pnpm/console-table-printer@2.12.0/node_modules/console-table-printer/dist/src/utils/console-utils.js"(exports) {
    "use strict";
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.findWidthInConsole = exports.stripAnsi = void 0;
    var simple_wcswidth_1 = require_dist();
    var colorRegex = /\x1b\[\d{1,3}(;\d{1,3})*m/g;
    var stripAnsi = (str) => str.replace(colorRegex, "");
    exports.stripAnsi = stripAnsi;
    var findWidthInConsole = (str, charLength) => {
      let strLen = 0;
      str = (0, exports.stripAnsi)(str);
      if (charLength) {
        Object.entries(charLength).forEach(([key, value]) => {
          let regex = new RegExp(key, "g");
          strLen += (str.match(regex) || []).length * value;
          str = str.replace(key, "");
        });
      }
      strLen += (0, simple_wcswidth_1.wcswidth)(str);
      return strLen;
    };
    exports.findWidthInConsole = findWidthInConsole;
  }
});

// node_modules/.pnpm/console-table-printer@2.12.0/node_modules/console-table-printer/dist/src/utils/string-utils.js
var require_string_utils = __commonJS({
  "node_modules/.pnpm/console-table-printer@2.12.0/node_modules/console-table-printer/dist/src/utils/string-utils.js"(exports) {
    "use strict";
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.biggestWordInSentence = exports.textWithPadding = exports.splitTextIntoTextsOfMinLen = void 0;
    var console_utils_1 = require_console_utils();
    var splitTextIntoTextsOfMinLen = (inpStr, width, charLength) => {
      const ret = [];
      const spaceSeparatedStrings = inpStr.split(" ");
      let now = [];
      let cnt = 0;
      spaceSeparatedStrings.forEach((strWithoutSpace) => {
        const consoleWidth = (0, console_utils_1.findWidthInConsole)(strWithoutSpace, charLength);
        if (cnt + consoleWidth <= width) {
          cnt += consoleWidth + 1;
          now.push(strWithoutSpace);
        } else {
          ret.push(now.join(" "));
          now = [strWithoutSpace];
          cnt = consoleWidth + 1;
        }
      });
      ret.push(now.join(" "));
      return ret;
    };
    exports.splitTextIntoTextsOfMinLen = splitTextIntoTextsOfMinLen;
    var textWithPadding = (text, alignment, columnLen, charLength) => {
      const curTextSize = (0, console_utils_1.findWidthInConsole)(text, charLength);
      const leftPadding = Math.floor((columnLen - curTextSize) / 2);
      const rightPadding = columnLen - leftPadding - curTextSize;
      if (columnLen < curTextSize) {
        const splittedLines = (0, exports.splitTextIntoTextsOfMinLen)(text, columnLen);
        if (splittedLines.length === 1) {
          return text;
        }
        return splittedLines.map((singleLine) => (0, exports.textWithPadding)(singleLine, alignment, columnLen, charLength)).join("\n");
      }
      switch (alignment) {
        case "left":
          return text.concat(" ".repeat(columnLen - curTextSize));
        case "center":
          return " ".repeat(leftPadding).concat(text).concat(" ".repeat(rightPadding));
        case "right":
        default:
          return " ".repeat(columnLen - curTextSize).concat(text);
      }
    };
    exports.textWithPadding = textWithPadding;
    var biggestWordInSentence = (inpStr, charLength) => inpStr.split(" ").reduce((a, b) => Math.max(a, (0, console_utils_1.findWidthInConsole)(b, charLength)), 0);
    exports.biggestWordInSentence = biggestWordInSentence;
  }
});

// node_modules/.pnpm/console-table-printer@2.12.0/node_modules/console-table-printer/dist/src/utils/table-helpers.js
var require_table_helpers = __commonJS({
  "node_modules/.pnpm/console-table-printer@2.12.0/node_modules/console-table-printer/dist/src/utils/table-helpers.js"(exports) {
    "use strict";
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.getWidthLimitedColumnsArray = exports.createHeaderAsRow = exports.renderTableHorizontalBorders = exports.findLenOfColumn = exports.createRow = exports.createColumFromComputedColumn = exports.createColumFromOnlyName = exports.createTableHorizontalBorders = exports.convertRawRowOptionsToStandard = exports.cellText = void 0;
    var input_converter_1 = require_input_converter();
    var console_utils_1 = require_console_utils();
    var string_utils_1 = require_string_utils();
    var table_constants_1 = require_table_constants();
    var max = (a, b) => Math.max(a, b);
    var cellText = (text) => text === void 0 || text === null ? "" : `${text}`;
    exports.cellText = cellText;
    var convertRawRowOptionsToStandard = (options) => {
      if (options) {
        return {
          color: options.color,
          separator: options.separator || table_constants_1.DEFAULT_ROW_SEPARATOR
        };
      }
      return void 0;
    };
    exports.convertRawRowOptionsToStandard = convertRawRowOptionsToStandard;
    var createTableHorizontalBorders = ({ left, mid, right, other }, column_lengths) => {
      let ret = left;
      column_lengths.forEach((len) => {
        ret += other.repeat(len + 2);
        ret += mid;
      });
      ret = ret.slice(0, -mid.length);
      ret += right;
      return ret;
    };
    exports.createTableHorizontalBorders = createTableHorizontalBorders;
    var createColumFromOnlyName = (name) => ({
      name,
      title: name
    });
    exports.createColumFromOnlyName = createColumFromOnlyName;
    var createColumFromComputedColumn = (column) => {
      var _a;
      return Object.assign(Object.assign(Object.assign(Object.assign({ name: column.name, title: (_a = column.title) !== null && _a !== void 0 ? _a : column.name }, (0, input_converter_1.objIfExists)("color", column.color)), (0, input_converter_1.objIfExists)("maxLen", column.maxLen)), (0, input_converter_1.objIfExists)("minLen", column.minLen)), { alignment: column.alignment || table_constants_1.DEFAULT_ROW_ALIGNMENT });
    };
    exports.createColumFromComputedColumn = createColumFromComputedColumn;
    var createRow = (color, text, separator) => ({
      color,
      separator,
      text
    });
    exports.createRow = createRow;
    var findLenOfColumn = (column, rows, charLength) => {
      const columnId = column.name;
      const columnTitle = column.title;
      let length = max(0, (column === null || column === void 0 ? void 0 : column.minLen) || 0);
      if (column.maxLen) {
        length = max(length, max(column.maxLen, (0, string_utils_1.biggestWordInSentence)(columnTitle, charLength)));
        length = rows.reduce((acc, row) => max(acc, (0, string_utils_1.biggestWordInSentence)((0, exports.cellText)(row.text[columnId]), charLength)), length);
        return length;
      }
      length = max(length, (0, console_utils_1.findWidthInConsole)(columnTitle, charLength));
      rows.forEach((row) => {
        length = max(length, (0, console_utils_1.findWidthInConsole)((0, exports.cellText)(row.text[columnId]), charLength));
      });
      return length;
    };
    exports.findLenOfColumn = findLenOfColumn;
    var renderTableHorizontalBorders = (style, column_lengths) => {
      const str = (0, exports.createTableHorizontalBorders)(style, column_lengths);
      return str;
    };
    exports.renderTableHorizontalBorders = renderTableHorizontalBorders;
    var createHeaderAsRow = (createRowFn, columns) => {
      const headerColor = table_constants_1.DEFAULT_HEADER_FONT_COLOR;
      const row = createRowFn(headerColor, {}, false);
      columns.forEach((column) => {
        row.text[column.name] = column.title;
      });
      return row;
    };
    exports.createHeaderAsRow = createHeaderAsRow;
    var getWidthLimitedColumnsArray = (columns, row, charLength) => {
      const ret = {};
      columns.forEach((column) => {
        ret[column.name] = (0, string_utils_1.splitTextIntoTextsOfMinLen)((0, exports.cellText)(row.text[column.name]), column.length || table_constants_1.DEFAULT_COLUMN_LEN, charLength);
      });
      return ret;
    };
    exports.getWidthLimitedColumnsArray = getWidthLimitedColumnsArray;
  }
});

// node_modules/.pnpm/console-table-printer@2.12.0/node_modules/console-table-printer/dist/src/internalTable/table-pre-processors.js
var require_table_pre_processors = __commonJS({
  "node_modules/.pnpm/console-table-printer@2.12.0/node_modules/console-table-printer/dist/src/internalTable/table-pre-processors.js"(exports) {
    "use strict";
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.preProcessRows = exports.preProcessColumns = void 0;
    var table_helpers_1 = require_table_helpers();
    var createComputedColumnsIfNecessary = (table) => {
      if (table.computedColumns.length) {
        table.computedColumns.forEach((computedColumn) => {
          table.addColumn(computedColumn);
          table.rows.forEach((row) => {
            row.text[computedColumn.name] = computedColumn.function(row.text);
          });
        });
      }
    };
    var disableColumnsIfNecessary = (table) => {
      if (table.enabledColumns.length) {
        table.columns = table.columns.filter((col) => table.enabledColumns.includes(col.name));
      }
    };
    var enableColumnsIfNecessary = (table) => {
      if (table.disabledColumns.length) {
        table.columns = table.columns.filter((col) => !table.disabledColumns.includes(col.name));
      }
    };
    var findColumnWidth = (table) => {
      table.columns.forEach((column) => {
        column.length = (0, table_helpers_1.findLenOfColumn)(column, table.rows, table.charLength);
      });
    };
    var preProcessColumns = (table) => {
      createComputedColumnsIfNecessary(table);
      enableColumnsIfNecessary(table);
      disableColumnsIfNecessary(table);
      findColumnWidth(table);
    };
    exports.preProcessColumns = preProcessColumns;
    var preProcessRows = (table) => {
      const newRows = table.rows.filter((r) => table.filterFunction(r.text)).sort((r1, r2) => table.sortFunction(r1.text, r2.text));
      table.rows = newRows;
    };
    exports.preProcessRows = preProcessRows;
  }
});

// node_modules/.pnpm/console-table-printer@2.12.0/node_modules/console-table-printer/dist/src/internalTable/internal-table-printer.js
var require_internal_table_printer = __commonJS({
  "node_modules/.pnpm/console-table-printer@2.12.0/node_modules/console-table-printer/dist/src/internalTable/internal-table-printer.js"(exports) {
    "use strict";
    var __importDefault = exports && exports.__importDefault || function(mod) {
      return mod && mod.__esModule ? mod : { "default": mod };
    };
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.printSimpleTable = exports.renderSimpleTable = exports.renderTable = void 0;
    var colored_console_line_1 = __importDefault(require_colored_console_line());
    var string_utils_1 = require_string_utils();
    var table_constants_1 = require_table_constants();
    var table_helpers_1 = require_table_helpers();
    var internal_table_1 = __importDefault(require_internal_table());
    var table_pre_processors_1 = require_table_pre_processors();
    var renderOneLine = (tableStyle, columns, currentLineIndex, widthLimitedColumnsArray, isHeader, row, colorMap, charLength) => {
      const line = new colored_console_line_1.default(colorMap);
      line.addCharsWithColor("", tableStyle.vertical);
      columns.forEach((column) => {
        const thisLineHasText = currentLineIndex < widthLimitedColumnsArray[column.name].length;
        const textForThisLine = thisLineHasText ? (0, table_helpers_1.cellText)(widthLimitedColumnsArray[column.name][currentLineIndex]) : "";
        line.addCharsWithColor(table_constants_1.DEFAULT_ROW_FONT_COLOR, " ");
        line.addCharsWithColor(isHeader && table_constants_1.DEFAULT_HEADER_FONT_COLOR || column.color || row.color, (0, string_utils_1.textWithPadding)(textForThisLine, column.alignment || table_constants_1.DEFAULT_ROW_ALIGNMENT, column.length || table_constants_1.DEFAULT_COLUMN_LEN, charLength));
        line.addCharsWithColor("", ` ${tableStyle.vertical}`);
      });
      return line.renderConsole();
    };
    var renderWidthLimitedLines = (tableStyle, columns, row, colorMap, isHeader, charLength) => {
      const widthLimitedColumnsArray = (0, table_helpers_1.getWidthLimitedColumnsArray)(columns, row, charLength);
      const totalLines = Object.values(widthLimitedColumnsArray).reduce((a, b) => Math.max(a, b.length), 0);
      const ret = [];
      for (let currentLineIndex = 0; currentLineIndex < totalLines; currentLineIndex += 1) {
        const singleLine = renderOneLine(tableStyle, columns, currentLineIndex, widthLimitedColumnsArray, isHeader, row, colorMap, charLength);
        ret.push(singleLine);
      }
      return ret;
    };
    var renderRow = (table, row) => {
      let ret = [];
      ret = ret.concat(renderWidthLimitedLines(table.tableStyle, table.columns, row, table.colorMap, void 0, table.charLength));
      return ret;
    };
    var renderTableTitle = (table) => {
      const ret = [];
      if (table.title === void 0) {
        return ret;
      }
      const getTableWidth = () => {
        const reducer = (accumulator, currentValue) => (
          // ║ cell ║, 2 spaces + cellTextSize + one border on the left
          accumulator + currentValue + 2 + 1
        );
        return table.columns.map((m) => m.length || table_constants_1.DEFAULT_COLUMN_LEN).reduce(reducer, 1);
      };
      const titleWithPadding = (0, string_utils_1.textWithPadding)(table.title, table_constants_1.DEFAULT_HEADER_ALIGNMENT, getTableWidth());
      const styledText = new colored_console_line_1.default(table.colorMap);
      styledText.addCharsWithColor(table_constants_1.DEFAULT_HEADER_FONT_COLOR, titleWithPadding);
      ret.push(styledText.renderConsole());
      return ret;
    };
    var renderTableHeaders = (table) => {
      let ret = [];
      ret.push((0, table_helpers_1.renderTableHorizontalBorders)(table.tableStyle.headerTop, table.columns.map((m) => m.length || table_constants_1.DEFAULT_COLUMN_LEN)));
      const row = (0, table_helpers_1.createHeaderAsRow)(table_helpers_1.createRow, table.columns);
      ret = ret.concat(renderWidthLimitedLines(table.tableStyle, table.columns, row, table.colorMap, true));
      ret.push((0, table_helpers_1.renderTableHorizontalBorders)(table.tableStyle.headerBottom, table.columns.map((m) => m.length || table_constants_1.DEFAULT_COLUMN_LEN)));
      return ret;
    };
    var renderTableEnding = (table) => {
      const ret = [];
      ret.push((0, table_helpers_1.renderTableHorizontalBorders)(table.tableStyle.tableBottom, table.columns.map((m) => m.length || table_constants_1.DEFAULT_COLUMN_LEN)));
      return ret;
    };
    var renderRowSeparator = (table, row) => {
      const ret = [];
      const lastRowIndex = table.rows.length - 1;
      const currentRowIndex = table.rows.indexOf(row);
      if (currentRowIndex !== lastRowIndex && row.separator) {
        ret.push((0, table_helpers_1.renderTableHorizontalBorders)(table.tableStyle.rowSeparator, table.columns.map((m) => m.length || table_constants_1.DEFAULT_COLUMN_LEN)));
      }
      return ret;
    };
    var renderTable = (table) => {
      (0, table_pre_processors_1.preProcessColumns)(table);
      (0, table_pre_processors_1.preProcessRows)(table);
      const ret = [];
      renderTableTitle(table).forEach((row) => ret.push(row));
      renderTableHeaders(table).forEach((row) => ret.push(row));
      table.rows.forEach((row) => {
        renderRow(table, row).forEach((row_) => ret.push(row_));
        renderRowSeparator(table, row).forEach((row_) => ret.push(row_));
      });
      renderTableEnding(table).forEach((row) => ret.push(row));
      return ret.join("\n");
    };
    exports.renderTable = renderTable;
    var renderSimpleTable = (rows) => {
      const table = new internal_table_1.default();
      table.addRows(rows);
      return (0, exports.renderTable)(table);
    };
    exports.renderSimpleTable = renderSimpleTable;
    var printSimpleTable = (rows) => {
      console.log((0, exports.renderSimpleTable)(rows));
    };
    exports.printSimpleTable = printSimpleTable;
  }
});

// node_modules/.pnpm/console-table-printer@2.12.0/node_modules/console-table-printer/dist/src/internalTable/internal-table.js
var require_internal_table = __commonJS({
  "node_modules/.pnpm/console-table-printer@2.12.0/node_modules/console-table-printer/dist/src/internalTable/internal-table.js"(exports) {
    "use strict";
    Object.defineProperty(exports, "__esModule", { value: true });
    var colored_console_line_1 = require_colored_console_line();
    var table_constants_1 = require_table_constants();
    var table_helpers_1 = require_table_helpers();
    var input_converter_1 = require_input_converter();
    var internal_table_printer_1 = require_internal_table_printer();
    var DEFAULT_ROW_SORT_FUNC = () => 0;
    var DEFAULT_ROW_FILTER_FUNC = () => true;
    var TableInternal = class {
      initSimple(columns) {
        this.columns = columns.map((column) => ({
          name: column,
          title: column,
          alignment: table_constants_1.DEFAULT_ROW_ALIGNMENT
        }));
      }
      initDetailed(options) {
        var _a;
        this.title = (options === null || options === void 0 ? void 0 : options.title) || this.title;
        this.tableStyle = (options === null || options === void 0 ? void 0 : options.style) || this.tableStyle;
        this.sortFunction = (options === null || options === void 0 ? void 0 : options.sort) || this.sortFunction;
        this.filterFunction = (options === null || options === void 0 ? void 0 : options.filter) || this.filterFunction;
        this.enabledColumns = (options === null || options === void 0 ? void 0 : options.enabledColumns) || this.enabledColumns;
        this.disabledColumns = (options === null || options === void 0 ? void 0 : options.disabledColumns) || this.disabledColumns;
        this.computedColumns = (options === null || options === void 0 ? void 0 : options.computedColumns) || this.computedColumns;
        this.columns = ((_a = options === null || options === void 0 ? void 0 : options.columns) === null || _a === void 0 ? void 0 : _a.map(input_converter_1.rawColumnToInternalColumn)) || this.columns;
        this.rowSeparator = (options === null || options === void 0 ? void 0 : options.rowSeparator) || this.rowSeparator;
        this.charLength = (options === null || options === void 0 ? void 0 : options.charLength) || this.charLength;
        if (options === null || options === void 0 ? void 0 : options.shouldDisableColors) {
          this.colorMap = {};
        } else if (options === null || options === void 0 ? void 0 : options.colorMap) {
          this.colorMap = Object.assign(Object.assign({}, this.colorMap), options.colorMap);
        }
        if (options.rows !== void 0) {
          this.addRows(options.rows);
        }
      }
      constructor(options) {
        this.rows = [];
        this.columns = [];
        this.title = void 0;
        this.tableStyle = table_constants_1.DEFAULT_TABLE_STYLE;
        this.filterFunction = DEFAULT_ROW_FILTER_FUNC;
        this.sortFunction = DEFAULT_ROW_SORT_FUNC;
        this.enabledColumns = [];
        this.disabledColumns = [];
        this.computedColumns = [];
        this.rowSeparator = table_constants_1.DEFAULT_ROW_SEPARATOR;
        this.colorMap = colored_console_line_1.DEFAULT_COLOR_MAP;
        this.charLength = {};
        if (options instanceof Array) {
          this.initSimple(options);
        } else if (typeof options === "object") {
          this.initDetailed(options);
        }
      }
      createColumnFromRow(text) {
        const colNames = this.columns.map((col) => col.name);
        Object.keys(text).forEach((key) => {
          if (!colNames.includes(key)) {
            this.columns.push((0, table_helpers_1.createColumFromOnlyName)(key));
          }
        });
      }
      addColumn(textOrObj) {
        if (typeof textOrObj === "string") {
          this.columns.push((0, table_helpers_1.createColumFromOnlyName)(textOrObj));
        } else {
          this.columns.push((0, table_helpers_1.createColumFromComputedColumn)(textOrObj));
        }
      }
      addColumns(toBeInsertedColumns) {
        toBeInsertedColumns.forEach((toBeInsertedColumn) => {
          this.addColumn(toBeInsertedColumn);
        });
      }
      addRow(text, options) {
        this.createColumnFromRow(text);
        this.rows.push((0, table_helpers_1.createRow)((options === null || options === void 0 ? void 0 : options.color) || table_constants_1.DEFAULT_ROW_FONT_COLOR, text, (options === null || options === void 0 ? void 0 : options.separator) !== void 0 ? options === null || options === void 0 ? void 0 : options.separator : this.rowSeparator));
      }
      addRows(toBeInsertedRows, options) {
        toBeInsertedRows.forEach((toBeInsertedRow) => {
          this.addRow(toBeInsertedRow, options);
        });
      }
      renderTable() {
        return (0, internal_table_printer_1.renderTable)(this);
      }
    };
    exports.default = TableInternal;
  }
});

// node_modules/.pnpm/console-table-printer@2.12.0/node_modules/console-table-printer/dist/src/console-table-printer.js
var require_console_table_printer = __commonJS({
  "node_modules/.pnpm/console-table-printer@2.12.0/node_modules/console-table-printer/dist/src/console-table-printer.js"(exports) {
    "use strict";
    var __importDefault = exports && exports.__importDefault || function(mod) {
      return mod && mod.__esModule ? mod : { "default": mod };
    };
    Object.defineProperty(exports, "__esModule", { value: true });
    var internal_table_1 = __importDefault(require_internal_table());
    var table_helpers_1 = require_table_helpers();
    var Table2 = class {
      constructor(options) {
        this.table = new internal_table_1.default(options);
      }
      addColumn(column) {
        this.table.addColumn(column);
        return this;
      }
      addColumns(columns) {
        this.table.addColumns(columns);
        return this;
      }
      addRow(text, rowOptions) {
        this.table.addRow(text, (0, table_helpers_1.convertRawRowOptionsToStandard)(rowOptions));
        return this;
      }
      addRows(toBeInsertedRows, rowOptions) {
        this.table.addRows(toBeInsertedRows, (0, table_helpers_1.convertRawRowOptionsToStandard)(rowOptions));
        return this;
      }
      printTable() {
        const tableRendered = this.table.renderTable();
        console.log(tableRendered);
      }
      render() {
        return this.table.renderTable();
      }
    };
    exports.default = Table2;
  }
});

// node_modules/.pnpm/console-table-printer@2.12.0/node_modules/console-table-printer/dist/index.js
var require_dist2 = __commonJS({
  "node_modules/.pnpm/console-table-printer@2.12.0/node_modules/console-table-printer/dist/index.js"(exports) {
    "use strict";
    var __importDefault = exports && exports.__importDefault || function(mod) {
      return mod && mod.__esModule ? mod : { "default": mod };
    };
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.renderTable = exports.printTable = exports.Table = void 0;
    var console_table_printer_1 = __importDefault(require_console_table_printer());
    exports.Table = console_table_printer_1.default;
    var internal_table_printer_1 = require_internal_table_printer();
    Object.defineProperty(exports, "printTable", { enumerable: true, get: function() {
      return internal_table_printer_1.printSimpleTable;
    } });
    Object.defineProperty(exports, "renderTable", { enumerable: true, get: function() {
      return internal_table_printer_1.renderSimpleTable;
    } });
  }
});

// src/index.ts
var import_core2 = __toESM(require_core(), 1);
var import_console_table_printer = __toESM(require_dist2(), 1);

// src/action.ts
var import_core = __toESM(require_core(), 1);

// src/get-package-licenses.ts
import { spawn } from "node:child_process";
import { resolve } from "node:path";
import { cwd } from "node:process";
async function getLicenses(directory) {
  const proc = spawn("pnpm", ["licenses", "ls", "--json"], {
    cwd: resolve(cwd(), directory)
  });
  let stdout = "";
  proc.stdout.on("data", (data) => stdout += data.toString());
  await new Promise((resolve2, reject) => {
    proc.on("close", resolve2);
    proc.on("error", reject);
  });
  return stdout.startsWith("{") ? JSON.parse(stdout) : {};
}

// src/ignore.ts
function matchesIgnore(packageVersion, ignoredVersion) {
  if (ignoredVersion === "*")
    return true;
  if (ignoredVersion === packageVersion)
    return true;
  if (ignoredVersion.endsWith("*")) {
    const prefix = ignoredVersion.slice(0, -1);
    return packageVersion.startsWith(prefix);
  }
  return false;
}

// src/action.ts
async function action(directory, allowedLicenses, ignoredPackages) {
  let result = {
    success: true,
    unusedIgnores: [],
    licensesUsed: {}
  };
  const licenses = await getLicenses(directory);
  ignores:
    for (const ignored of ignoredPackages) {
      for (const [_, packages] of Object.entries(licenses)) {
        if (!packages) {
          (0, import_core.debug)(`Something went wrong with ${ignored.name}@${ignored.version}`);
        }
        if (packages.some((pkg) => pkg.name === ignored.name && matchesIgnore(pkg.version, ignored.version))) {
          continue ignores;
        }
      }
      result.unusedIgnores.push(`${ignored.name}@${ignored.version}`);
    }
  for (const [license, packages] of Object.entries(licenses)) {
    licenses[license] = packages.filter((pkg) => {
      for (const { name, version: version2 } of ignoredPackages) {
        if (pkg.name === name && matchesIgnore(pkg.version, version2)) {
          return false;
        }
      }
      return true;
    });
  }
  result.licensesUsed = Object.fromEntries(Object.entries(licenses).map(([license, packages]) => [license, new Set(packages)]).sort((a, b) => b[1].size - a[1].size));
  const invalidLicenses = new Set(Object.entries(licenses).filter(([license]) => !allowedLicenses.has(license)).filter(([_, packages]) => packages.length > 0).map(([license]) => license));
  if (invalidLicenses.size > 0) {
    result = {
      ...result,
      invalidLicenses,
      success: false
    };
  }
  return result;
}

// src/index.ts
try {
  const directory = ((0, import_core2.getInput)("directory", { required: false, trimWhitespace: true }) || ".").replaceAll("'", "");
  const allowedLicenses = new Set((0, import_core2.getMultilineInput)("allowed", { required: false, trimWhitespace: true }));
  const ignoredPackages = new Set((0, import_core2.getMultilineInput)("ignored", { required: false, trimWhitespace: true }).map((pkg) => pkg.replace(/#.*/, "").trim()).map((pkg) => {
    if (pkg.startsWith("@")) {
      const [_, name2 = "", version3 = ""] = pkg.split("@");
      return { name: `@${name2}`, version: version3 };
    }
    const [name = "", version2 = ""] = pkg.split("@");
    return { name, version: version2 };
  }));
  (0, import_core2.debug)(`directory: ${directory}`);
  (0, import_core2.debug)(`allowed: ${[...allowedLicenses].join(", ")}`);
  (0, import_core2.debug)(`ignored: ${[...ignoredPackages].map((pkg) => `${pkg.name}@${pkg.version}`).join(", ")}`);
  const result = await action(directory, allowedLicenses, ignoredPackages);
  if (result.success) {
    (0, import_core2.info)("All licenses are valid");
    const table = new import_console_table_printer.Table({
      columns: [
        { alignment: "left", name: "license", title: "License" },
        { alignment: "right", name: "count", title: "Count" }
      ]
    });
    table.addRows(Object.entries(result.licensesUsed).map((pkg) => ({
      license: pkg[0],
      count: pkg[1].size
    })));
    (0, import_core2.info)(table.render());
  } else {
    (0, import_core2.setFailed)("Invalid licenses found");
    for (const license of result.invalidLicenses) {
      (0, import_core2.warning)(`Invalid license ${license}`);
      const table = new import_console_table_printer.Table({
        columns: [
          { alignment: "left", name: "name", title: "Name" },
          { alignment: "left", name: "version", title: "Version" },
          { alignment: "left", name: "license", title: "License" },
          { alignment: "left", name: "homepage", title: "Homepage" }
        ]
      });
      const packages = result.licensesUsed[license];
      if (!packages) {
        continue;
      }
      table.addRows([...packages].map((pkg) => ({
        name: pkg.name,
        version: pkg.version,
        license: pkg.license,
        homepage: pkg.homepage
        // todo include chain `pnpm why <package> --json`
      })));
      (0, import_core2.info)(table.render());
    }
  }
} catch (error) {
  if (error instanceof Error) {
    (0, import_core2.setFailed)(error.message);
  } else {
    (0, import_core2.setFailed)(error ? error.toString() : "Unknown error");
  }
}
