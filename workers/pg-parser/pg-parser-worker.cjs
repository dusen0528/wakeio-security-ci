"use strict";
var __create = Object.create;
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __getProtoOf = Object.getPrototypeOf;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __commonJS = (cb, mod) => function __require() {
  try {
    return mod || (0, cb[__getOwnPropNames(cb)[0]])((mod = { exports: {} }).exports, mod), mod.exports;
  } catch (e) {
    throw mod = 0, e;
  }
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

// node_modules/@pgsql/types/types.js
var require_types = __commonJS({
  "node_modules/@pgsql/types/types.js"(exports2) {
    "use strict";
    Object.defineProperty(exports2, "__esModule", { value: true });
  }
});

// node_modules/@pgsql/types/enums.js
var require_enums = __commonJS({
  "node_modules/@pgsql/types/enums.js"(exports2) {
    "use strict";
    Object.defineProperty(exports2, "__esModule", { value: true });
  }
});

// node_modules/@pgsql/types/index.js
var require_types2 = __commonJS({
  "node_modules/@pgsql/types/index.js"(exports2) {
    "use strict";
    var __createBinding = exports2 && exports2.__createBinding || (Object.create ? (function(o, m, k, k2) {
      if (k2 === void 0) k2 = k;
      var desc = Object.getOwnPropertyDescriptor(m, k);
      if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
        desc = { enumerable: true, get: function() {
          return m[k];
        } };
      }
      Object.defineProperty(o, k2, desc);
    }) : (function(o, m, k, k2) {
      if (k2 === void 0) k2 = k;
      o[k2] = m[k];
    }));
    var __exportStar = exports2 && exports2.__exportStar || function(m, exports3) {
      for (var p in m) if (p !== "default" && !Object.prototype.hasOwnProperty.call(exports3, p)) __createBinding(exports3, m, p);
    };
    Object.defineProperty(exports2, "__esModule", { value: true });
    __exportStar(require_types(), exports2);
    __exportStar(require_enums(), exports2);
  }
});

// node_modules/libpg-query/wasm/libpg-query.js
var require_libpg_query = __commonJS({
  "node_modules/libpg-query/wasm/libpg-query.js"(exports2, module2) {
    var PgQueryModule = (() => {
      var _scriptName = globalThis.document?.currentScript?.src;
      return async function(moduleArg = {}) {
        var Module = moduleArg;
        var ENVIRONMENT_IS_WEB = !!globalThis.window;
        var ENVIRONMENT_IS_WORKER = !!globalThis.WorkerGlobalScope;
        var ENVIRONMENT_IS_NODE = globalThis.process?.versions?.node && globalThis.process?.type != "renderer";
        var programArgs = [];
        var thisProgram = "./this.program";
        var quit_ = (status, toThrow) => {
          throw toThrow;
        };
        if (typeof __filename != "undefined") {
          _scriptName = __filename;
        } else if (ENVIRONMENT_IS_WORKER) {
          _scriptName = self.location.href;
        }
        var scriptDirectory = "";
        function locateFile(path) {
          if (Module["locateFile"]) {
            return Module["locateFile"](path, scriptDirectory);
          }
          return scriptDirectory + path;
        }
        var readAsync, readBinary;
        if (ENVIRONMENT_IS_NODE) {
          var fs = require("node:fs");
          scriptDirectory = __dirname + "/";
          readBinary = (filename) => {
            filename = isFileURI(filename) ? new URL(filename) : filename;
            var ret = fs.readFileSync(filename);
            return ret;
          };
          readAsync = async (filename, binary = true) => {
            filename = isFileURI(filename) ? new URL(filename) : filename;
            var ret = fs.readFileSync(filename, binary ? void 0 : "utf8");
            return ret;
          };
          if (process.argv.length > 1) {
            thisProgram = process.argv[1].replace(/\\/g, "/");
          }
          programArgs = process.argv.slice(2);
          quit_ = (status, toThrow) => {
            process.exitCode = status;
            throw toThrow;
          };
        } else if (ENVIRONMENT_IS_WEB || ENVIRONMENT_IS_WORKER) {
          try {
            scriptDirectory = new URL(".", _scriptName).href;
          } catch {
          }
          {
            if (ENVIRONMENT_IS_WORKER) {
              readBinary = (url) => {
                var xhr = new XMLHttpRequest();
                xhr.open("GET", url, false);
                xhr.responseType = "arraybuffer";
                xhr.send(null);
                return new Uint8Array(xhr.response);
              };
            }
            readAsync = async (url) => {
              var response = await fetch(url, { credentials: "same-origin" });
              if (response.ok) {
                return response.arrayBuffer();
              }
              throw new Error(response.status + " : " + response.url);
            };
          }
        } else {
        }
        var out = console.log.bind(console);
        var err = console.error.bind(console);
        var wasmBinary;
        var ABORT = false;
        var EXITSTATUS;
        var isFileURI = (filename) => filename.startsWith("file://");
        class EmscriptenEH {
        }
        class EmscriptenSjLj extends EmscriptenEH {
        }
        var runtimeInitialized = false;
        function getMemoryBuffer() {
          return wasmMemory.buffer;
        }
        function updateMemoryViews() {
          if (HEAP8?.buffer?.resizable) return;
          var b = getMemoryBuffer();
          HEAP8 = new Int8Array(b);
          HEAP16 = new Int16Array(b);
          Module["HEAPU8"] = HEAPU8 = new Uint8Array(b);
          HEAPU16 = new Uint16Array(b);
          HEAP32 = new Int32Array(b);
          Module["HEAPU32"] = HEAPU32 = new Uint32Array(b);
          HEAPF32 = new Float32Array(b);
          HEAPF64 = new Float64Array(b);
          HEAP64 = new BigInt64Array(b);
          HEAPU64 = new BigUint64Array(b);
        }
        function preRun() {
          var preRun2 = Module["preRun"];
          if (preRun2) {
            if (typeof preRun2 == "function") preRun2 = [preRun2];
            onPreRuns.push(...preRun2);
          }
          callRuntimeCallbacks(onPreRuns);
        }
        function initRuntime() {
          runtimeInitialized = true;
          if (!Module["noFSInit"] && !FS.initialized) FS.init();
          TTY.init();
          wasmExports["A"]();
          FS.ignorePermissions = false;
        }
        function postRun() {
          var postRun2 = Module["postRun"];
          if (postRun2) {
            if (typeof postRun2 == "function") postRun2 = [postRun2];
            onPostRuns.push(...postRun2);
          }
          callRuntimeCallbacks(onPostRuns);
        }
        function abort(what) {
          Module["onAbort"]?.(what);
          what = `Aborted(${what})`;
          err(what);
          ABORT = true;
          what += ". Build with -sASSERTIONS for more info.";
          var e = new WebAssembly.RuntimeError(what);
          throw e;
        }
        var wasmBinaryFile;
        function findWasmBinary() {
          return locateFile("libpg-query.wasm");
        }
        function getBinarySync(file) {
          if (readBinary) {
            return readBinary(file);
          }
          throw "both async and sync fetching of the wasm failed";
        }
        async function getWasmBinary(binaryFile) {
          if (!wasmBinary) {
            try {
              var response = await readAsync(binaryFile);
              return new Uint8Array(response);
            } catch {
            }
          }
          return getBinarySync(binaryFile);
        }
        async function instantiateArrayBuffer(binaryFile, imports) {
          try {
            var binary = await getWasmBinary(binaryFile);
            var instance = await WebAssembly.instantiate(binary, imports);
            return instance;
          } catch (reason) {
            err(`failed to asynchronously prepare wasm: ${reason}`);
            abort(reason);
          }
        }
        async function instantiateAsync(binary, binaryFile, imports) {
          if (!binary && !ENVIRONMENT_IS_NODE) {
            try {
              var response = fetch(binaryFile, { credentials: "same-origin" });
              var instantiationResult = await WebAssembly.instantiateStreaming(response, imports);
              return instantiationResult;
            } catch (reason) {
              err(`wasm streaming compile failed: ${reason}`);
              err("falling back to ArrayBuffer instantiation");
            }
          }
          return instantiateArrayBuffer(binaryFile, imports);
        }
        function getWasmImports() {
          var imports = { a: wasmImports };
          return imports;
        }
        async function createWasm() {
          function receiveInstance(instance) {
            wasmExports = instance.exports;
            assignWasmExports(wasmExports);
            updateMemoryViews();
            return wasmExports;
          }
          function receiveInstantiationResult(result2) {
            return receiveInstance(result2["instance"]);
          }
          var info = getWasmImports();
          var instantiateWasm = Module["instantiateWasm"];
          if (instantiateWasm) {
            return new Promise((resolve) => {
              instantiateWasm(info, (inst) => resolve(receiveInstance(inst)));
            });
          }
          wasmBinaryFile ??= findWasmBinary();
          var result = await instantiateAsync(wasmBinary, wasmBinaryFile, info);
          var exports3 = receiveInstantiationResult(result);
          return exports3;
        }
        class ExitStatus {
          name = "ExitStatus";
          constructor(status) {
            this.message = `Program terminated with exit(${status})`;
            this.status = status;
          }
        }
        var HEAP16;
        var HEAP32;
        var HEAP64;
        var HEAP8;
        var HEAPF32;
        var HEAPF64;
        var HEAPU16;
        var HEAPU32;
        var HEAPU64;
        var HEAPU8;
        var callRuntimeCallbacks = (callbacks) => {
          while (callbacks.length > 0) {
            callbacks.shift()(Module);
          }
        };
        var onPostRuns = [];
        var onPreRuns = [];
        function getValue(ptr, type = "i8") {
          if (type.endsWith("*")) type = "*";
          switch (type) {
            case "i1":
              return HEAP8[ptr];
            case "i8":
              return HEAP8[ptr];
            case "i16":
              return HEAP16[ptr >> 1];
            case "i32":
              return HEAP32[ptr >> 2];
            case "i64":
              return HEAP64[ptr >> 3];
            case "float":
              return HEAPF32[ptr >> 2];
            case "double":
              return HEAPF64[ptr >> 3];
            case "*":
              return HEAPU32[ptr >> 2];
            default:
              abort(`invalid type for getValue: ${type}`);
          }
        }
        var noExitRuntime = true;
        var stackRestore = (val) => __emscripten_stack_restore(val);
        var stackSave = () => _emscripten_stack_get_current();
        var UTF8Decoder = globalThis.TextDecoder && new TextDecoder();
        var findStringEnd = (heapOrArray, idx, maxBytesToRead, ignoreNul) => {
          var maxIdx = idx + maxBytesToRead;
          if (ignoreNul) return maxIdx;
          while (heapOrArray[idx] && !(idx >= maxIdx)) ++idx;
          return idx;
        };
        var UTF8ArrayToString = (heapOrArray, idx = 0, maxBytesToRead, ignoreNul) => {
          var endPtr = findStringEnd(heapOrArray, idx, maxBytesToRead, ignoreNul);
          if (endPtr - idx > 16 && heapOrArray.buffer && UTF8Decoder) {
            return UTF8Decoder.decode(heapOrArray.subarray(idx, endPtr));
          }
          var str = "";
          while (idx < endPtr) {
            var u0 = heapOrArray[idx++];
            if (!(u0 & 128)) {
              str += String.fromCharCode(u0);
              continue;
            }
            var u1 = heapOrArray[idx++] & 63;
            if ((u0 & 224) == 192) {
              str += String.fromCharCode((u0 & 31) << 6 | u1);
              continue;
            }
            var u2 = heapOrArray[idx++] & 63;
            if ((u0 & 240) == 224) {
              u0 = (u0 & 15) << 12 | u1 << 6 | u2;
            } else {
              u0 = (u0 & 7) << 18 | u1 << 12 | u2 << 6 | heapOrArray[idx++] & 63;
            }
            if (u0 < 65536) {
              str += String.fromCharCode(u0);
            } else {
              var ch = u0 - 65536;
              str += String.fromCharCode(55296 | ch >> 10, 56320 | ch & 1023);
            }
          }
          return str;
        };
        var UTF8ToString = (ptr, maxBytesToRead, ignoreNul) => ptr ? UTF8ArrayToString(HEAPU8, ptr, maxBytesToRead, ignoreNul) : "";
        var ___assert_fail = (condition, filename, line, func) => abort(`Assertion failed: ${UTF8ToString(condition)}, at: ` + [filename ? UTF8ToString(filename) : "unknown filename", line, func ? UTF8ToString(func) : "unknown function"]);
        var __abort_js = () => abort("");
        var runtimeKeepaliveCounter = 0;
        var __emscripten_runtime_keepalive_clear = () => {
          noExitRuntime = false;
          runtimeKeepaliveCounter = 0;
        };
        var __emscripten_throw_longjmp = () => {
          throw new EmscriptenSjLj();
        };
        var timers = {};
        var handleException = (e) => {
          if (e instanceof ExitStatus || e == "unwind") {
            return EXITSTATUS;
          }
          quit_(1, e);
        };
        var keepRuntimeAlive = () => noExitRuntime || runtimeKeepaliveCounter > 0;
        var _proc_exit = (code) => {
          EXITSTATUS = code;
          if (!keepRuntimeAlive()) {
            Module["onExit"]?.(code);
            ABORT = true;
          }
          quit_(code, new ExitStatus(code));
        };
        var exitJS = (status, implicit) => {
          EXITSTATUS = status;
          _proc_exit(status);
        };
        var _exit = exitJS;
        var maybeExit = () => {
          if (!keepRuntimeAlive()) {
            try {
              _exit(EXITSTATUS);
            } catch (e) {
              handleException(e);
            }
          }
        };
        var callUserCallback = (func) => {
          if (ABORT) {
            return;
          }
          try {
            return func();
          } catch (e) {
            handleException(e);
          } finally {
            maybeExit();
          }
        };
        var _emscripten_get_now = () => performance.now();
        var __setitimer_js = (which, timeout_ms) => {
          if (timers[which]) {
            clearTimeout(timers[which].id);
            delete timers[which];
          }
          if (!timeout_ms) return 0;
          var id = setTimeout(() => {
            delete timers[which];
            callUserCallback(() => __emscripten_timeout(which, _emscripten_get_now()));
          }, timeout_ms);
          timers[which] = { id, timeout_ms };
          return 0;
        };
        var getHeapMax = () => 1073741824;
        var alignMemory = (size, alignment) => Math.ceil(size / alignment) * alignment;
        var growMemory = (size) => {
          var oldHeapSize = wasmMemory.buffer.byteLength;
          var pages = (size - oldHeapSize + 65535) / 65536 | 0;
          try {
            wasmMemory.grow(pages);
            updateMemoryViews();
            return 1;
          } catch (e) {
          }
        };
        var _emscripten_resize_heap = (requestedSize) => {
          var oldSize = HEAPU8.length;
          requestedSize >>>= 0;
          var maxHeapSize = getHeapMax();
          if (requestedSize > maxHeapSize) {
            return false;
          }
          for (var cutDown = 1; cutDown <= 4; cutDown *= 2) {
            var overGrownHeapSize = oldSize * (1 + 0.2 / cutDown);
            overGrownHeapSize = Math.min(overGrownHeapSize, requestedSize + 100663296);
            var newSize = Math.min(maxHeapSize, alignMemory(Math.max(requestedSize, overGrownHeapSize), 65536));
            var replacement = growMemory(newSize);
            if (replacement) {
              return true;
            }
          }
          return false;
        };
        var PATH = { isAbs: (path) => path.charAt(0) === "/", splitPath: (filename) => {
          var splitPathRe = /^(\/?|)([\s\S]*?)((?:\.{1,2}|[^\/]+?|)(\.[^.\/]*|))(?:[\/]*)$/;
          return splitPathRe.exec(filename).slice(1);
        }, normalizeArray: (parts, allowAboveRoot) => {
          var up = 0;
          for (var i = parts.length - 1; i >= 0; i--) {
            var last = parts[i];
            if (last === ".") {
              parts.splice(i, 1);
            } else if (last === "..") {
              parts.splice(i, 1);
              up++;
            } else if (up) {
              parts.splice(i, 1);
              up--;
            }
          }
          if (allowAboveRoot) {
            for (; up; up--) {
              parts.unshift("..");
            }
          }
          return parts;
        }, normalize: (path) => {
          var isAbsolute = PATH.isAbs(path), trailingSlash = path.slice(-1) === "/";
          path = PATH.normalizeArray(path.split("/").filter((p) => !!p), !isAbsolute).join("/");
          if (!path && !isAbsolute) {
            path = ".";
          }
          if (path && trailingSlash) {
            path += "/";
          }
          return (isAbsolute ? "/" : "") + path;
        }, dirname: (path) => {
          var result = PATH.splitPath(path), root = result[0], dir = result[1];
          if (!root && !dir) {
            return ".";
          }
          if (dir) {
            dir = dir.slice(0, -1);
          }
          return root + dir;
        }, basename: (path) => path && path.match(/([^\/]+|\/)\/*$/)[1], join: (...paths) => PATH.normalize(paths.join("/")), join2: (l, r) => PATH.normalize(l + "/" + r) };
        var initRandomFill = () => {
          if (ENVIRONMENT_IS_NODE) {
            var nodeCrypto = require("node:crypto");
            return (view) => (nodeCrypto.randomFillSync(view), 0);
          }
          return (view) => (crypto.getRandomValues(view), 0);
        };
        var randomFill = (view) => (randomFill = initRandomFill())(view);
        var PATH_FS = { resolve: (...args) => {
          var resolvedPath = "", resolvedAbsolute = false;
          for (var i = args.length - 1; i >= -1 && !resolvedAbsolute; i--) {
            var path = i >= 0 ? args[i] : FS.cwd();
            if (typeof path != "string") {
              throw new TypeError("Arguments to path.resolve must be strings");
            } else if (!path) {
              return "";
            }
            resolvedPath = path + "/" + resolvedPath;
            resolvedAbsolute = PATH.isAbs(path);
          }
          resolvedPath = PATH.normalizeArray(resolvedPath.split("/").filter((p) => !!p), !resolvedAbsolute).join("/");
          return (resolvedAbsolute ? "/" : "") + resolvedPath || ".";
        }, relative: (from, to) => {
          from = PATH_FS.resolve(from).slice(1);
          to = PATH_FS.resolve(to).slice(1);
          function trim(arr) {
            var start = 0;
            for (; start < arr.length; start++) {
              if (arr[start] !== "") break;
            }
            var end = arr.length - 1;
            for (; end >= 0; end--) {
              if (arr[end] !== "") break;
            }
            if (start > end) return [];
            return arr.slice(start, end - start + 1);
          }
          var fromParts = trim(from.split("/"));
          var toParts = trim(to.split("/"));
          var length = Math.min(fromParts.length, toParts.length);
          var samePartsLength = length;
          for (var i = 0; i < length; i++) {
            if (fromParts[i] !== toParts[i]) {
              samePartsLength = i;
              break;
            }
          }
          var outputParts = [];
          for (var i = samePartsLength; i < fromParts.length; i++) {
            outputParts.push("..");
          }
          outputParts = outputParts.concat(toParts.slice(samePartsLength));
          return outputParts.join("/");
        } };
        var FS_stdin_getChar_buffer = [];
        var lengthBytesUTF8 = (str) => {
          var len = 0;
          for (var i = 0; i < str.length; ++i) {
            var c = str.charCodeAt(i);
            if (c <= 127) {
              len++;
            } else if (c <= 2047) {
              len += 2;
            } else if (c >= 55296 && c <= 57343) {
              len += 4;
              ++i;
            } else {
              len += 3;
            }
          }
          return len;
        };
        var stringToUTF8Array = (str, heap, outIdx, maxBytesToWrite) => {
          if (!(maxBytesToWrite > 0)) return 0;
          var startIdx = outIdx;
          var endIdx = outIdx + maxBytesToWrite - 1;
          for (var i = 0; i < str.length; ++i) {
            var u = str.codePointAt(i);
            if (u <= 127) {
              if (outIdx >= endIdx) break;
              heap[outIdx++] = u;
            } else if (u <= 2047) {
              if (outIdx + 1 >= endIdx) break;
              heap[outIdx++] = 192 | u >> 6;
              heap[outIdx++] = 128 | u & 63;
            } else if (u <= 65535) {
              if (outIdx + 2 >= endIdx) break;
              heap[outIdx++] = 224 | u >> 12;
              heap[outIdx++] = 128 | u >> 6 & 63;
              heap[outIdx++] = 128 | u & 63;
            } else {
              if (outIdx + 3 >= endIdx) break;
              heap[outIdx++] = 240 | u >> 18;
              heap[outIdx++] = 128 | u >> 12 & 63;
              heap[outIdx++] = 128 | u >> 6 & 63;
              heap[outIdx++] = 128 | u & 63;
              i++;
            }
          }
          heap[outIdx] = 0;
          return outIdx - startIdx;
        };
        var intArrayFromString = (stringy, dontAddNull, length) => {
          var len = length > 0 ? length : lengthBytesUTF8(stringy) + 1;
          var u8array = new Array(len);
          var numBytesWritten = stringToUTF8Array(stringy, u8array, 0, u8array.length);
          if (dontAddNull) u8array.length = numBytesWritten;
          return u8array;
        };
        var FS_stdin_getChar = () => {
          if (!FS_stdin_getChar_buffer.length) {
            var result = null;
            if (ENVIRONMENT_IS_NODE) {
              var BUFSIZE = 256;
              var buf = Buffer.alloc(BUFSIZE);
              var bytesRead = 0;
              var fd = process.stdin.fd;
              try {
                bytesRead = fs.readSync(fd, buf, 0, BUFSIZE);
              } catch (e) {
                if (e.toString().includes("EOF")) bytesRead = 0;
                else throw e;
              }
              if (bytesRead > 0) {
                result = buf.slice(0, bytesRead).toString("utf-8");
              }
            } else if (globalThis.window?.prompt) {
              result = window.prompt("Input: ");
              if (result !== null) {
                result += "\n";
              }
            } else {
            }
            if (!result) {
              return null;
            }
            FS_stdin_getChar_buffer = intArrayFromString(result, true);
          }
          return FS_stdin_getChar_buffer.shift();
        };
        var TTY = { ttys: [], init() {
        }, shutdown() {
        }, register(dev, ops) {
          TTY.ttys[dev] = { input: [], output: [], ops };
          FS.registerDevice(dev, TTY.stream_ops);
        }, stream_ops: { open(stream) {
          var tty = TTY.ttys[stream.node.rdev];
          if (!tty) {
            throw new FS.ErrnoError(43);
          }
          stream.tty = tty;
          stream.seekable = false;
        }, close(stream) {
          stream.tty.ops.fsync(stream.tty);
        }, fsync(stream) {
          stream.tty.ops.fsync(stream.tty);
        }, read(stream, buffer, offset, length, pos) {
          if (!stream.tty || !stream.tty.ops.get_char) {
            throw new FS.ErrnoError(60);
          }
          var bytesRead = 0;
          for (var i = 0; i < length; i++) {
            var result;
            try {
              result = stream.tty.ops.get_char(stream.tty);
            } catch (e) {
              throw new FS.ErrnoError(29);
            }
            if (result === void 0 && bytesRead === 0) {
              throw new FS.ErrnoError(6);
            }
            if (result === null || result === void 0) break;
            bytesRead++;
            buffer[offset + i] = result;
          }
          if (bytesRead) {
            stream.node.atime = Date.now();
          }
          return bytesRead;
        }, write(stream, buffer, offset, length, pos) {
          if (!stream.tty || !stream.tty.ops.put_char) {
            throw new FS.ErrnoError(60);
          }
          try {
            for (var i = 0; i < length; i++) {
              stream.tty.ops.put_char(stream.tty, buffer[offset + i]);
            }
          } catch (e) {
            throw new FS.ErrnoError(29);
          }
          if (length) {
            stream.node.mtime = stream.node.ctime = Date.now();
          }
          return i;
        } }, default_tty_ops: { get_char(tty) {
          return FS_stdin_getChar();
        }, put_char(tty, val) {
          if (val === null || val === 10) {
            out(UTF8ArrayToString(tty.output));
            tty.output = [];
          } else {
            if (val != 0) tty.output.push(val);
          }
        }, fsync(tty) {
          if (tty.output?.length > 0) {
            out(UTF8ArrayToString(tty.output));
            tty.output = [];
          }
        }, ioctl_tcgets(tty) {
          return { c_iflag: 25856, c_oflag: 5, c_cflag: 191, c_lflag: 35387, c_cc: [3, 28, 127, 21, 4, 0, 1, 0, 17, 19, 26, 0, 18, 15, 23, 22, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0] };
        }, ioctl_tcsets(tty, optional_actions, data) {
          return 0;
        }, ioctl_tiocgwinsz(tty) {
          return [24, 80];
        } }, default_tty1_ops: { put_char(tty, val) {
          if (val === null || val === 10) {
            err(UTF8ArrayToString(tty.output));
            tty.output = [];
          } else {
            if (val != 0) tty.output.push(val);
          }
        }, fsync(tty) {
          if (tty.output?.length > 0) {
            err(UTF8ArrayToString(tty.output));
            tty.output = [];
          }
        } } };
        var mmapAlloc = (size) => {
          abort();
        };
        var MEMFS = { ops_table: null, mount(mount) {
          return MEMFS.createNode(null, "/", 16895, 0);
        }, createNode(parent, name, mode, dev) {
          if (FS.isBlkdev(mode) || FS.isFIFO(mode)) {
            throw new FS.ErrnoError(63);
          }
          MEMFS.ops_table ||= { dir: { node: { getattr: MEMFS.node_ops.getattr, setattr: MEMFS.node_ops.setattr, lookup: MEMFS.node_ops.lookup, mknod: MEMFS.node_ops.mknod, rename: MEMFS.node_ops.rename, unlink: MEMFS.node_ops.unlink, rmdir: MEMFS.node_ops.rmdir, readdir: MEMFS.node_ops.readdir, symlink: MEMFS.node_ops.symlink }, stream: { llseek: MEMFS.stream_ops.llseek } }, file: { node: { getattr: MEMFS.node_ops.getattr, setattr: MEMFS.node_ops.setattr }, stream: { llseek: MEMFS.stream_ops.llseek, read: MEMFS.stream_ops.read, write: MEMFS.stream_ops.write, mmap: MEMFS.stream_ops.mmap, msync: MEMFS.stream_ops.msync } }, link: { node: { getattr: MEMFS.node_ops.getattr, setattr: MEMFS.node_ops.setattr, readlink: MEMFS.node_ops.readlink }, stream: {} }, chrdev: { node: { getattr: MEMFS.node_ops.getattr, setattr: MEMFS.node_ops.setattr }, stream: FS.chrdev_stream_ops } };
          var node = FS.createNode(parent, name, mode, dev);
          if (FS.isDir(node.mode)) {
            node.node_ops = MEMFS.ops_table.dir.node;
            node.stream_ops = MEMFS.ops_table.dir.stream;
            node.contents = {};
          } else if (FS.isFile(node.mode)) {
            node.node_ops = MEMFS.ops_table.file.node;
            node.stream_ops = MEMFS.ops_table.file.stream;
            node.usedBytes = 0;
            node.contents = MEMFS.emptyFileContents ??= new Uint8Array(0);
          } else if (FS.isLink(node.mode)) {
            node.node_ops = MEMFS.ops_table.link.node;
            node.stream_ops = MEMFS.ops_table.link.stream;
          } else if (FS.isChrdev(node.mode)) {
            node.node_ops = MEMFS.ops_table.chrdev.node;
            node.stream_ops = MEMFS.ops_table.chrdev.stream;
          }
          node.atime = node.mtime = node.ctime = Date.now();
          if (parent) {
            parent.contents[name] = node;
            parent.atime = parent.mtime = parent.ctime = node.atime;
          }
          return node;
        }, getFileDataAsTypedArray(node) {
          return node.contents.subarray(0, node.usedBytes);
        }, expandFileStorage(node, newCapacity) {
          var prevCapacity = node.contents.length;
          if (prevCapacity >= newCapacity) return;
          var CAPACITY_DOUBLING_MAX = 1024 * 1024;
          newCapacity = Math.max(newCapacity, prevCapacity * (prevCapacity < CAPACITY_DOUBLING_MAX ? 2 : 1.125) >>> 0);
          if (prevCapacity) newCapacity = Math.max(newCapacity, 256);
          var oldContents = MEMFS.getFileDataAsTypedArray(node);
          node.contents = new Uint8Array(newCapacity);
          node.contents.set(oldContents);
        }, resizeFileStorage(node, newSize) {
          if (node.usedBytes == newSize) return;
          var oldContents = node.contents;
          node.contents = new Uint8Array(newSize);
          node.contents.set(oldContents.subarray(0, Math.min(newSize, node.usedBytes)));
          node.usedBytes = newSize;
        }, node_ops: { getattr(node) {
          var attr = {};
          attr.dev = FS.isChrdev(node.mode) ? node.id : 1;
          attr.ino = node.id;
          attr.mode = node.mode;
          attr.nlink = 1;
          attr.uid = 0;
          attr.gid = 0;
          attr.rdev = node.rdev;
          if (FS.isDir(node.mode)) {
            attr.size = 4096;
          } else if (FS.isFile(node.mode)) {
            attr.size = node.usedBytes;
          } else if (FS.isLink(node.mode)) {
            attr.size = node.link.length;
          } else {
            attr.size = 0;
          }
          attr.atime = new Date(node.atime);
          attr.mtime = new Date(node.mtime);
          attr.ctime = new Date(node.ctime);
          attr.blksize = 4096;
          attr.blocks = Math.ceil(attr.size / attr.blksize);
          return attr;
        }, setattr(node, attr) {
          for (const key of ["mode", "atime", "mtime", "ctime"]) {
            if (attr[key] != null) {
              node[key] = attr[key];
            }
          }
          if (attr.size !== void 0) {
            MEMFS.resizeFileStorage(node, attr.size);
          }
        }, lookup(parent, name) {
          if (!MEMFS.doesNotExistError) {
            MEMFS.doesNotExistError = new FS.ErrnoError(44);
            MEMFS.doesNotExistError.stack = "<generic error, no stack>";
          }
          throw MEMFS.doesNotExistError;
        }, mknod(parent, name, mode, dev) {
          return MEMFS.createNode(parent, name, mode, dev);
        }, rename(old_node, new_dir, new_name) {
          var new_node;
          try {
            new_node = FS.lookupNode(new_dir, new_name);
          } catch (e) {
          }
          if (new_node) {
            if (FS.isDir(old_node.mode)) {
              for (var i in new_node.contents) {
                throw new FS.ErrnoError(55);
              }
            }
            FS.hashRemoveNode(new_node);
          }
          delete old_node.parent.contents[old_node.name];
          new_dir.contents[new_name] = old_node;
          old_node.name = new_name;
          new_dir.ctime = new_dir.mtime = old_node.parent.ctime = old_node.parent.mtime = Date.now();
        }, unlink(parent, name) {
          delete parent.contents[name];
          parent.ctime = parent.mtime = Date.now();
        }, rmdir(parent, name) {
          var node = FS.lookupNode(parent, name);
          for (var i in node.contents) {
            throw new FS.ErrnoError(55);
          }
          delete parent.contents[name];
          parent.ctime = parent.mtime = Date.now();
        }, readdir(node) {
          return [".", "..", ...Object.keys(node.contents)];
        }, symlink(parent, newname, oldpath) {
          var node = MEMFS.createNode(parent, newname, 511 | 40960, 0);
          node.link = oldpath;
          return node;
        }, readlink(node) {
          if (!FS.isLink(node.mode)) {
            throw new FS.ErrnoError(28);
          }
          return node.link;
        } }, stream_ops: { read(stream, buffer, offset, length, position) {
          var contents = stream.node.contents;
          if (position >= stream.node.usedBytes) return 0;
          var size = Math.min(stream.node.usedBytes - position, length);
          buffer.set(contents.subarray(position, position + size), offset);
          return size;
        }, write(stream, buffer, offset, length, position, canOwn) {
          if (buffer.buffer === HEAP8.buffer) {
            canOwn = false;
          }
          if (!length) return 0;
          var node = stream.node;
          node.mtime = node.ctime = Date.now();
          if (canOwn) {
            node.contents = buffer.subarray(offset, offset + length);
            node.usedBytes = length;
          } else if (node.usedBytes === 0 && position === 0) {
            node.contents = buffer.slice(offset, offset + length);
            node.usedBytes = length;
          } else {
            MEMFS.expandFileStorage(node, position + length);
            node.contents.set(buffer.subarray(offset, offset + length), position);
            node.usedBytes = Math.max(node.usedBytes, position + length);
          }
          return length;
        }, llseek(stream, offset, whence) {
          var position = offset;
          if (whence === 1) {
            position += stream.position;
          } else if (whence === 2) {
            if (FS.isFile(stream.node.mode)) {
              position += stream.node.usedBytes;
            }
          }
          if (position < 0) {
            throw new FS.ErrnoError(28);
          }
          return position;
        }, mmap(stream, length, position, prot, flags) {
          if (!FS.isFile(stream.node.mode)) {
            throw new FS.ErrnoError(43);
          }
          var ptr;
          var allocated;
          var contents = stream.node.contents;
          if (!(flags & 2) && contents.buffer === HEAP8.buffer) {
            allocated = false;
            ptr = contents.byteOffset;
          } else {
            allocated = true;
            ptr = mmapAlloc(length);
            if (!ptr) {
              throw new FS.ErrnoError(48);
            }
            if (contents) {
              if (position > 0 || position + length < contents.length) {
                if (contents.subarray) {
                  contents = contents.subarray(position, position + length);
                } else {
                  contents = Array.prototype.slice.call(contents, position, position + length);
                }
              }
              HEAP8.set(contents, ptr);
            }
          }
          return { ptr, allocated };
        }, msync(stream, buffer, offset, length, mmapFlags) {
          MEMFS.stream_ops.write(stream, buffer, 0, length, offset, false);
          return 0;
        } } };
        var FS_modeStringToFlags = (str) => {
          if (typeof str != "string") return str;
          var flagModes = { r: 0, "r+": 2, w: 512 | 64 | 1, "w+": 512 | 64 | 2, a: 1024 | 64 | 1, "a+": 1024 | 64 | 2 };
          var flags = flagModes[str];
          if (typeof flags == "undefined") {
            throw new Error(`Unknown file open mode: ${str}`);
          }
          return flags;
        };
        var FS_fileDataToTypedArray = (data) => {
          if (typeof data == "string") {
            data = intArrayFromString(data, true);
          }
          if (!data.subarray) {
            data = new Uint8Array(data);
          }
          return data;
        };
        var FS_getMode = (canRead, canWrite) => {
          var mode = 0;
          if (canRead) mode |= 292 | 73;
          if (canWrite) mode |= 146;
          return mode;
        };
        var asyncLoad = async (url) => {
          var arrayBuffer = await readAsync(url);
          return new Uint8Array(arrayBuffer);
        };
        var FS_createDataFile = (...args) => FS.createDataFile(...args);
        var getUniqueRunDependency = (id) => id;
        var dependenciesPromise = null;
        var resolveRunDependencies = async () => dependenciesPromise;
        var runDependencies = 0;
        var dependenciesPromiseResolve = null;
        var removeRunDependency = (id) => {
          runDependencies--;
          Module["monitorRunDependencies"]?.(runDependencies);
          if (!runDependencies) {
            dependenciesPromiseResolve();
          }
        };
        var addRunDependency = (id) => {
          if (!runDependencies) {
            dependenciesPromise = new Promise((resolve) => dependenciesPromiseResolve = resolve);
          }
          runDependencies++;
          Module["monitorRunDependencies"]?.(runDependencies);
        };
        var preloadPlugins = [];
        var FS_handledByPreloadPlugin = async (byteArray, fullname) => {
          if (typeof Browser != "undefined") Browser.init();
          for (var plugin of preloadPlugins) {
            if (plugin["canHandle"](fullname)) {
              return plugin["handle"](byteArray, fullname);
            }
          }
          return byteArray;
        };
        var FS_preloadFile = async (parent, name, url, canRead, canWrite, dontCreateFile, canOwn, preFinish) => {
          var fullname = name ? PATH_FS.resolve(PATH.join2(parent, name)) : parent;
          var dep = getUniqueRunDependency(`cp ${fullname}`);
          addRunDependency(dep);
          try {
            var byteArray = url;
            if (typeof url == "string") {
              byteArray = await asyncLoad(url);
            }
            byteArray = await FS_handledByPreloadPlugin(byteArray, fullname);
            preFinish?.();
            if (!dontCreateFile) {
              FS_createDataFile(parent, name, byteArray, canRead, canWrite, canOwn);
            }
          } finally {
            removeRunDependency(dep);
          }
        };
        var FS_createPreloadedFile = (parent, name, url, canRead, canWrite, onload, onerror, dontCreateFile, canOwn, preFinish) => {
          FS_preloadFile(parent, name, url, canRead, canWrite, dontCreateFile, canOwn, preFinish).then(onload).catch(onerror);
        };
        var FS = { root: null, mounts: [], devices: {}, streams: [], nextInode: 1, nameTable: null, currentPath: "/", initialized: false, ignorePermissions: true, filesystems: null, syncFSRequests: 0, ErrnoError: class {
          name = "ErrnoError";
          constructor(errno) {
            this.errno = errno;
          }
        }, FSStream: class {
          shared = {};
          get object() {
            return this.node;
          }
          set object(val) {
            this.node = val;
          }
          get isRead() {
            return (this.flags & 2097155) !== 1;
          }
          get isWrite() {
            return (this.flags & 2097155) !== 0;
          }
          get isAppend() {
            return this.flags & 1024;
          }
          get flags() {
            return this.shared.flags;
          }
          set flags(val) {
            this.shared.flags = val;
          }
          get position() {
            return this.shared.position;
          }
          set position(val) {
            this.shared.position = val;
          }
        }, FSNode: class {
          node_ops = {};
          stream_ops = {};
          readMode = 292 | 73;
          writeMode = 146;
          mounted = null;
          constructor(parent, name, mode, rdev) {
            if (!parent) {
              parent = this;
            }
            this.parent = parent;
            this.mount = parent.mount;
            this.id = FS.nextInode++;
            this.name = name;
            this.mode = mode;
            this.rdev = rdev;
            this.atime = this.mtime = this.ctime = Date.now();
          }
          get read() {
            return (this.mode & this.readMode) === this.readMode;
          }
          set read(val) {
            val ? this.mode |= this.readMode : this.mode &= ~this.readMode;
          }
          get write() {
            return (this.mode & this.writeMode) === this.writeMode;
          }
          set write(val) {
            val ? this.mode |= this.writeMode : this.mode &= ~this.writeMode;
          }
          get isFolder() {
            return FS.isDir(this.mode);
          }
          get isDevice() {
            return FS.isChrdev(this.mode);
          }
          addListener(cb, exclusive = false) {
            var entry = { cb, exclusive };
            var listeners = this.listeners ??= /* @__PURE__ */ new Set();
            listeners.add(entry);
            return { listeners, entry };
          }
          notifyListeners(flags) {
            if (!this.listeners) return;
            var excl;
            for (var entry of this.listeners) {
              if (entry.exclusive) (excl ||= []).push(entry);
              else entry.cb(flags);
            }
            if (excl) {
              var i = (this.exclTurn || 0) % excl.length;
              this.exclTurn = i + 1;
              excl[i].cb(flags);
            }
          }
        }, lookupPath(path, opts = {}) {
          if (!path) {
            throw new FS.ErrnoError(44);
          }
          opts.follow_mount ??= true;
          if (!PATH.isAbs(path)) {
            path = FS.cwd() + "/" + path;
          }
          linkloop: for (var nlinks = 0; nlinks < 40; nlinks++) {
            var parts = path.split("/").filter((p) => !!p);
            var current = FS.root;
            var current_path = "/";
            for (var i = 0; i < parts.length; i++) {
              var islast = i === parts.length - 1;
              if (islast && opts.parent) {
                break;
              }
              if (parts[i] === ".") {
                continue;
              }
              if (parts[i] === "..") {
                current_path = PATH.dirname(current_path);
                if (FS.isRoot(current)) {
                  path = current_path + "/" + parts.slice(i + 1).join("/");
                  nlinks--;
                  continue linkloop;
                } else {
                  current = current.parent;
                }
                continue;
              }
              current_path = PATH.join2(current_path, parts[i]);
              try {
                current = FS.lookupNode(current, parts[i]);
              } catch (e) {
                if (e?.errno === 44 && islast && opts.noent_okay) {
                  return { path: current_path };
                }
                throw e;
              }
              if (FS.isMountpoint(current) && (!islast || opts.follow_mount)) {
                current = current.mounted.root;
              }
              if (FS.isLink(current.mode) && (!islast || opts.follow)) {
                if (!current.node_ops.readlink) {
                  throw new FS.ErrnoError(52);
                }
                var link = current.node_ops.readlink(current);
                if (!PATH.isAbs(link)) {
                  link = PATH.dirname(current_path) + "/" + link;
                }
                path = link + "/" + parts.slice(i + 1).join("/");
                continue linkloop;
              }
            }
            return { path: current_path, node: current };
          }
          throw new FS.ErrnoError(32);
        }, getPath(node) {
          var path;
          while (true) {
            if (FS.isRoot(node)) {
              var mount = node.mount.mountpoint;
              if (!path) return mount;
              return mount[mount.length - 1] !== "/" ? `${mount}/${path}` : mount + path;
            }
            path = path ? `${node.name}/${path}` : node.name;
            node = node.parent;
          }
        }, hashName(parentid, name) {
          var hash2 = 0;
          for (var i = 0; i < name.length; i++) {
            hash2 = (hash2 << 5) - hash2 + name.charCodeAt(i) | 0;
          }
          return (parentid + hash2 >>> 0) % FS.nameTable.length;
        }, hashAddNode(node) {
          var hash2 = FS.hashName(node.parent.id, node.name);
          node.name_next = FS.nameTable[hash2];
          FS.nameTable[hash2] = node;
        }, hashRemoveNode(node) {
          var hash2 = FS.hashName(node.parent.id, node.name);
          if (FS.nameTable[hash2] === node) {
            FS.nameTable[hash2] = node.name_next;
          } else {
            var current = FS.nameTable[hash2];
            while (current) {
              if (current.name_next === node) {
                current.name_next = node.name_next;
                break;
              }
              current = current.name_next;
            }
          }
        }, lookupNode(parent, name) {
          var errCode = FS.mayLookup(parent);
          if (errCode) {
            throw new FS.ErrnoError(errCode);
          }
          var hash2 = FS.hashName(parent.id, name);
          for (var node = FS.nameTable[hash2]; node; node = node.name_next) {
            var nodeName = node.name;
            if (node.parent.id === parent.id && nodeName === name) {
              return node;
            }
          }
          return FS.lookup(parent, name);
        }, createNode(parent, name, mode, rdev) {
          var node = new FS.FSNode(parent, name, mode, rdev);
          FS.hashAddNode(node);
          return node;
        }, destroyNode(node) {
          FS.hashRemoveNode(node);
        }, isRoot(node) {
          return node === node.parent;
        }, isMountpoint(node) {
          return !!node.mounted;
        }, isFile(mode) {
          return (mode & 61440) === 32768;
        }, isDir(mode) {
          return (mode & 61440) === 16384;
        }, isLink(mode) {
          return (mode & 61440) === 40960;
        }, isChrdev(mode) {
          return (mode & 61440) === 8192;
        }, isBlkdev(mode) {
          return (mode & 61440) === 24576;
        }, isFIFO(mode) {
          return (mode & 61440) === 4096;
        }, isSocket(mode) {
          return (mode & 49152) === 49152;
        }, flagsToPermissionString(flag) {
          var perms = ["r", "w", "rw"][flag & 3];
          if (flag & 512) {
            perms += "w";
          }
          return perms;
        }, nodePermissions(node, perms) {
          if (FS.ignorePermissions) {
            return 0;
          }
          if (perms.includes("r") && !(node.mode & 292)) {
            return 2;
          }
          if (perms.includes("w") && !(node.mode & 146)) {
            return 2;
          }
          if (perms.includes("x") && !(node.mode & 73)) {
            return 2;
          }
          return 0;
        }, mayLookup(dir) {
          if (!FS.isDir(dir.mode)) return 54;
          var errCode = FS.nodePermissions(dir, "x");
          if (errCode) return errCode;
          if (!dir.node_ops.lookup) return 2;
          return 0;
        }, mayCreate(dir, name) {
          if (!FS.isDir(dir.mode)) {
            return 54;
          }
          try {
            var node = FS.lookupNode(dir, name);
            return 20;
          } catch (e) {
          }
          return FS.nodePermissions(dir, "wx");
        }, mayDelete(dir, name, isdir) {
          var node;
          try {
            node = FS.lookupNode(dir, name);
          } catch (e) {
            return e.errno;
          }
          var errCode = FS.nodePermissions(dir, "wx");
          if (errCode) {
            return errCode;
          }
          if (isdir) {
            if (!FS.isDir(node.mode)) {
              return 54;
            }
            if (FS.isRoot(node) || FS.getPath(node) === FS.cwd()) {
              return 10;
            }
          } else if (FS.isDir(node.mode)) {
            return 31;
          }
          return 0;
        }, mayOpen(node, flags) {
          if (!node) {
            return 44;
          }
          if (FS.isLink(node.mode)) {
            return 32;
          }
          var mode = FS.flagsToPermissionString(flags);
          if (FS.isDir(node.mode)) {
            if (mode !== "r" || flags & (512 | 64)) {
              return 31;
            }
          }
          return FS.nodePermissions(node, mode);
        }, checkOpExists(op, err2) {
          if (!op) {
            throw new FS.ErrnoError(err2);
          }
          return op;
        }, MAX_OPEN_FDS: 4096, nextfd() {
          for (var fd = 0; fd <= FS.MAX_OPEN_FDS; fd++) {
            if (!FS.streams[fd]) {
              return fd;
            }
          }
          throw new FS.ErrnoError(33);
        }, getStreamChecked(fd) {
          var stream = FS.getStream(fd);
          if (!stream) {
            throw new FS.ErrnoError(8);
          }
          return stream;
        }, getStream: (fd) => FS.streams[fd], createStream(stream, fd = -1) {
          stream = Object.assign(new FS.FSStream(), stream);
          if (fd == -1) {
            fd = FS.nextfd();
          }
          stream.fd = fd;
          FS.streams[fd] = stream;
          return stream;
        }, closeStream(fd) {
          FS.streams[fd] = null;
        }, dupStream(origStream, fd = -1) {
          var stream = FS.createStream(origStream, fd);
          stream.stream_ops?.dup?.(stream);
          return stream;
        }, doSetAttr(stream, node, attr) {
          var setattr = stream?.stream_ops.setattr;
          var arg = setattr ? stream : node;
          setattr ??= node.node_ops.setattr;
          FS.checkOpExists(setattr, 63);
          try {
            setattr(arg, attr);
          } catch (e) {
            if (e instanceof RangeError) {
              throw new FS.ErrnoError(22);
            }
            throw e;
          }
        }, chrdev_stream_ops: { open(stream) {
          var device = FS.getDevice(stream.node.rdev);
          stream.stream_ops = device.stream_ops;
          stream.stream_ops.open?.(stream);
        }, llseek() {
          throw new FS.ErrnoError(70);
        } }, major: (dev) => dev >> 8, minor: (dev) => dev & 255, makedev: (ma, mi) => ma << 8 | mi, registerDevice(dev, ops) {
          FS.devices[dev] = { stream_ops: ops };
        }, getDevice: (dev) => FS.devices[dev], getMounts(mount) {
          var mounts = [];
          var check2 = [mount];
          while (check2.length) {
            var m = check2.pop();
            mounts.push(m);
            check2.push(...m.mounts);
          }
          return mounts;
        }, syncfs(populate, callback) {
          if (typeof populate == "function") {
            callback = populate;
            populate = false;
          }
          FS.syncFSRequests++;
          if (FS.syncFSRequests > 1) {
            err(`warning: ${FS.syncFSRequests} FS.syncfs operations in flight at once, probably just doing extra work`);
          }
          var mounts = FS.getMounts(FS.root.mount);
          var completed = 0;
          function doCallback(errCode) {
            FS.syncFSRequests--;
            return callback(errCode);
          }
          function done(errCode) {
            if (errCode) {
              if (!done.errored) {
                done.errored = true;
                return doCallback(errCode);
              }
              return;
            }
            if (++completed >= mounts.length) {
              doCallback(null);
            }
          }
          for (var mount of mounts) {
            if (mount.type.syncfs) {
              mount.type.syncfs(mount, populate, done);
            } else {
              done(null);
            }
          }
        }, mount(type, opts, mountpoint) {
          var root = mountpoint === "/";
          var pseudo = !mountpoint;
          var node;
          if (root && FS.root) {
            throw new FS.ErrnoError(10);
          } else if (!root && !pseudo) {
            var lookup = FS.lookupPath(mountpoint, { follow_mount: false });
            mountpoint = lookup.path;
            node = lookup.node;
            if (FS.isMountpoint(node)) {
              throw new FS.ErrnoError(10);
            }
            if (!FS.isDir(node.mode)) {
              throw new FS.ErrnoError(54);
            }
          }
          var mount = { type, opts, mountpoint, mounts: [] };
          var mountRoot = type.mount(mount);
          mountRoot.mount = mount;
          mount.root = mountRoot;
          if (root) {
            FS.root = mountRoot;
          } else if (node) {
            node.mounted = mount;
            if (node.mount) {
              node.mount.mounts.push(mount);
            }
          }
          return mountRoot;
        }, unmount(mountpoint) {
          var lookup = FS.lookupPath(mountpoint, { follow_mount: false });
          if (!FS.isMountpoint(lookup.node)) {
            throw new FS.ErrnoError(28);
          }
          var node = lookup.node;
          var mount = node.mounted;
          var mounts = FS.getMounts(mount);
          for (var [hash2, current] of Object.entries(FS.nameTable)) {
            while (current) {
              var next = current.name_next;
              if (mounts.includes(current.mount)) {
                FS.destroyNode(current);
              }
              current = next;
            }
          }
          node.mounted = null;
          var idx = node.mount.mounts.indexOf(mount);
          node.mount.mounts.splice(idx, 1);
        }, lookup(parent, name) {
          return parent.node_ops.lookup(parent, name);
        }, mknod(path, mode, dev) {
          var lookup = FS.lookupPath(path, { parent: true });
          var parent = lookup.node;
          var name = PATH.basename(path);
          if (!name) {
            throw new FS.ErrnoError(28);
          }
          if (name === "." || name === "..") {
            throw new FS.ErrnoError(20);
          }
          var errCode = FS.mayCreate(parent, name);
          if (errCode) {
            throw new FS.ErrnoError(errCode);
          }
          if (!parent.node_ops.mknod) {
            throw new FS.ErrnoError(63);
          }
          return parent.node_ops.mknod(parent, name, mode, dev);
        }, statfs(path) {
          return FS.statfsNode(FS.lookupPath(path, { follow: true }).node);
        }, statfsStream(stream) {
          return FS.statfsNode(stream.node);
        }, statfsNode(node) {
          var rtn = { bsize: 4096, frsize: 4096, blocks: 1e6, bfree: 5e5, bavail: 5e5, files: FS.nextInode, ffree: FS.nextInode - 1, fsid: 42, flags: 2, namelen: 255 };
          if (node.node_ops.statfs) {
            Object.assign(rtn, node.node_ops.statfs(node.mount.opts.root));
          }
          return rtn;
        }, create(path, mode = 438) {
          mode &= 4095;
          mode |= 32768;
          return FS.mknod(path, mode, 0);
        }, mkdir(path, mode = 511) {
          mode &= 511 | 512;
          mode |= 16384;
          return FS.mknod(path, mode, 0);
        }, mkdirTree(path, mode) {
          var dirs = path.split("/");
          var d = "";
          for (var dir of dirs) {
            if (!dir) continue;
            if (d || PATH.isAbs(path)) d += "/";
            d += dir;
            try {
              FS.mkdir(d, mode);
            } catch (e) {
              if (e.errno != 20) throw e;
            }
          }
        }, mkdev(path, mode, dev) {
          if (typeof dev == "undefined") {
            dev = mode;
            mode = 438;
          }
          mode |= 8192;
          return FS.mknod(path, mode, dev);
        }, symlink(oldpath, newpath) {
          if (!PATH_FS.resolve(oldpath)) {
            throw new FS.ErrnoError(44);
          }
          var lookup = FS.lookupPath(newpath, { parent: true });
          var parent = lookup.node;
          if (!parent) {
            throw new FS.ErrnoError(44);
          }
          var newname = PATH.basename(newpath);
          var errCode = FS.mayCreate(parent, newname);
          if (errCode) {
            throw new FS.ErrnoError(errCode);
          }
          if (!parent.node_ops.symlink) {
            throw new FS.ErrnoError(63);
          }
          return parent.node_ops.symlink(parent, newname, oldpath);
        }, link(oldpath, newpath, flags) {
          var lookup = FS.lookupPath(newpath, { parent: true });
          var parent = lookup.node;
          if (!parent) {
            throw new FS.ErrnoError(44);
          }
          var newname = PATH.basename(newpath);
          var errCode = FS.mayCreate(parent, newname);
          if (errCode) {
            throw new FS.ErrnoError(errCode);
          }
          if (!parent.node_ops.link) {
            throw new FS.ErrnoError(34);
          }
          return parent.node_ops.link(parent, newname, oldpath, flags);
        }, rename(old_path, new_path) {
          var old_dirname = PATH.dirname(old_path);
          var new_dirname = PATH.dirname(new_path);
          var old_name = PATH.basename(old_path);
          var new_name = PATH.basename(new_path);
          var lookup, old_dir, new_dir;
          lookup = FS.lookupPath(old_path, { parent: true });
          old_dir = lookup.node;
          lookup = FS.lookupPath(new_path, { parent: true });
          new_dir = lookup.node;
          if (!old_dir || !new_dir) throw new FS.ErrnoError(44);
          if (old_dir.mount !== new_dir.mount) {
            throw new FS.ErrnoError(75);
          }
          var old_node = FS.lookupNode(old_dir, old_name);
          var relative = PATH_FS.relative(old_path, new_dirname);
          if (relative.charAt(0) !== ".") {
            throw new FS.ErrnoError(28);
          }
          relative = PATH_FS.relative(new_path, old_dirname);
          if (relative.charAt(0) !== ".") {
            throw new FS.ErrnoError(55);
          }
          var new_node;
          try {
            new_node = FS.lookupNode(new_dir, new_name);
          } catch (e) {
          }
          if (old_node === new_node) {
            return;
          }
          var isdir = FS.isDir(old_node.mode);
          var errCode = FS.mayDelete(old_dir, old_name, isdir);
          if (errCode) {
            throw new FS.ErrnoError(errCode);
          }
          errCode = new_node ? FS.mayDelete(new_dir, new_name, isdir) : FS.mayCreate(new_dir, new_name);
          if (errCode) {
            throw new FS.ErrnoError(errCode);
          }
          if (!old_dir.node_ops.rename) {
            throw new FS.ErrnoError(63);
          }
          if (FS.isMountpoint(old_node) || new_node && FS.isMountpoint(new_node)) {
            throw new FS.ErrnoError(10);
          }
          if (new_dir !== old_dir) {
            errCode = FS.nodePermissions(old_dir, "w");
            if (errCode) {
              throw new FS.ErrnoError(errCode);
            }
          }
          FS.hashRemoveNode(old_node);
          try {
            old_dir.node_ops.rename(old_node, new_dir, new_name);
            old_node.parent = new_dir;
          } catch (e) {
            throw e;
          } finally {
            FS.hashAddNode(old_node);
          }
        }, rmdir(path) {
          var lookup = FS.lookupPath(path, { parent: true });
          var parent = lookup.node;
          var name = PATH.basename(path);
          var node = FS.lookupNode(parent, name);
          var errCode = FS.mayDelete(parent, name, true);
          if (errCode) {
            throw new FS.ErrnoError(errCode);
          }
          if (!parent.node_ops.rmdir) {
            throw new FS.ErrnoError(63);
          }
          if (FS.isMountpoint(node)) {
            throw new FS.ErrnoError(10);
          }
          parent.node_ops.rmdir(parent, name);
          FS.destroyNode(node);
        }, readdir(path) {
          var lookup = FS.lookupPath(path, { follow: true });
          var node = lookup.node;
          var readdir = FS.checkOpExists(node.node_ops.readdir, 54);
          return readdir(node);
        }, unlink(path) {
          var lookup = FS.lookupPath(path, { parent: true });
          var parent = lookup.node;
          if (!parent) {
            throw new FS.ErrnoError(44);
          }
          var name = PATH.basename(path);
          var node = FS.lookupNode(parent, name);
          var errCode = FS.mayDelete(parent, name, false);
          if (errCode) {
            throw new FS.ErrnoError(errCode);
          }
          if (!parent.node_ops.unlink) {
            throw new FS.ErrnoError(63);
          }
          if (FS.isMountpoint(node)) {
            throw new FS.ErrnoError(10);
          }
          parent.node_ops.unlink(parent, name);
          FS.destroyNode(node);
        }, readlink(path) {
          var lookup = FS.lookupPath(path);
          var link = lookup.node;
          if (!link) {
            throw new FS.ErrnoError(44);
          }
          if (!link.node_ops.readlink) {
            throw new FS.ErrnoError(28);
          }
          return link.node_ops.readlink(link);
        }, stat(path, dontFollow) {
          var lookup = FS.lookupPath(path, { follow: !dontFollow });
          var node = lookup.node;
          var getattr = FS.checkOpExists(node.node_ops.getattr, 63);
          return getattr(node);
        }, fstat(fd) {
          var stream = FS.getStreamChecked(fd);
          var node = stream.node;
          var getattr = stream.stream_ops.getattr;
          var arg = getattr ? stream : node;
          getattr ??= node.node_ops.getattr;
          FS.checkOpExists(getattr, 63);
          return getattr(arg);
        }, lstat(path) {
          return FS.stat(path, true);
        }, doChmod(stream, node, mode, dontFollow) {
          FS.doSetAttr(stream, node, { mode: mode & 4095 | node.mode & ~4095, ctime: Date.now(), dontFollow });
        }, chmod(path, mode, dontFollow) {
          var node;
          if (typeof path == "string") {
            var lookup = FS.lookupPath(path, { follow: !dontFollow });
            node = lookup.node;
          } else {
            node = path;
          }
          FS.doChmod(null, node, mode, dontFollow);
        }, lchmod(path, mode) {
          FS.chmod(path, mode, true);
        }, fchmod(fd, mode) {
          var stream = FS.getStreamChecked(fd);
          FS.doChmod(stream, stream.node, mode, false);
        }, doChown(stream, node, dontFollow) {
          FS.doSetAttr(stream, node, { timestamp: Date.now(), dontFollow });
        }, chown(path, uid, gid, dontFollow) {
          var node;
          if (typeof path == "string") {
            var lookup = FS.lookupPath(path, { follow: !dontFollow });
            node = lookup.node;
          } else {
            node = path;
          }
          FS.doChown(null, node, dontFollow);
        }, lchown(path, uid, gid) {
          FS.chown(path, uid, gid, true);
        }, fchown(fd, uid, gid) {
          var stream = FS.getStreamChecked(fd);
          FS.doChown(stream, stream.node, false);
        }, doTruncate(stream, node, len) {
          if (FS.isDir(node.mode)) {
            throw new FS.ErrnoError(31);
          }
          if (!FS.isFile(node.mode)) {
            throw new FS.ErrnoError(28);
          }
          var errCode = FS.nodePermissions(node, "w");
          if (errCode) {
            throw new FS.ErrnoError(errCode);
          }
          FS.doSetAttr(stream, node, { size: len, timestamp: Date.now() });
        }, truncate(path, len) {
          if (len < 0) {
            throw new FS.ErrnoError(28);
          }
          var node;
          if (typeof path == "string") {
            var lookup = FS.lookupPath(path, { follow: true });
            node = lookup.node;
          } else {
            node = path;
          }
          FS.doTruncate(null, node, len);
        }, ftruncate(fd, len) {
          var stream = FS.getStreamChecked(fd);
          if (len < 0 || (stream.flags & 2097155) === 0) {
            throw new FS.ErrnoError(28);
          }
          FS.doTruncate(stream, stream.node, len);
        }, utime(path, atime, mtime, dontFollow) {
          var lookup = FS.lookupPath(path, { follow: !dontFollow });
          FS.doSetAttr(null, lookup.node, { atime, mtime, dontFollow });
        }, open(path, flags, mode = 438) {
          if (path === "") {
            throw new FS.ErrnoError(44);
          }
          flags = FS_modeStringToFlags(flags);
          if (flags & 64) {
            mode = mode & 4095 | 32768;
          } else {
            mode = 0;
          }
          var node;
          var isDirPath;
          if (typeof path == "object") {
            node = path;
          } else {
            isDirPath = path.endsWith("/");
            var lookup = FS.lookupPath(path, { follow: !(flags & 131072), noent_okay: true });
            node = lookup.node;
            path = lookup.path;
          }
          var created = false;
          if (flags & 64) {
            if (node) {
              if (flags & 128) {
                throw new FS.ErrnoError(20);
              }
            } else if (isDirPath) {
              throw new FS.ErrnoError(31);
            } else {
              node = FS.mknod(path, mode | 511, 0);
              created = true;
            }
          }
          if (!node) {
            throw new FS.ErrnoError(44);
          }
          if (FS.isChrdev(node.mode)) {
            flags &= ~512;
          }
          if (flags & 65536 && !FS.isDir(node.mode)) {
            throw new FS.ErrnoError(54);
          }
          if (!created) {
            var errCode = FS.mayOpen(node, flags);
            if (errCode) {
              throw new FS.ErrnoError(errCode);
            }
          }
          if (flags & 512 && !created) {
            FS.truncate(node, 0);
          }
          flags &= ~(128 | 512 | 131072);
          var stream = FS.createStream({ node, path: FS.getPath(node), flags, seekable: true, position: 0, stream_ops: node.stream_ops, ungotten: [], error: false });
          if (stream.stream_ops.open) {
            stream.stream_ops.open(stream);
          }
          if (created) {
            FS.chmod(node, mode & 511);
          }
          return stream;
        }, close(stream) {
          if (FS.isClosed(stream)) {
            throw new FS.ErrnoError(8);
          }
          if (stream.getdents) stream.getdents = null;
          stream.node?.notifyListeners(32);
          try {
            if (stream.stream_ops.close) {
              stream.stream_ops.close(stream);
            }
          } catch (e) {
            throw e;
          } finally {
            FS.closeStream(stream.fd);
          }
          stream.fd = null;
        }, isClosed(stream) {
          return stream.fd === null;
        }, llseek(stream, offset, whence) {
          if (FS.isClosed(stream)) {
            throw new FS.ErrnoError(8);
          }
          if (!stream.seekable || !stream.stream_ops.llseek) {
            throw new FS.ErrnoError(70);
          }
          if (whence != 0 && whence != 1 && whence != 2) {
            throw new FS.ErrnoError(28);
          }
          stream.position = stream.stream_ops.llseek(stream, offset, whence);
          stream.ungotten = [];
          return stream.position;
        }, read(stream, buffer, offset, length, position) {
          if (length < 0 || position < 0) {
            throw new FS.ErrnoError(28);
          }
          if (FS.isClosed(stream)) {
            throw new FS.ErrnoError(8);
          }
          if ((stream.flags & 2097155) === 1) {
            throw new FS.ErrnoError(8);
          }
          if (FS.isDir(stream.node.mode)) {
            throw new FS.ErrnoError(31);
          }
          if (!stream.stream_ops.read) {
            throw new FS.ErrnoError(28);
          }
          var seeking = typeof position != "undefined";
          if (!seeking) {
            position = stream.position;
          } else if (!stream.seekable) {
            throw new FS.ErrnoError(70);
          }
          var bytesRead = stream.stream_ops.read(stream, buffer, offset, length, position);
          if (!seeking) stream.position += bytesRead;
          return bytesRead;
        }, write(stream, buffer, offset, length, position, canOwn) {
          if (length < 0 || position < 0) {
            throw new FS.ErrnoError(28);
          }
          if (FS.isClosed(stream)) {
            throw new FS.ErrnoError(8);
          }
          if ((stream.flags & 2097155) === 0) {
            throw new FS.ErrnoError(8);
          }
          if (FS.isDir(stream.node.mode)) {
            throw new FS.ErrnoError(31);
          }
          if (!stream.stream_ops.write) {
            throw new FS.ErrnoError(28);
          }
          if (stream.seekable && stream.flags & 1024) {
            FS.llseek(stream, 0, 2);
          }
          var seeking = typeof position != "undefined";
          if (!seeking) {
            position = stream.position;
          } else if (!stream.seekable) {
            throw new FS.ErrnoError(70);
          }
          var bytesWritten = stream.stream_ops.write(stream, buffer, offset, length, position, canOwn);
          if (!seeking) stream.position += bytesWritten;
          return bytesWritten;
        }, mmap(stream, length, position, prot, flags) {
          if ((prot & 2) !== 0 && (flags & 2) === 0 && (stream.flags & 2097155) !== 2) {
            throw new FS.ErrnoError(2);
          }
          if ((stream.flags & 2097155) === 1) {
            throw new FS.ErrnoError(2);
          }
          if (!stream.stream_ops.mmap) {
            throw new FS.ErrnoError(43);
          }
          if (!length) {
            throw new FS.ErrnoError(28);
          }
          return stream.stream_ops.mmap(stream, length, position, prot, flags);
        }, msync(stream, buffer, offset, length, mmapFlags) {
          if (!stream.stream_ops.msync) {
            return 0;
          }
          return stream.stream_ops.msync(stream, buffer, offset, length, mmapFlags);
        }, ioctl(stream, cmd, arg) {
          if (!stream.stream_ops.ioctl) {
            throw new FS.ErrnoError(59);
          }
          return stream.stream_ops.ioctl(stream, cmd, arg);
        }, readFile(path, opts = {}) {
          opts.flags = opts.flags ?? 0;
          opts.encoding = opts.encoding ?? "binary";
          if (opts.encoding !== "utf8" && opts.encoding !== "binary") {
            abort(`Invalid encoding type "${opts.encoding}"`);
          }
          var stream = FS.open(path, opts.flags);
          var stat = FS.stat(path);
          var length = stat.size;
          var buf = new Uint8Array(length);
          FS.read(stream, buf, 0, length, 0);
          if (opts.encoding === "utf8") {
            buf = UTF8ArrayToString(buf);
          }
          FS.close(stream);
          return buf;
        }, writeFile(path, data, opts = {}) {
          opts.flags = opts.flags ?? 577;
          var stream = FS.open(path, opts.flags, opts.mode);
          data = FS_fileDataToTypedArray(data);
          FS.write(stream, data, 0, data.byteLength, void 0, opts.canOwn);
          FS.close(stream);
        }, cwd: () => FS.currentPath, chdir(path) {
          var lookup = FS.lookupPath(path, { follow: true });
          if (lookup.node === null) {
            throw new FS.ErrnoError(44);
          }
          if (!FS.isDir(lookup.node.mode)) {
            throw new FS.ErrnoError(54);
          }
          var errCode = FS.nodePermissions(lookup.node, "x");
          if (errCode) {
            throw new FS.ErrnoError(errCode);
          }
          FS.currentPath = lookup.path;
        }, createDefaultDirectories() {
          FS.mkdir("/tmp");
          FS.mkdir("/home");
          FS.mkdir("/home/web_user");
        }, createDefaultDevices() {
          FS.mkdir("/dev");
          FS.registerDevice(FS.makedev(1, 3), { read: () => 0, write: (stream, buffer, offset, length, pos) => length, llseek: () => 0 });
          FS.mkdev("/dev/null", FS.makedev(1, 3));
          TTY.register(FS.makedev(5, 0), TTY.default_tty_ops);
          TTY.register(FS.makedev(6, 0), TTY.default_tty1_ops);
          FS.mkdev("/dev/tty", FS.makedev(5, 0));
          FS.mkdev("/dev/tty1", FS.makedev(6, 0));
          var randomBuffer = new Uint8Array(1024), randomLeft = 0;
          var randomByte = () => {
            if (randomLeft === 0) {
              randomFill(randomBuffer);
              randomLeft = randomBuffer.byteLength;
            }
            return randomBuffer[--randomLeft];
          };
          FS.createDevice("/dev", "random", randomByte);
          FS.createDevice("/dev", "urandom", randomByte);
          FS.mkdir("/dev/shm");
          FS.mkdir("/dev/shm/tmp");
        }, createSpecialDirectories() {
          FS.mkdir("/proc");
          var proc_self = FS.mkdir("/proc/self");
          FS.mkdir("/proc/self/fd");
          FS.mount({ mount() {
            var node = FS.createNode(proc_self, "fd", 16895, 73);
            node.stream_ops = { llseek: MEMFS.stream_ops.llseek };
            node.node_ops = { lookup(parent, name) {
              var fd = +name;
              var stream = FS.getStreamChecked(fd);
              var ret = { parent: null, mount: { mountpoint: "fake" }, node_ops: { readlink: () => stream.path }, id: fd + 1 };
              ret.parent = ret;
              return ret;
            }, readdir() {
              return Array.from(FS.streams.entries()).filter(([k, v]) => v).map(([k, v]) => k.toString());
            } };
            return node;
          } }, {}, "/proc/self/fd");
        }, createStandardStreams(input2, output2, error) {
          if (input2) {
            FS.createDevice("/dev", "stdin", input2);
          } else {
            FS.symlink("/dev/tty", "/dev/stdin");
          }
          if (output2) {
            FS.createDevice("/dev", "stdout", null, output2);
          } else {
            FS.symlink("/dev/tty", "/dev/stdout");
          }
          if (error) {
            FS.createDevice("/dev", "stderr", null, error);
          } else {
            FS.symlink("/dev/tty1", "/dev/stderr");
          }
          var stdin = FS.open("/dev/stdin", 0);
          var stdout = FS.open("/dev/stdout", 1);
          var stderr = FS.open("/dev/stderr", 1);
        }, staticInit() {
          FS.nameTable = new Array(4096);
          FS.mount(MEMFS, {}, "/");
          FS.createDefaultDirectories();
          FS.createDefaultDevices();
          FS.createSpecialDirectories();
          FS.filesystems = { MEMFS };
        }, init(input2, output2, error) {
          FS.initialized = true;
          input2 ??= Module["stdin"];
          output2 ??= Module["stdout"];
          error ??= Module["stderr"];
          FS.createStandardStreams(input2, output2, error);
        }, quit() {
          FS.initialized = false;
          for (var stream of FS.streams) {
            if (stream) {
              FS.close(stream);
            }
          }
        }, findObject(path, dontResolveLastLink) {
          var ret = FS.analyzePath(path, dontResolveLastLink);
          if (!ret.exists) {
            return null;
          }
          return ret.object;
        }, analyzePath(path, dontResolveLastLink) {
          try {
            var lookup = FS.lookupPath(path, { follow: !dontResolveLastLink });
            path = lookup.path;
          } catch (e) {
          }
          var ret = { isRoot: false, exists: false, error: 0, name: null, path: null, object: null, parentExists: false, parentPath: null, parentObject: null };
          try {
            var lookup = FS.lookupPath(path, { parent: true });
            ret.parentExists = true;
            ret.parentPath = lookup.path;
            ret.parentObject = lookup.node;
            ret.name = PATH.basename(path);
            lookup = FS.lookupPath(path, { follow: !dontResolveLastLink });
            ret.exists = true;
            ret.path = lookup.path;
            ret.object = lookup.node;
            ret.name = lookup.node.name;
            ret.isRoot = lookup.path === "/";
          } catch (e) {
            ret.error = e.errno;
          }
          return ret;
        }, createPath(parent, path, canRead, canWrite) {
          parent = typeof parent == "string" ? parent : FS.getPath(parent);
          var parts = path.split("/").reverse();
          while (parts.length) {
            var part = parts.pop();
            if (!part) continue;
            var current = PATH.join2(parent, part);
            try {
              FS.mkdir(current);
            } catch (e) {
              if (e.errno != 20) throw e;
            }
            parent = current;
          }
          return current;
        }, createFile(parent, name, properties, canRead, canWrite) {
          var path = PATH.join2(typeof parent == "string" ? parent : FS.getPath(parent), name);
          var mode = FS_getMode(canRead, canWrite);
          return FS.create(path, mode);
        }, createDataFile(parent, name, data, canRead, canWrite, canOwn) {
          var path = name;
          if (parent) {
            parent = typeof parent == "string" ? parent : FS.getPath(parent);
            path = name ? PATH.join2(parent, name) : parent;
          }
          var mode = FS_getMode(canRead, canWrite);
          var node = FS.create(path, mode);
          if (data) {
            data = FS_fileDataToTypedArray(data);
            FS.chmod(node, mode | 146);
            var stream = FS.open(node, 577);
            FS.write(stream, data, 0, data.length, 0, canOwn);
            FS.close(stream);
            FS.chmod(node, mode);
          }
        }, createDevice(parent, name, input2, output2) {
          var path = PATH.join2(typeof parent == "string" ? parent : FS.getPath(parent), name);
          var mode = FS_getMode(!!input2, !!output2);
          FS.createDevice.major ??= 64;
          var dev = FS.makedev(FS.createDevice.major++, 0);
          FS.registerDevice(dev, { open(stream) {
            stream.seekable = false;
          }, close(stream) {
            if (output2?.buffer?.length) {
              output2(10);
            }
          }, read(stream, buffer, offset, length, pos) {
            var bytesRead = 0;
            for (var i = 0; i < length; i++) {
              var result;
              try {
                result = input2();
              } catch (e) {
                throw new FS.ErrnoError(29);
              }
              if (result === void 0 && bytesRead === 0) {
                throw new FS.ErrnoError(6);
              }
              if (result === null || result === void 0) break;
              bytesRead++;
              buffer[offset + i] = result;
            }
            if (bytesRead) {
              stream.node.atime = Date.now();
            }
            return bytesRead;
          }, write(stream, buffer, offset, length, pos) {
            for (var i = 0; i < length; i++) {
              try {
                output2(buffer[offset + i]);
              } catch (e) {
                throw new FS.ErrnoError(29);
              }
            }
            if (length) {
              stream.node.mtime = stream.node.ctime = Date.now();
            }
            return i;
          } });
          return FS.mkdev(path, mode, dev);
        }, forceLoadFile(obj) {
          if (obj.isDevice || obj.isFolder || obj.link || obj.contents) return true;
          if (globalThis.XMLHttpRequest) {
            abort("Lazy loading should have been performed (contents set) in createLazyFile, but it was not. Lazy loading only works in web workers. Use --embed-file or --preload-file in emcc on the main thread.");
          } else {
            try {
              obj.contents = readBinary(obj.url);
            } catch (e) {
              throw new FS.ErrnoError(29);
            }
          }
        }, createLazyFile(parent, name, url, canRead, canWrite) {
          class LazyUint8Array {
            lengthKnown = false;
            chunks = [];
            get(idx) {
              if (idx > this.length - 1 || idx < 0) {
                return void 0;
              }
              var chunkOffset = idx % this.chunkSize;
              var chunkNum = idx / this.chunkSize | 0;
              return this.getter(chunkNum)[chunkOffset];
            }
            setDataGetter(getter) {
              this.getter = getter;
            }
            cacheLength() {
              var xhr = new XMLHttpRequest();
              xhr.open("HEAD", url, false);
              xhr.send(null);
              if (!(xhr.status >= 200 && xhr.status < 300 || xhr.status === 304)) abort("Couldn't load " + url + ". Status: " + xhr.status);
              var datalength = Number(xhr.getResponseHeader("Content-length"));
              var header;
              var hasByteServing = (header = xhr.getResponseHeader("Accept-Ranges")) && header === "bytes";
              var usesGzip = (header = xhr.getResponseHeader("Content-Encoding")) && header === "gzip";
              var chunkSize = 1024 * 1024;
              if (!hasByteServing) chunkSize = datalength;
              var doXHR = (from, to) => {
                if (from > to) abort(`invalid range (${from}, ${to}) or no bytes requested!`);
                if (to > datalength - 1) abort(`only ${datalength} bytes available! programmer error!`);
                var xhr2 = new XMLHttpRequest();
                xhr2.open("GET", url, false);
                if (datalength !== chunkSize) xhr2.setRequestHeader("Range", "bytes=" + from + "-" + to);
                xhr2.responseType = "arraybuffer";
                if (xhr2.overrideMimeType) {
                  xhr2.overrideMimeType("text/plain; charset=x-user-defined");
                }
                xhr2.send(null);
                if (!(xhr2.status >= 200 && xhr2.status < 300 || xhr2.status === 304)) abort("Couldn't load " + url + ". Status: " + xhr2.status);
                if (xhr2.response !== void 0) {
                  return new Uint8Array(xhr2.response || []);
                }
                return intArrayFromString(xhr2.responseText ?? "", true);
              };
              var lazyArray2 = this;
              lazyArray2.setDataGetter((chunkNum) => {
                var start = chunkNum * chunkSize;
                var end = (chunkNum + 1) * chunkSize - 1;
                end = Math.min(end, datalength - 1);
                if (typeof lazyArray2.chunks[chunkNum] == "undefined") {
                  lazyArray2.chunks[chunkNum] = doXHR(start, end);
                }
                if (typeof lazyArray2.chunks[chunkNum] == "undefined") abort("doXHR failed!");
                return lazyArray2.chunks[chunkNum];
              });
              if (usesGzip || !datalength) {
                chunkSize = datalength = 1;
                datalength = this.getter(0).length;
                chunkSize = datalength;
                out("LazyFiles on gzip forces download of the whole file when length is accessed");
              }
              this._length = datalength;
              this._chunkSize = chunkSize;
              this.lengthKnown = true;
            }
            get length() {
              if (!this.lengthKnown) {
                this.cacheLength();
              }
              return this._length;
            }
            get chunkSize() {
              if (!this.lengthKnown) {
                this.cacheLength();
              }
              return this._chunkSize;
            }
          }
          if (globalThis.XMLHttpRequest) {
            if (!ENVIRONMENT_IS_WORKER) abort("Cannot do synchronous binary XHRs outside webworkers in modern browsers. Use --embed-file or --preload-file in emcc");
            var lazyArray = new LazyUint8Array();
            var properties = { isDevice: false, contents: lazyArray };
          } else {
            var properties = { isDevice: false, url };
          }
          var node = FS.createFile(parent, name, properties, canRead, canWrite);
          if (properties.contents) {
            node.contents = properties.contents;
          } else if (properties.url) {
            node.contents = null;
            node.url = properties.url;
          }
          Object.defineProperties(node, { usedBytes: { get: function() {
            return this.contents.length;
          } } });
          var stream_ops = {};
          for (const [key, fn] of Object.entries(node.stream_ops)) {
            stream_ops[key] = (...args) => {
              FS.forceLoadFile(node);
              return fn(...args);
            };
          }
          function writeChunks(stream, buffer, offset, length, position) {
            var contents = stream.node.contents;
            if (position >= contents.length) return 0;
            var size = Math.min(contents.length - position, length);
            if (contents.slice) {
              for (var i = 0; i < size; i++) {
                buffer[offset + i] = contents[position + i];
              }
            } else {
              for (var i = 0; i < size; i++) {
                buffer[offset + i] = contents.get(position + i);
              }
            }
            return size;
          }
          stream_ops.read = (stream, buffer, offset, length, position) => {
            FS.forceLoadFile(node);
            return writeChunks(stream, buffer, offset, length, position);
          };
          stream_ops.mmap = (stream, length, position, prot, flags) => {
            FS.forceLoadFile(node);
            var ptr = mmapAlloc(length);
            if (!ptr) {
              throw new FS.ErrnoError(48);
            }
            writeChunks(stream, HEAP8, ptr, length, position);
            return { ptr, allocated: true };
          };
          node.stream_ops = stream_ops;
          return node;
        } };
        var SYSCALLS = { currentUmask: 18, calculateAt(dirfd, path, allowEmpty) {
          if (PATH.isAbs(path)) {
            return path;
          }
          var dir;
          if (dirfd === -100) {
            dir = FS.cwd();
          } else {
            var dirstream = SYSCALLS.getStreamFromFD(dirfd);
            dir = dirstream.path;
          }
          if (path.length == 0) {
            if (!allowEmpty) {
              throw new FS.ErrnoError(44);
            }
            return dir;
          }
          return dir + "/" + path;
        }, writeStat(buf, stat) {
          HEAPU32[buf >> 2] = stat.dev;
          HEAPU32[buf + 4 >> 2] = stat.mode;
          HEAPU32[buf + 8 >> 2] = stat.nlink;
          HEAPU32[buf + 12 >> 2] = stat.uid;
          HEAPU32[buf + 16 >> 2] = stat.gid;
          HEAPU32[buf + 20 >> 2] = stat.rdev;
          HEAP64[buf + 24 >> 3] = BigInt(stat.size);
          HEAP32[buf + 32 >> 2] = 4096;
          HEAP32[buf + 36 >> 2] = stat.blocks;
          var atime = stat.atime.getTime();
          var mtime = stat.mtime.getTime();
          var ctime = stat.ctime.getTime();
          HEAP64[buf + 40 >> 3] = BigInt(Math.floor(atime / 1e3));
          HEAPU32[buf + 48 >> 2] = atime % 1e3 * 1e3 * 1e3;
          HEAP64[buf + 56 >> 3] = BigInt(Math.floor(mtime / 1e3));
          HEAPU32[buf + 64 >> 2] = mtime % 1e3 * 1e3 * 1e3;
          HEAP64[buf + 72 >> 3] = BigInt(Math.floor(ctime / 1e3));
          HEAPU32[buf + 80 >> 2] = ctime % 1e3 * 1e3 * 1e3;
          HEAP64[buf + 88 >> 3] = BigInt(stat.ino);
          return 0;
        }, writeStatFs(buf, stats) {
          HEAPU32[buf + 4 >> 2] = stats.bsize;
          HEAPU32[buf + 60 >> 2] = stats.bsize;
          HEAP64[buf + 8 >> 3] = BigInt(stats.blocks);
          HEAP64[buf + 16 >> 3] = BigInt(stats.bfree);
          HEAP64[buf + 24 >> 3] = BigInt(stats.bavail);
          HEAP64[buf + 32 >> 3] = BigInt(stats.files);
          HEAP64[buf + 40 >> 3] = BigInt(stats.ffree);
          HEAPU32[buf + 48 >> 2] = stats.fsid;
          HEAPU32[buf + 64 >> 2] = stats.flags;
          HEAPU32[buf + 56 >> 2] = stats.namelen;
        }, doMsync(addr, stream, len, flags, offset) {
          if (!FS.isFile(stream.node.mode)) {
            throw new FS.ErrnoError(43);
          }
          if (flags & 2) {
            return 0;
          }
          var buffer = HEAPU8.subarray(addr, addr + len);
          FS.msync(stream, buffer, offset, len, flags);
        }, getStreamFromFD(fd) {
          var stream = FS.getStreamChecked(fd);
          return stream;
        }, varargs: void 0, getStr(ptr) {
          var ret = UTF8ToString(ptr);
          return ret;
        } };
        function _fd_close(fd) {
          try {
            var stream = SYSCALLS.getStreamFromFD(fd);
            FS.close(stream);
            return 0;
          } catch (e) {
            if (typeof FS == "undefined" || !(e.name === "ErrnoError")) throw e;
            return e.errno;
          }
        }
        var doReadv = (stream, iov, iovcnt, offset) => {
          var ret = 0;
          for (var i = 0; i < iovcnt; i++) {
            var ptr = HEAPU32[iov >> 2];
            var len = HEAPU32[iov + 4 >> 2];
            iov += 8;
            try {
              var curr = FS.read(stream, HEAP8, ptr, len, offset);
            } catch (e) {
              if (ret > 0 && e instanceof FS.ErrnoError && (e.errno == 6 || e.errno == 6)) {
                break;
              }
              throw e;
            }
            if (curr < 0) return -1;
            ret += curr;
            if (curr < len) break;
            if (typeof offset != "undefined") {
              offset += curr;
            }
          }
          return ret;
        };
        function _fd_read(fd, iov, iovcnt, pnum) {
          try {
            var stream = SYSCALLS.getStreamFromFD(fd);
            var num = doReadv(stream, iov, iovcnt);
            HEAPU32[pnum >> 2] = num;
            return 0;
          } catch (e) {
            if (typeof FS == "undefined" || !(e.name === "ErrnoError")) throw e;
            return e.errno;
          }
        }
        var INT53_MAX = 9007199254740992;
        var INT53_MIN = -9007199254740992;
        var bigintToI53Checked = (num) => num < INT53_MIN || num > INT53_MAX ? NaN : Number(num);
        function _fd_seek(fd, offset, whence, newOffset) {
          offset = bigintToI53Checked(offset);
          try {
            if (isNaN(offset)) return 22;
            var stream = SYSCALLS.getStreamFromFD(fd);
            FS.llseek(stream, offset, whence);
            HEAP64[newOffset >> 3] = BigInt(stream.position);
            if (stream.getdents && offset === 0 && whence === 0) stream.getdents = null;
            return 0;
          } catch (e) {
            if (typeof FS == "undefined" || !(e.name === "ErrnoError")) throw e;
            return e.errno;
          }
        }
        var doWritev = (stream, iov, iovcnt, offset) => {
          if (iovcnt == 1) {
            return FS.write(stream, HEAP8, HEAPU32[iov >> 2], HEAPU32[iov + 4 >> 2], offset);
          }
          var total = 0;
          for (var i = 0, p = iov; i < iovcnt; i++, p += 8) {
            total += HEAPU32[p + 4 >> 2];
          }
          var view = new Uint8Array(total);
          var voff = 0;
          for (var i = 0; i < iovcnt; i++, iov += 8) {
            var ptr = HEAPU32[iov >> 2];
            var len = HEAPU32[iov + 4 >> 2];
            view.set(HEAPU8.subarray(ptr, ptr + len), voff);
            voff += len;
          }
          return FS.write(stream, view, 0, total, offset);
        };
        function _fd_write(fd, iov, iovcnt, pnum) {
          try {
            var stream = SYSCALLS.getStreamFromFD(fd);
            var num = doWritev(stream, iov, iovcnt);
            HEAPU32[pnum >> 2] = num;
            return 0;
          } catch (e) {
            if (typeof FS == "undefined" || !(e.name === "ErrnoError")) throw e;
            return e.errno;
          }
        }
        var wasmTableMirror = [];
        var getWasmTableEntry = (funcPtr) => {
          var func = wasmTableMirror[funcPtr];
          if (!func) {
            wasmTableMirror[funcPtr] = func = wasmTable.get(funcPtr);
          }
          return func;
        };
        var stringToUTF8 = (str, outPtr, maxBytesToWrite) => stringToUTF8Array(str, HEAPU8, outPtr, maxBytesToWrite);
        FS.createPreloadedFile = FS_createPreloadedFile;
        FS.preloadFile = FS_preloadFile;
        FS.staticInit();
        {
          if (Module["noExitRuntime"]) noExitRuntime = Module["noExitRuntime"];
          if (Module["print"]) out = Module["print"];
          if (Module["printErr"]) err = Module["printErr"];
          if (Module["arguments"]) programArgs = Module["arguments"];
          if (Module["thisProgram"]) thisProgram = Module["thisProgram"];
          var preInit = Module["preInit"];
          if (preInit) {
            if (typeof preInit == "function") Module["preInit"] = preInit = [preInit];
            while (preInit.length > 0) {
              preInit.shift()();
            }
          }
        }
        Module["getValue"] = getValue;
        Module["UTF8ToString"] = UTF8ToString;
        Module["stringToUTF8"] = stringToUTF8;
        Module["lengthBytesUTF8"] = lengthBytesUTF8;
        var _wasm_parse_query, _malloc, _free, _wasm_parse_query_raw, _wasm_free_parse_result, _wasm_parse_plpgsql, _wasm_fingerprint, _wasm_normalize_query, _wasm_parse_query_detailed, _wasm_free_detailed_result, _wasm_scan, _wasm_free_string, __emscripten_timeout, _setThrew, __emscripten_stack_restore, _emscripten_stack_get_current, memory, __indirect_function_table, wasmMemory, wasmTable;
        function assignWasmExports(wasmExports2) {
          _wasm_parse_query = Module["_wasm_parse_query"] = wasmExports2["B"];
          _malloc = Module["_malloc"] = wasmExports2["C"];
          _free = Module["_free"] = wasmExports2["E"];
          _wasm_parse_query_raw = Module["_wasm_parse_query_raw"] = wasmExports2["F"];
          _wasm_free_parse_result = Module["_wasm_free_parse_result"] = wasmExports2["G"];
          _wasm_parse_plpgsql = Module["_wasm_parse_plpgsql"] = wasmExports2["H"];
          _wasm_fingerprint = Module["_wasm_fingerprint"] = wasmExports2["I"];
          _wasm_normalize_query = Module["_wasm_normalize_query"] = wasmExports2["J"];
          _wasm_parse_query_detailed = Module["_wasm_parse_query_detailed"] = wasmExports2["K"];
          _wasm_free_detailed_result = Module["_wasm_free_detailed_result"] = wasmExports2["L"];
          _wasm_scan = Module["_wasm_scan"] = wasmExports2["M"];
          _wasm_free_string = Module["_wasm_free_string"] = wasmExports2["N"];
          __emscripten_timeout = wasmExports2["O"];
          _setThrew = wasmExports2["P"];
          __emscripten_stack_restore = wasmExports2["Q"];
          _emscripten_stack_get_current = wasmExports2["R"];
          memory = wasmMemory = wasmExports2["z"];
          __indirect_function_table = wasmTable = wasmExports2["D"];
        }
        var wasmImports = { c: ___assert_fail, x: __abort_js, w: __emscripten_runtime_keepalive_clear, p: __emscripten_throw_longjmp, o: __setitimer_js, q: _emscripten_resize_heap, m: _exit, u: _fd_close, r: _fd_read, s: _fd_seek, t: _fd_write, g: invoke_i, b: invoke_ii, a: invoke_iii, d: invoke_iiii, k: invoke_iiiii, l: invoke_ji, e: invoke_v, f: invoke_vi, h: invoke_vii, j: invoke_viii, i: invoke_viiii, y: invoke_viiiii, n: invoke_viiiiiiiiiiiii, v: _proc_exit };
        function invoke_iii(index, a1, a2) {
          var sp = stackSave();
          try {
            return getWasmTableEntry(index)(a1, a2);
          } catch (e) {
            stackRestore(sp);
            if (!(e instanceof EmscriptenEH)) throw e;
            _setThrew(1, 0);
          }
        }
        function invoke_ii(index, a1) {
          var sp = stackSave();
          try {
            return getWasmTableEntry(index)(a1);
          } catch (e) {
            stackRestore(sp);
            if (!(e instanceof EmscriptenEH)) throw e;
            _setThrew(1, 0);
          }
        }
        function invoke_i(index) {
          var sp = stackSave();
          try {
            return getWasmTableEntry(index)();
          } catch (e) {
            stackRestore(sp);
            if (!(e instanceof EmscriptenEH)) throw e;
            _setThrew(1, 0);
          }
        }
        function invoke_v(index) {
          var sp = stackSave();
          try {
            getWasmTableEntry(index)();
          } catch (e) {
            stackRestore(sp);
            if (!(e instanceof EmscriptenEH)) throw e;
            _setThrew(1, 0);
          }
        }
        function invoke_iiii(index, a1, a2, a3) {
          var sp = stackSave();
          try {
            return getWasmTableEntry(index)(a1, a2, a3);
          } catch (e) {
            stackRestore(sp);
            if (!(e instanceof EmscriptenEH)) throw e;
            _setThrew(1, 0);
          }
        }
        function invoke_viiii(index, a1, a2, a3, a4) {
          var sp = stackSave();
          try {
            getWasmTableEntry(index)(a1, a2, a3, a4);
          } catch (e) {
            stackRestore(sp);
            if (!(e instanceof EmscriptenEH)) throw e;
            _setThrew(1, 0);
          }
        }
        function invoke_viiiiiiiiiiiii(index, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13) {
          var sp = stackSave();
          try {
            getWasmTableEntry(index)(a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13);
          } catch (e) {
            stackRestore(sp);
            if (!(e instanceof EmscriptenEH)) throw e;
            _setThrew(1, 0);
          }
        }
        function invoke_iiiii(index, a1, a2, a3, a4) {
          var sp = stackSave();
          try {
            return getWasmTableEntry(index)(a1, a2, a3, a4);
          } catch (e) {
            stackRestore(sp);
            if (!(e instanceof EmscriptenEH)) throw e;
            _setThrew(1, 0);
          }
        }
        function invoke_viii(index, a1, a2, a3) {
          var sp = stackSave();
          try {
            getWasmTableEntry(index)(a1, a2, a3);
          } catch (e) {
            stackRestore(sp);
            if (!(e instanceof EmscriptenEH)) throw e;
            _setThrew(1, 0);
          }
        }
        function invoke_vi(index, a1) {
          var sp = stackSave();
          try {
            getWasmTableEntry(index)(a1);
          } catch (e) {
            stackRestore(sp);
            if (!(e instanceof EmscriptenEH)) throw e;
            _setThrew(1, 0);
          }
        }
        function invoke_vii(index, a1, a2) {
          var sp = stackSave();
          try {
            getWasmTableEntry(index)(a1, a2);
          } catch (e) {
            stackRestore(sp);
            if (!(e instanceof EmscriptenEH)) throw e;
            _setThrew(1, 0);
          }
        }
        function invoke_viiiii(index, a1, a2, a3, a4, a5) {
          var sp = stackSave();
          try {
            getWasmTableEntry(index)(a1, a2, a3, a4, a5);
          } catch (e) {
            stackRestore(sp);
            if (!(e instanceof EmscriptenEH)) throw e;
            _setThrew(1, 0);
          }
        }
        function invoke_ji(index, a1) {
          var sp = stackSave();
          try {
            return getWasmTableEntry(index)(a1);
          } catch (e) {
            stackRestore(sp);
            if (!(e instanceof EmscriptenEH)) throw e;
            _setThrew(1, 0);
            return 0n;
          }
        }
        async function run() {
          preRun();
          if (runDependencies) {
            await resolveRunDependencies();
          }
          var setStatus = Module["setStatus"];
          if (setStatus) {
            setStatus("Running...");
            await new Promise((resolve) => setTimeout(resolve, 1));
            setTimeout(setStatus, 1, "");
          }
          if (ABORT) return;
          initRuntime();
          Module["onRuntimeInitialized"]?.();
          postRun();
        }
        var wasmExports;
        wasmExports = await createWasm();
        await run();
        ;
        return Module;
      };
    })();
    if (typeof exports2 === "object" && typeof module2 === "object") {
      module2.exports = PgQueryModule;
      module2.exports.default = PgQueryModule;
    } else if (typeof define === "function" && define["amd"]) define([], () => PgQueryModule);
  }
});

// node_modules/libpg-query/wasm/index.cjs
var require_wasm = __commonJS({
  "node_modules/libpg-query/wasm/index.cjs"(exports2) {
    "use strict";
    var __createBinding = exports2 && exports2.__createBinding || (Object.create ? (function(o, m, k, k2) {
      if (k2 === void 0) k2 = k;
      var desc = Object.getOwnPropertyDescriptor(m, k);
      if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
        desc = { enumerable: true, get: function() {
          return m[k];
        } };
      }
      Object.defineProperty(o, k2, desc);
    }) : (function(o, m, k, k2) {
      if (k2 === void 0) k2 = k;
      o[k2] = m[k];
    }));
    var __exportStar = exports2 && exports2.__exportStar || function(m, exports3) {
      for (var p in m) if (p !== "default" && !Object.prototype.hasOwnProperty.call(exports3, p)) __createBinding(exports3, m, p);
    };
    var __importDefault = exports2 && exports2.__importDefault || function(mod) {
      return mod && mod.__esModule ? mod : { "default": mod };
    };
    Object.defineProperty(exports2, "__esModule", { value: true });
    exports2.scan = exports2.normalize = exports2.fingerprint = exports2.parsePlPgSQL = exports2.parse = exports2.SqlError = void 0;
    exports2.hasSqlDetails = hasSqlDetails;
    exports2.formatSqlError = formatSqlError;
    exports2.loadModule = loadModule;
    exports2.parseSync = parseSync;
    exports2.parsePlPgSQLSync = parsePlPgSQLSync;
    exports2.fingerprintSync = fingerprintSync;
    exports2.normalizeSync = normalizeSync;
    exports2.scanSync = scanSync;
    __exportStar(require_types2(), exports2);
    var SqlError = class extends Error {
      sqlDetails;
      constructor(message, details) {
        super(message);
        this.name = "SqlError";
        this.sqlDetails = details;
      }
    };
    exports2.SqlError = SqlError;
    function hasSqlDetails(error) {
      return error instanceof SqlError && error.sqlDetails !== void 0;
    }
    function formatSqlError(error, query, options = {}) {
      const { showPosition = true, showQuery = true, color = false, maxQueryLength } = options;
      const lines = [];
      const red = color ? "\x1B[31m" : "";
      const yellow = color ? "\x1B[33m" : "";
      const reset = color ? "\x1B[0m" : "";
      lines.push(`${red}Error: ${error.message}${reset}`);
      if (error.sqlDetails) {
        const { cursorPosition, fileName, functionName, lineNumber } = error.sqlDetails;
        if (cursorPosition !== void 0 && cursorPosition >= 0) {
          lines.push(`Position: ${cursorPosition}`);
        }
        if (fileName || functionName || lineNumber) {
          const details = [];
          if (fileName)
            details.push(`file: ${fileName}`);
          if (functionName)
            details.push(`function: ${functionName}`);
          if (lineNumber)
            details.push(`line: ${lineNumber}`);
          lines.push(`Source: ${details.join(", ")}`);
        }
        if (showQuery && showPosition && cursorPosition !== void 0 && cursorPosition >= 0) {
          let displayQuery = query;
          let adjustedPosition = cursorPosition;
          if (maxQueryLength && query.length > maxQueryLength) {
            const start = Math.max(0, cursorPosition - Math.floor(maxQueryLength / 2));
            const end = Math.min(query.length, start + maxQueryLength);
            displayQuery = (start > 0 ? "..." : "") + query.substring(start, end) + (end < query.length ? "..." : "");
            adjustedPosition = cursorPosition - start + (start > 0 ? 3 : 0);
          }
          lines.push(displayQuery);
          lines.push(" ".repeat(adjustedPosition) + `${yellow}^${reset}`);
        }
      } else if (showQuery) {
        let displayQuery = query;
        if (maxQueryLength && query.length > maxQueryLength) {
          displayQuery = query.substring(0, maxQueryLength) + "...";
        }
        lines.push(`Query: ${displayQuery}`);
      }
      return lines.join("\n");
    }
    var libpg_query_js_1 = __importDefault(require_libpg_query());
    var wasmModule;
    var stale = false;
    var loading;
    var failures = 0;
    var MAX_STALE_FAILURES = 10;
    var staleFailures = 0;
    function instantiate() {
      if (loading)
        return loading;
      const promise = (0, libpg_query_js_1.default)().then((module3) => {
        wasmModule = module3;
        stale = false;
        staleFailures = 0;
        loading = void 0;
      }, (error) => {
        loading = void 0;
        throw error;
      });
      loading = promise;
      promise.catch(() => {
      });
      return promise;
    }
    instantiate();
    function callWasm(fn) {
      const proc = globalThis.process;
      const exitCode = proc?.exitCode;
      try {
        return fn();
      } catch (error) {
        failures++;
        stale = true;
        if (++staleFailures >= MAX_STALE_FAILURES)
          wasmModule = void 0;
        instantiate();
        if (proc)
          proc.exitCode = exitCode;
        if (error instanceof Error)
          throw error;
        const reason = typeof error === "object" && error !== null ? error.message ?? error.constructor?.name : error;
        throw new Error(`libpg_query terminated (${reason}), most likely out of WASM memory; parse large inputs in smaller pieces`, { cause: error });
      }
    }
    function ensureLoaded() {
      if (!wasmModule)
        throw new Error("WASM module not initialized. Call `loadModule()` first.");
    }
    async function loadModule() {
      while (!wasmModule || stale)
        await instantiate();
    }
    function awaitInit(fn) {
      return (async (...args) => {
        while (!wasmModule || stale)
          await instantiate();
        return fn(...args);
      });
    }
    var SURROGATE = /[\uD800-\uDBFF][\uDC00-\uDFFF]|[\uD800-\uDFFF]/g;
    function stringToPtr(str) {
      ensureLoaded();
      if (typeof str !== "string") {
        throw new TypeError(`Expected a string, got ${typeof str}`);
      }
      if (str.includes("\0")) {
        throw new Error("Query must not contain a NUL (U+0000) character");
      }
      const wellFormed = str.replace(SURROGATE, (s) => s.length === 2 ? s : "\uFFFD");
      const size = wasmModule.lengthBytesUTF8(wellFormed) + 1;
      const ptr = wasmModule._malloc(size);
      if (!ptr) {
        throw new Error("Failed to allocate memory for query");
      }
      wasmModule.stringToUTF8(wellFormed, ptr, size);
      return ptr;
    }
    function ptrToString(ptr) {
      ensureLoaded();
      if (typeof ptr !== "number") {
        throw new TypeError(`Expected a number, got ${typeof ptr}`);
      }
      return wasmModule.UTF8ToString(ptr);
    }
    exports2.parse = awaitInit(async (query) => {
      if (query === null || query === void 0) {
        throw new Error("Query cannot be null or undefined");
      }
      if (query === "") {
        throw new Error("Query cannot be empty");
      }
      const queryPtr = stringToPtr(query);
      const failuresBefore = failures;
      let resultPtr = 0;
      try {
        resultPtr = callWasm(() => wasmModule._wasm_parse_query_raw(queryPtr));
        if (!resultPtr) {
          throw new Error("Failed to parse query: memory allocation failed");
        }
        const parseTreePtr = wasmModule.getValue(resultPtr, "i32");
        const stderrBufferPtr = wasmModule.getValue(resultPtr + 4, "i32");
        const errorPtr = wasmModule.getValue(resultPtr + 8, "i32");
        if (errorPtr) {
          const messagePtr = wasmModule.getValue(errorPtr, "i32");
          const funcnamePtr = wasmModule.getValue(errorPtr + 4, "i32");
          const filenamePtr = wasmModule.getValue(errorPtr + 8, "i32");
          const lineno = wasmModule.getValue(errorPtr + 12, "i32");
          const cursorpos = wasmModule.getValue(errorPtr + 16, "i32");
          const message = messagePtr ? wasmModule.UTF8ToString(messagePtr) : "Unknown error";
          const funcname = funcnamePtr ? wasmModule.UTF8ToString(funcnamePtr) : void 0;
          const filename = filenamePtr ? wasmModule.UTF8ToString(filenamePtr) : void 0;
          throw new SqlError(message, {
            message,
            cursorPosition: cursorpos > 0 ? cursorpos - 1 : 0,
            // Convert to 0-based
            fileName: filename,
            functionName: funcname,
            lineNumber: lineno > 0 ? lineno : void 0
          });
        }
        if (!parseTreePtr) {
          throw new Error("libpg_query returned no parse tree: out of WASM memory (heap limit is WASM_MAXIMUM_MEMORY, 1 GiB); parse large inputs in smaller pieces");
        }
        const parseTreeStr = wasmModule.UTF8ToString(parseTreePtr);
        return JSON.parse(parseTreeStr);
      } finally {
        if (failures === failuresBefore) {
          wasmModule._free(queryPtr);
          if (resultPtr) {
            wasmModule._wasm_free_parse_result(resultPtr);
          }
        }
      }
    });
    exports2.parsePlPgSQL = awaitInit(async (query) => {
      const queryPtr = stringToPtr(query);
      const failuresBefore = failures;
      let resultPtr = 0;
      try {
        resultPtr = callWasm(() => wasmModule._wasm_parse_plpgsql(queryPtr));
        const resultStr = ptrToString(resultPtr);
        if (!resultStr.startsWith("{")) {
          throw new Error(resultStr);
        }
        return JSON.parse(resultStr);
      } finally {
        if (failures === failuresBefore) {
          wasmModule._free(queryPtr);
          if (resultPtr) {
            wasmModule._wasm_free_string(resultPtr);
          }
        }
      }
    });
    exports2.fingerprint = awaitInit(async (query) => {
      const queryPtr = stringToPtr(query);
      const failuresBefore = failures;
      let resultPtr = 0;
      try {
        resultPtr = callWasm(() => wasmModule._wasm_fingerprint(queryPtr));
        const resultStr = ptrToString(resultPtr);
        if (resultStr.startsWith("syntax error") || resultStr.startsWith("deparse error") || resultStr.startsWith("ERROR")) {
          throw new Error(resultStr);
        }
        return resultStr;
      } finally {
        if (failures === failuresBefore) {
          wasmModule._free(queryPtr);
          if (resultPtr) {
            wasmModule._wasm_free_string(resultPtr);
          }
        }
      }
    });
    exports2.normalize = awaitInit(async (query) => {
      const queryPtr = stringToPtr(query);
      const failuresBefore = failures;
      let resultPtr = 0;
      try {
        resultPtr = callWasm(() => wasmModule._wasm_normalize_query(queryPtr));
        const resultStr = ptrToString(resultPtr);
        if (resultStr.startsWith("syntax error") || resultStr.startsWith("deparse error") || resultStr.startsWith("ERROR")) {
          throw new Error(resultStr);
        }
        return resultStr;
      } finally {
        if (failures === failuresBefore) {
          wasmModule._free(queryPtr);
          if (resultPtr) {
            wasmModule._wasm_free_string(resultPtr);
          }
        }
      }
    });
    function parseSync(query) {
      if (!wasmModule) {
        throw new Error("WASM module not initialized. Call loadModule() first.");
      }
      if (query === null || query === void 0) {
        throw new Error("Query cannot be null or undefined");
      }
      if (query === "") {
        throw new Error("Query cannot be empty");
      }
      const queryPtr = stringToPtr(query);
      const failuresBefore = failures;
      let resultPtr = 0;
      try {
        resultPtr = callWasm(() => wasmModule._wasm_parse_query_raw(queryPtr));
        if (!resultPtr) {
          throw new Error("Failed to parse query: memory allocation failed");
        }
        const parseTreePtr = wasmModule.getValue(resultPtr, "i32");
        const stderrBufferPtr = wasmModule.getValue(resultPtr + 4, "i32");
        const errorPtr = wasmModule.getValue(resultPtr + 8, "i32");
        if (errorPtr) {
          const messagePtr = wasmModule.getValue(errorPtr, "i32");
          const funcnamePtr = wasmModule.getValue(errorPtr + 4, "i32");
          const filenamePtr = wasmModule.getValue(errorPtr + 8, "i32");
          const lineno = wasmModule.getValue(errorPtr + 12, "i32");
          const cursorpos = wasmModule.getValue(errorPtr + 16, "i32");
          const message = messagePtr ? wasmModule.UTF8ToString(messagePtr) : "Unknown error";
          const funcname = funcnamePtr ? wasmModule.UTF8ToString(funcnamePtr) : void 0;
          const filename = filenamePtr ? wasmModule.UTF8ToString(filenamePtr) : void 0;
          throw new SqlError(message, {
            message,
            cursorPosition: cursorpos > 0 ? cursorpos - 1 : 0,
            // Convert to 0-based
            fileName: filename,
            functionName: funcname,
            lineNumber: lineno > 0 ? lineno : void 0
          });
        }
        if (!parseTreePtr) {
          throw new Error("libpg_query returned no parse tree: out of WASM memory (heap limit is WASM_MAXIMUM_MEMORY, 1 GiB); parse large inputs in smaller pieces");
        }
        const parseTreeStr = wasmModule.UTF8ToString(parseTreePtr);
        return JSON.parse(parseTreeStr);
      } finally {
        if (failures === failuresBefore) {
          wasmModule._free(queryPtr);
          if (resultPtr) {
            wasmModule._wasm_free_parse_result(resultPtr);
          }
        }
      }
    }
    function parsePlPgSQLSync(query) {
      if (!wasmModule) {
        throw new Error("WASM module not initialized. Call loadModule() first.");
      }
      const queryPtr = stringToPtr(query);
      const failuresBefore = failures;
      let resultPtr = 0;
      try {
        resultPtr = callWasm(() => wasmModule._wasm_parse_plpgsql(queryPtr));
        const resultStr = ptrToString(resultPtr);
        if (!resultStr.startsWith("{")) {
          throw new Error(resultStr);
        }
        return JSON.parse(resultStr);
      } finally {
        if (failures === failuresBefore) {
          wasmModule._free(queryPtr);
          if (resultPtr) {
            wasmModule._wasm_free_string(resultPtr);
          }
        }
      }
    }
    function fingerprintSync(query) {
      if (!wasmModule) {
        throw new Error("WASM module not initialized. Call loadModule() first.");
      }
      const queryPtr = stringToPtr(query);
      const failuresBefore = failures;
      let resultPtr = 0;
      try {
        resultPtr = callWasm(() => wasmModule._wasm_fingerprint(queryPtr));
        const resultStr = ptrToString(resultPtr);
        if (resultStr.startsWith("syntax error") || resultStr.startsWith("deparse error") || resultStr.startsWith("ERROR")) {
          throw new Error(resultStr);
        }
        return resultStr;
      } finally {
        if (failures === failuresBefore) {
          wasmModule._free(queryPtr);
          if (resultPtr) {
            wasmModule._wasm_free_string(resultPtr);
          }
        }
      }
    }
    function normalizeSync(query) {
      if (!wasmModule) {
        throw new Error("WASM module not initialized. Call loadModule() first.");
      }
      const queryPtr = stringToPtr(query);
      const failuresBefore = failures;
      let resultPtr = 0;
      try {
        resultPtr = callWasm(() => wasmModule._wasm_normalize_query(queryPtr));
        const resultStr = ptrToString(resultPtr);
        if (resultStr.startsWith("syntax error") || resultStr.startsWith("deparse error") || resultStr.startsWith("ERROR")) {
          throw new Error(resultStr);
        }
        return resultStr;
      } finally {
        if (failures === failuresBefore) {
          wasmModule._free(queryPtr);
          if (resultPtr) {
            wasmModule._wasm_free_string(resultPtr);
          }
        }
      }
    }
    exports2.scan = awaitInit(async (query) => {
      const queryPtr = stringToPtr(query);
      const failuresBefore = failures;
      let resultPtr = 0;
      try {
        resultPtr = callWasm(() => wasmModule._wasm_scan(queryPtr));
        const resultStr = ptrToString(resultPtr);
        if (resultStr.startsWith("syntax error") || resultStr.startsWith("deparse error") || resultStr.startsWith("ERROR")) {
          throw new Error(resultStr);
        }
        return JSON.parse(resultStr);
      } finally {
        if (failures === failuresBefore) {
          wasmModule._free(queryPtr);
          if (resultPtr) {
            wasmModule._wasm_free_string(resultPtr);
          }
        }
      }
    });
    function scanSync(query) {
      if (!wasmModule) {
        throw new Error("WASM module not initialized. Call loadModule() first.");
      }
      const queryPtr = stringToPtr(query);
      const failuresBefore = failures;
      let resultPtr = 0;
      try {
        resultPtr = callWasm(() => wasmModule._wasm_scan(queryPtr));
        const resultStr = ptrToString(resultPtr);
        if (resultStr.startsWith("syntax error") || resultStr.startsWith("deparse error") || resultStr.startsWith("ERROR")) {
          throw new Error(resultStr);
        }
        return JSON.parse(resultStr);
      } finally {
        if (failures === failuresBefore) {
          wasmModule._free(queryPtr);
          if (resultPtr) {
            wasmModule._wasm_free_string(resultPtr);
          }
        }
      }
    }
  }
});

// build/src/runtime/observers/pg-parser-worker.js
var pg_parser_worker_exports = {};
__export(pg_parser_worker_exports, {
  PG_PARSER_WORKER_PROTOCOL_REVISION: () => PG_PARSER_WORKER_PROTOCOL_REVISION
});
module.exports = __toCommonJS(pg_parser_worker_exports);
var import_node_crypto2 = require("node:crypto");
var import_node_fs = require("node:fs");
var import_node_path = require("node:path");

// build/src/runtime/observers/pg-parser-helper.js
var import_node_crypto = require("node:crypto");
var import_node_util2 = require("node:util");

// build/src/json-snapshot.js
var import_node_util = require("node:util");
var JSON_MAX_INPUT_BYTES = 1024 * 1024;
var JSON_MAX_INPUT_NODES = 2e4;
var JSON_MAX_DEPTH = 40;
function fail() {
  throw new TypeError("invalid_bounded_json");
}
function snapshotJsonData(input2, invalid = fail, limit = fail) {
  let nodes = 0, bytes = 0;
  const active = /* @__PURE__ */ new Set();
  const count = (value) => {
    bytes += Buffer.byteLength(value, "utf8");
    if (bytes > JSON_MAX_INPUT_BYTES)
      limit();
  };
  const string = (value) => {
    if (value.length > JSON_MAX_INPUT_BYTES)
      limit();
    count(JSON.stringify(value));
  };
  const copy = (value, depth) => {
    if (++nodes > JSON_MAX_INPUT_NODES || depth > JSON_MAX_DEPTH)
      limit();
    if (value === null || typeof value === "boolean") {
      count(String(value));
      return value;
    }
    if (typeof value === "string") {
      string(value);
      return value;
    }
    if (typeof value === "number") {
      if (!Number.isFinite(value))
        invalid();
      count(String(value));
      return value;
    }
    if (typeof value !== "object" || import_node_util.types.isProxy(value) || active.has(value))
      invalid();
    const array2 = Array.isArray(value);
    const prototype = Object.getPrototypeOf(value);
    if (array2 ? prototype !== Array.prototype : prototype !== Object.prototype && prototype !== null)
      invalid();
    if (Object.getOwnPropertySymbols(value).length !== 0)
      invalid();
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const names = Object.keys(descriptors);
    if (names.length > JSON_MAX_INPUT_NODES - nodes)
      limit();
    active.add(value);
    count("{}");
    if (array2) {
      if (value.length > JSON_MAX_INPUT_NODES - nodes || names.length !== value.length + 1)
        invalid();
      const result2 = [];
      for (let i = 0; i < value.length; i++) {
        const descriptor = descriptors[String(i)];
        if (!descriptor || !descriptor.enumerable || !("value" in descriptor))
          invalid();
        if (i > 0)
          count(",");
        result2.push(copy(descriptor.value, depth + 1));
      }
      active.delete(value);
      return result2;
    }
    const result = /* @__PURE__ */ Object.create(null);
    for (let i = 0; i < names.length; i++) {
      const name = names[i];
      const descriptor = descriptors[name];
      if (!descriptor.enumerable || !("value" in descriptor))
        invalid();
      if (i > 0)
        count(",");
      string(name);
      count(":");
      result[name] = copy(descriptor.value, depth + 1);
    }
    active.delete(value);
    return result;
  };
  return copy(input2, 0);
}

// build/src/runtime/observers/pg-parser-helper.js
var PG_PARSER_PROTOCOL_REVISION = "wakeio.pg-parser/v1";
var PG_PARSER_LIMITS = Object.freeze({ sqlBytes: 32768, stdinBytes: 65536, stdoutBytes: 1048576 });
var PG_PARSER_PIN = Object.freeze({
  version: "18.2.1",
  pgMajor: 18,
  lockSha256: "adc4e4026559ed0e5229acb4cb5354a82437420efdb58056d4a9d73969e37493",
  wasmSha256: "355c489d8b0bf2bac28b48408f656e818852d7000e1e66a67503ad2bc7cc6062"
});
var PgParserProtocolError = class extends Error {
  reason;
  constructor(reason) {
    super(reason);
    this.reason = reason;
  }
};
var sha = (value) => (0, import_node_crypto.createHash)("sha256").update(value).digest("hex");
function fail2(reason = "unsupported_shape") {
  throw new PgParserProtocolError(reason);
}
function check(value, reason) {
  if (!value)
    fail2(reason);
}
function record(value) {
  check(value && typeof value === "object" && !Array.isArray(value));
  return value;
}
function keys(raw, required, optional = "") {
  const value = record(raw), names = required ? required.split(" ") : [], extras = optional ? optional.split(" ") : [];
  check(names.every((k) => Object.hasOwn(value, k)) && Object.keys(value).every((k) => names.includes(k) || extras.includes(k)));
  return value;
}
function integer(raw, min = 0, max = PG_PARSER_LIMITS.sqlBytes) {
  check(Number.isSafeInteger(raw) && raw >= min && raw <= max);
}
function hash(raw) {
  check(typeof raw === "string" && /^[a-f0-9]{64}$/.test(raw));
}
function array(raw, max = 2e4) {
  check(Array.isArray(raw) && raw.length <= max);
}
var same = (a, b) => a[0] === b[0] && a[1] === b[1];
var overlap = (a, b) => a[0] < b[1] && b[0] < a[1];
var inside = (a, b) => a[0] <= b[0] && b[1] <= a[1];
function span(raw, size) {
  array(raw, 2);
  check(raw.length === 2);
  integer(raw[0]);
  integer(raw[1]);
  check(raw[0] < raw[1] && raw[1] <= size);
}
function pinned(raw) {
  const p = keys(raw, "version pgMajor lockSha256 wasmSha256");
  check(Object.entries(PG_PARSER_PIN).every(([k, v]) => p[k] === v), "pin_mismatch");
}
function assets(raw) {
  const a = keys(raw, "workerSha256 manifestSha256");
  hash(a.workerSha256);
  hash(a.manifestSha256);
  return { workerSha256: a.workerSha256, manifestSha256: a.manifestSha256 };
}
function byteCopy(raw, max) {
  check(!import_node_util2.types.isProxy(raw) && import_node_util2.types.isUint8Array(raw), "encoding");
  const proto = Object.getPrototypeOf(Uint8Array.prototype);
  const field = (name) => Object.getOwnPropertyDescriptor(proto, name).get.call(raw);
  const size = field("byteLength"), offset = field("byteOffset"), buffer = field("buffer");
  check(size <= max, "limit");
  check(import_node_util2.types.isArrayBuffer(buffer), "encoding");
  return Buffer.from(new Uint8Array(buffer, offset, size));
}
function json(raw, max) {
  const bytes = byteCopy(raw, max);
  let value;
  try {
    value = JSON.parse(new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes));
  } catch {
    return fail2("encoding");
  }
  return snapshotJsonData(value, () => fail2("invalid_request"), () => fail2("limit"));
}
function boundary(bytes, offset) {
  return offset === bytes.length || (bytes[offset] & 192) !== 128;
}
function validatePgParserRequest(raw) {
  const data = snapshotJsonData(raw, () => fail2("invalid_request"), () => fail2("limit"));
  const r = keys(data, "protocolRevision requestId pin assets sql insertions");
  check(r.protocolRevision === PG_PARSER_PROTOCOL_REVISION, "pin_mismatch");
  hash(r.requestId);
  pinned(r.pin);
  const a = assets(r.assets);
  check(typeof r.sql === "string" && r.sql.length > 0, "invalid_request");
  check(!r.sql.includes("\0"), "encoding");
  for (const ch of r.sql)
    check(!(ch.codePointAt(0) >= 55296 && ch.codePointAt(0) <= 57343), "encoding");
  const bytes = Buffer.from(r.sql);
  check(bytes.length <= PG_PARSER_LIMITS.sqlBytes, "limit");
  array(r.insertions, 128);
  let end = 0;
  const insertions = r.insertions.map((raw2) => {
    const i = keys(raw2, "payloadHash span");
    hash(i.payloadHash);
    span(i.span, bytes.length);
    check(i.span[0] >= end && boundary(bytes, i.span[0]) && boundary(bytes, i.span[1]));
    end = i.span[1];
    return { payloadHash: i.payloadHash, span: [...i.span] };
  });
  const result = {
    protocolRevision: PG_PARSER_PROTOCOL_REVISION,
    requestId: r.requestId,
    pin: { ...PG_PARSER_PIN },
    assets: a,
    sql: r.sql,
    insertions
  };
  check(Buffer.byteLength(JSON.stringify(result)) <= PG_PARSER_LIMITS.stdinBytes, "limit");
  return result;
}
function decodePgParserRequest(bytes) {
  return validatePgParserRequest(json(bytes, PG_PARSER_LIMITS.stdinBytes));
}
function pgParserBinding(request) {
  const r = validatePgParserRequest(request);
  return {
    requestId: r.requestId,
    assets: r.assets,
    statementSha256: sha(r.sql),
    statementBytes: Buffer.byteLength(r.sql),
    insertions: r.insertions
  };
}
var reasons = [
  "none",
  "invalid_request",
  "encoding",
  "limit",
  "pin_mismatch",
  "asset_mismatch",
  "parser_unavailable",
  "parser_failure",
  "unsupported_shape",
  "invalid_projection"
];
function pgParserFailure(reason, request) {
  const b = request ? pgParserBinding(request) : void 0;
  return {
    protocolRevision: PG_PARSER_PROTOCOL_REVISION,
    requestId: b?.requestId ?? null,
    pin: { ...PG_PARSER_PIN },
    assets: b?.assets ?? null,
    statementSha256: b?.statementSha256 ?? null,
    statementBytes: b?.statementBytes ?? null,
    status: "unknown",
    reason,
    projection: null
  };
}
function context(tokens, hashes, insertions) {
  return sha(JSON.stringify(tokens.flatMap((t, index) => insertions.some((i) => overlap(i.span, t.span)) ? [] : [[t.kind, t.role, hashes[index]]])));
}
function projection(raw, binding) {
  const p = keys(raw, "ast tokens tokenHashes insertions controlContextHash outsidePayloadTokenHash");
  array(p.ast);
  array(p.tokens);
  array(p.tokenHashes);
  array(p.insertions, 128);
  const ast = p.ast, tokens = p.tokens, hashes = p.tokenHashes;
  const nodes = new Map(ast.map((n) => [n.id, n]));
  check(nodes.size === ast.length && ast.length > 0);
  const kinds = ["SelectStmt", "ColumnRef", "StringConst", "ParamRef", "A_Expr", "BoolExpr"];
  for (const n of ast) {
    keys(n, "id kind parent span");
    integer(n.id, 0, 19999);
    check(kinds.includes(n.kind));
    span(n.span, binding.statementBytes);
    if (n.parent !== null)
      integer(n.parent, 0, 19999);
    let parent = n.parent;
    const seen = /* @__PURE__ */ new Set([n.id]);
    while (parent !== null) {
      const node = nodes.get(parent);
      check(node && !seen.has(parent) && seen.size < 40 && inside(node.span, n.span));
      seen.add(parent);
      parent = node.parent;
    }
  }
  check(ast.filter((n) => n.parent === null).length === 1 && ast[0].parent === null && ast[0].kind === "SelectStmt" && same(ast[0].span, [0, binding.statementBytes]));
  check(tokens.length === hashes.length);
  let end = 0;
  for (const [index, t] of tokens.entries()) {
    keys(t, "kind span role");
    span(t.span, binding.statementBytes);
    hash(hashes[index]);
    check(t.span[0] >= end);
    end = t.span[1];
    check(/^(IDENT|SCONST|CONST|PARAM|OR|AND|EQUALS|COMMENT|TOKEN_[0-9]{1,5})$/.test(t.kind));
    const role = t.kind === "IDENT" ? "identifier" : ["SCONST", "CONST"].includes(t.kind) ? "literal" : t.kind === "PARAM" ? "parameter" : t.kind === "COMMENT" ? "comment" : t.kind === "EQUALS" ? "operator" : "syntax";
    check(t.role === role);
  }
  check(p.insertions.length === binding.insertions.length);
  for (const [index, rawInsertion] of p.insertions.entries()) {
    const i = keys(rawInsertion, "payloadHash span tokenIndexes nodeIds"), expected = binding.insertions[index];
    hash(i.payloadHash);
    span(i.span, binding.statementBytes);
    check(i.payloadHash === expected.payloadHash && same(i.span, expected.span));
    array(i.tokenIndexes);
    array(i.nodeIds);
    const expectedTokens = tokens.flatMap((t, index2) => overlap(t.span, expected.span) ? [index2] : []);
    const expectedNodes = ast.flatMap((n) => n.id !== 0 && overlap(n.span, expected.span) ? [n.id] : []);
    check(JSON.stringify(i.tokenIndexes) === JSON.stringify(expectedTokens) && JSON.stringify(i.nodeIds) === JSON.stringify(expectedNodes));
  }
  const normalized = context(tokens, hashes, binding.insertions);
  check(p.controlContextHash === normalized && p.outsidePayloadTokenHash === normalized);
  return {
    ast,
    tokens,
    tokenHashes: hashes,
    insertions: p.insertions,
    controlContextHash: normalized,
    outsidePayloadTokenHash: normalized
  };
}
function expectedBinding(raw) {
  const b = keys(snapshotJsonData(raw), "requestId assets statementSha256 statementBytes insertions");
  hash(b.requestId);
  hash(b.statementSha256);
  integer(b.statementBytes, 1);
  array(b.insertions, 128);
  const a = assets(b.assets);
  let end = 0;
  for (const item of b.insertions) {
    const i = keys(item, "payloadHash span");
    hash(i.payloadHash);
    span(i.span, b.statementBytes);
    check(i.span[0] >= end);
    end = i.span[1];
  }
  return {
    requestId: b.requestId,
    assets: a,
    statementSha256: b.statementSha256,
    statementBytes: b.statementBytes,
    insertions: b.insertions
  };
}
function validatePgParserReply(raw, expected) {
  const r = keys(snapshotJsonData(raw, () => fail2("invalid_projection"), () => fail2("limit")), "protocolRevision requestId pin assets status reason statementSha256 statementBytes projection");
  check(r.protocolRevision === PG_PARSER_PROTOCOL_REVISION, "pin_mismatch");
  pinned(r.pin);
  check(["ok", "unknown", "error"].includes(r.status) && reasons.includes(r.reason));
  if (!expected) {
    check(r.status !== "ok" && r.reason !== "none" && r.requestId === null && r.assets === null && r.statementSha256 === null && r.statementBytes === null && r.projection === null, "invalid_projection");
  } else {
    expected = expectedBinding(expected);
    const a = assets(r.assets);
    check(r.requestId === expected.requestId && a.workerSha256 === expected.assets.workerSha256 && a.manifestSha256 === expected.assets.manifestSha256 && r.statementSha256 === expected.statementSha256 && r.statementBytes === expected.statementBytes, "asset_mismatch");
    if (r.status === "ok") {
      check(r.reason === "none");
      r.projection = projection(r.projection, expected);
    } else
      check(r.reason !== "none" && r.projection === null, "invalid_projection");
  }
  return r;
}
function encodePgParserReply(raw, expected) {
  const data = validatePgParserReply(raw, expected), bytes = Buffer.from(JSON.stringify(data) + "\n");
  check(bytes.length <= PG_PARSER_LIMITS.stdoutBytes, "limit");
  return bytes;
}
function scanFacts(raw, sql) {
  const s = keys(snapshotJsonData(raw), "version tokens");
  integer(s.version, 18e4, 189999);
  array(s.tokens);
  const bytes = Buffer.from(sql), tokens = [], hashes = [];
  let end = 0;
  for (const item of s.tokens) {
    keys(item, "start end text tokenType tokenName keywordKind keywordName");
    const t = item;
    span([t.start, t.end], bytes.length);
    integer(t.tokenType, 0, 99999);
    integer(t.keywordKind, 0, 4);
    check(t.start >= end && boundary(bytes, t.start) && boundary(bytes, t.end));
    end = t.end;
    check(typeof t.text === "string" && t.text === bytes.subarray(t.start, t.end).toString("utf8"));
    let kind = "TOKEN_" + t.tokenType, role = "syntax";
    if (["IDENT", "UIDENT"].includes(t.tokenName)) {
      kind = "IDENT";
      role = "identifier";
    } else if (["SCONST", "USCONST"].includes(t.tokenName)) {
      kind = "SCONST";
      role = "literal";
    } else if (["ICONST", "FCONST", "BCONST", "XCONST"].includes(t.tokenName)) {
      kind = "CONST";
      role = "literal";
    } else if (t.tokenName === "PARAM") {
      kind = "PARAM";
      role = "parameter";
    } else if (["SQL_COMMENT", "C_COMMENT"].includes(t.tokenName)) {
      kind = "COMMENT";
      role = "comment";
    } else if (t.tokenType === 61 && t.text === "=") {
      kind = "EQUALS";
      role = "operator";
    } else if (t.keywordKind === 4 && ["OR", "AND"].includes(t.text.toUpperCase()))
      kind = t.text.toUpperCase();
    tokens.push({ kind, role, span: [t.start, t.end] });
    hashes.push(sha(bytes.subarray(t.start, t.end)));
  }
  return { version: s.version, tokens, hashes };
}
function strings(raw) {
  array(raw, 8);
  check(raw.length > 0);
  for (const item of raw) {
    const value = keys(keys(item, "String").String, "sval");
    check(typeof value.sval === "string");
  }
}
function select(raw, size, version) {
  const root = keys(raw, "version stmts");
  integer(root.version, 18e4, 189999);
  array(root.stmts, 1);
  check(root.version === version);
  check(root.stmts.length === 1);
  const stmt = keys(root.stmts[0], "stmt", "stmt_location stmt_len");
  check(stmt.stmt_location === void 0 || stmt.stmt_location === 0);
  if (stmt.stmt_len !== void 0)
    integer(stmt.stmt_len, 0, size);
  const s = keys(keys(stmt.stmt, "SelectStmt").SelectStmt, "targetList fromClause whereClause", "op limitOption");
  check(s.op === void 0 || s.op === "SETOP_NONE");
  check(s.limitOption === void 0 || s.limitOption === "LIMIT_OPTION_DEFAULT");
  array(s.targetList, 32);
  array(s.fromClause, 1);
  check(s.targetList.length > 0 && s.fromClause.length === 1);
  for (const target of s.targetList) {
    const t = keys(keys(target, "ResTarget").ResTarget, "val", "location name");
    const column = keys(keys(t.val, "ColumnRef").ColumnRef, "fields location");
    strings(column.fields);
  }
  const table = keys(keys(s.fromClause[0], "RangeVar").RangeVar, "relname", "catalogname schemaname inh relpersistence location");
  check(typeof table.relname === "string");
  for (const k of ["catalogname", "schemaname", "relpersistence"])
    check(table[k] === void 0 || typeof table[k] === "string");
  return s;
}
function astFacts(raw, tokens, size, version) {
  const s = select(snapshotJsonData(raw), size, version);
  const ast = [{ id: 0, kind: "SelectStmt", parent: null, span: [0, size] }];
  const locate = (value, kind) => {
    integer(value);
    const token = tokens.find((t) => t.span[0] === value && t.kind === kind);
    check(token);
    return token.span;
  };
  const visit = (rawNode, parent, depth) => {
    check(depth <= 40 && ast.length < 2e4);
    const wrapper = record(rawNode), names = Object.keys(wrapper);
    check(names.length === 1);
    const kind = names[0], node = record(wrapper[kind]), id = ast.length;
    const out = { id, kind, parent, span: [0, size] };
    ast.push(out);
    if (kind === "ColumnRef") {
      keys(node, "fields location");
      strings(node.fields);
      check(node.fields.length === 1);
      out.span = locate(node.location, "IDENT");
    } else if (kind === "ParamRef") {
      keys(node, "number location");
      integer(node.number, 1);
      out.span = locate(node.location, "PARAM");
    } else if (kind === "A_Const") {
      keys(node, "sval location");
      check(typeof keys(node.sval, "sval").sval === "string");
      out.kind = "StringConst";
      out.span = locate(node.location, "SCONST");
    } else if (kind === "A_Expr") {
      keys(node, "kind name lexpr rexpr location");
      check(node.kind === "AEXPR_OP");
      strings(node.name);
      const operator = node.name;
      check(operator.length === 1 && operator[0].String.sval === "=");
      const token = locate(node.location, "EQUALS"), left = ast[visit(node.lexpr, id, depth + 1)].span;
      const right = ast[visit(node.rexpr, id, depth + 1)].span;
      check(left[1] <= token[0] && token[1] <= right[0]);
      out.span = [left[0], right[1]];
    } else if (kind === "BoolExpr") {
      keys(node, "boolop args location");
      check(["OR_EXPR", "AND_EXPR"].includes(node.boolop));
      array(node.args, 128);
      check(node.args.length >= 2);
      const token = locate(node.location, node.boolop === "OR_EXPR" ? "OR" : "AND");
      const children = node.args.map((child) => ast[visit(child, id, depth + 1)].span);
      check(children.every((child, i) => i === 0 || children[i - 1][1] <= child[0]) && children.some((c) => c[1] <= token[0]) && children.some((c) => c[0] >= token[1]));
      out.span = [children[0][0], children.at(-1)[1]];
    } else
      fail2("unsupported_shape");
    return id;
  };
  visit(s.whereClause, 0, 1);
  return ast;
}
function projectPgParserFacts(request, parsed, scanned) {
  const r = validatePgParserRequest(request), binding = pgParserBinding(r);
  try {
    const { version, tokens, hashes } = scanFacts(scanned, r.sql);
    const ast = astFacts(parsed, tokens, binding.statementBytes, version);
    const insertions = r.insertions.map((i) => ({
      ...i,
      tokenIndexes: tokens.flatMap((t, index) => overlap(t.span, i.span) ? [index] : []),
      nodeIds: ast.flatMap((n) => n.id !== 0 && overlap(n.span, i.span) ? [n.id] : [])
    }));
    const digest = context(tokens, hashes, r.insertions);
    return validatePgParserReply({
      protocolRevision: PG_PARSER_PROTOCOL_REVISION,
      requestId: r.requestId,
      pin: r.pin,
      assets: r.assets,
      status: "ok",
      reason: "none",
      statementSha256: binding.statementSha256,
      statementBytes: binding.statementBytes,
      projection: {
        ast,
        tokens,
        tokenHashes: hashes,
        insertions,
        controlContextHash: digest,
        outsidePayloadTokenHash: digest
      }
    }, binding);
  } catch {
    return pgParserFailure("unsupported_shape", r);
  }
}

// build/src/runtime/observers/pg-parser-worker.js
var PG_PARSER_WORKER_PROTOCOL_REVISION = "wakeio.pg-parser/v1";
var output = process.stdout.write.bind(process.stdout);
function silenceDiagnostics() {
  process.stdout.write = (() => true);
  process.stderr.write = (() => true);
  for (const key of ["log", "info", "warn", "error", "debug"])
    console[key] = () => void 0;
}
function assetHash(path, max) {
  const before = (0, import_node_fs.lstatSync)(path);
  if (!before.isFile() || before.isSymbolicLink() || before.size > max)
    throw new PgParserProtocolError("asset_mismatch");
  const bytes = (0, import_node_fs.readFileSync)(path), after = (0, import_node_fs.lstatSync)(path);
  if (bytes.length !== before.size || after.ino !== before.ino || after.dev !== before.dev || after.mtimeMs !== before.mtimeMs || after.ctimeMs !== before.ctimeMs)
    throw new PgParserProtocolError("asset_mismatch");
  return (0, import_node_crypto2.createHash)("sha256").update(bytes).digest("hex");
}
function verifyAssets(request) {
  if (typeof __dirname !== "string" || typeof __filename !== "string" || __filename !== (0, import_node_path.join)(__dirname, "pg-parser-worker.cjs") || PG_PARSER_WORKER_PROTOCOL_REVISION !== PG_PARSER_PROTOCOL_REVISION)
    throw new PgParserProtocolError("parser_unavailable");
  if (assetHash(__filename, 16 * 1024 * 1024) !== request.assets.workerSha256 || assetHash((0, import_node_path.join)(__dirname, "manifest.json"), 65536) !== request.assets.manifestSha256 || assetHash((0, import_node_path.join)(__dirname, "libpg-query.wasm"), 16 * 1024 * 1024) !== PG_PARSER_PIN.wasmSha256)
    throw new PgParserProtocolError("asset_mismatch");
}
async function input() {
  const chunks = [];
  let bytes = 0;
  for await (const chunk of process.stdin) {
    bytes += chunk.length;
    if (bytes > PG_PARSER_LIMITS.stdinBytes) {
      process.stdin.destroy();
      throw new PgParserProtocolError("limit");
    }
    chunks.push(Buffer.from(chunk));
  }
  return Buffer.concat(chunks, bytes);
}
function emit(reply, request) {
  let bytes, ok = false;
  try {
    bytes = encodePgParserReply(reply, request ? pgParserBinding(request) : void 0);
    ok = reply.status === "ok";
  } catch {
    bytes = encodePgParserReply(pgParserFailure("invalid_projection"));
  }
  output(bytes, () => process.exit(ok ? 0 : 2));
}
async function main() {
  silenceDiagnostics();
  let request;
  try {
    request = decodePgParserRequest(await input());
    verifyAssets(request);
    const parser = await Promise.resolve().then(() => __toESM(require_wasm(), 1));
    await parser.loadModule();
    const parsed = parser.parseSync(request.sql), scanned = parser.scanSync(request.sql);
    emit(projectPgParserFacts(request, parsed, scanned), request);
  } catch (error) {
    const reason = error instanceof PgParserProtocolError ? error.reason : "parser_failure";
    emit(pgParserFailure(reason === "none" ? "parser_failure" : reason, request), request);
  }
}
void main();
// Annotate the CommonJS export names for ESM import in node:
0 && (module.exports = {
  PG_PARSER_WORKER_PROTOCOL_REVISION
});
