// frida_sign_capture.js — dump Tuya BLE/cloud native sign calls from the live app.
//
// Usage (rooted phone or rooted AVD with frida-server running):
//   frida -U -f com.yongfengshun -l frida_sign_capture.js --no-pause
// Then open the app (it will log in / talk BLE); the script prints every
// doCommandNative / getEncryptoKey / encryptPostData call with in/out bytes.
//
// Why offsets: libthing_security.so registers its JNI methods dynamically
// (no Java_ symbols), so we hook the native implementations by offset from
// the module base.  Offsets are from the static analysis of
// YouFs-A_1.0.3_APKPure.apk (arm64-v8a), see docs/cloud_api.md.

const OFFSETS = {
    doCommandNative: 0x53a8,   // (env, cls, cmd, data, data2, flag)
    getEncryptoKey:  0x6970,   // (env, cls, requestId, ecode) -> byte[16]
    encryptPostData: 0x6800,
    decryptResponseData: 0x7428,
};

function bytesToStr(p) {
    if (p.isNull()) return "(null)";
    return Memory.readCString(p);
}

function dumpBytes(label, env, jbyteArray) {
    if (jbyteArray.isNull()) { console.log(label, "(null)"); return; }
    const env2 = Java.vm.tryGetEnv();
    const len = env2.getArrayLength(jbyteArray);
    const ptr = env2.getByteArrayElements(jbyteArray, null);
    const bytes = Memory.readByteArray(ptr, len);
    console.log(label, "len=" + len, hexdump(ptr, { length: Math.min(len, 128) }));
}

function hookModule() {
    const mod = Process.findModuleByName("libthing_security.so");
    if (!mod) return false;
    const base = mod.base;
    console.log("[*] libthing_security.so @", base);

    Interceptor.attach(base.add(OFFSETS.doCommandNative), {
        onEnter(args) {
            this.cmd = args[2].toInt32();
            console.log("=== doCommandNative cmd=" + this.cmd);
            // args[3], args[4] are jbyteArray (data, data2); args[5] jboolean
            try { dumpBytes("  data :", Java.vm.tryGetEnv(), args[3]); } catch (e) {}
            try { dumpBytes("  data2:", Java.vm.tryGetEnv(), args[4]); } catch (e) {}
            console.log("  flag :", args[5]);
        },
        onLeave(retval) {
            if (!retval.isNull()) {
                try {
                    const env = Java.vm.tryGetEnv();
                    const s = env.getStringUtfChars(retval, null).readCString();
                    console.log("  => ", s);
                    env.releaseStringUtfChars(retval, s);
                } catch (e) { console.log("  => (non-string ret)", retval); }
            } else console.log("  => null");
        }
    });

    Interceptor.attach(base.add(OFFSETS.getEncryptoKey), {
        onEnter(args) {
            console.log("=== getEncryptoKey");
            try {
                const env = Java.vm.tryGetEnv();
                console.log("  requestId:", env.getStringUtfChars(args[2], null).readCString());
                const e = args[3];
                console.log("  ecode    :", e.isNull() ? "(null)" :
                    env.getStringUtfChars(e, null).readCString());
            } catch (e) {}
        },
        onLeave(retval) {
            try { dumpBytes("  => key:", Java.vm.tryGetEnv(), retval); } catch (e) {}
        }
    });

    Interceptor.attach(base.add(OFFSETS.encryptPostData), {
        onEnter(args) { console.log("=== encryptPostData"); },
        onLeave(retval) {
            try { dumpBytes("  => :", Java.vm.tryGetEnv(), retval); } catch (e) {}
        }
    });

    return true;
}

// The library loads late; retry until present.
if (!hookModule()) {
    console.log("[*] libthing_security.so not loaded yet — waiting for dlopen");
    const interval = setInterval(() => {
        if (hookModule()) clearInterval(interval);
    }, 500);
}
