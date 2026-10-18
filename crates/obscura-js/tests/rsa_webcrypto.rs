#![cfg(feature = "stealth")]

use obscura_js::runtime::ObscuraJsRuntime;
use serde_json::{json, Value};

async fn probe(script: &str) -> Value {
    let mut rt = ObscuraJsRuntime::new();
    rt.set_dom(obscura_dom::parse_html("<!doctype html><body></body>"));
    rt.set_url("https://crypto.test/");
    rt.run_page_init();
    rt.execute_script("rsa-webcrypto-regression", &format!(r#"
        globalThis.rsaResult = null;
        const algorithm = {{name:'RSASSA-PKCS1-v1_5',modulusLength:2048,
            publicExponent:new Uint8Array([1,0,1]),hash:{{name:'SHA-256'}}}};
        const payload = new TextEncoder().encode('offline RSA signing fixture');
        const rejected = async operation => {{
            try {{ await operation(); return 'accepted'; }} catch (error) {{ return error.name; }}
        }};
        (async () => {{ {script} }})().then(
            value => rsaResult = value,
            error => rsaResult = {{error:error.name}}
        );
    "#)).unwrap();
    rt.run_event_loop_bounded(5000).await.unwrap();
    rt.evaluate("rsaResult").unwrap()
}

#[tokio::test(flavor = "current_thread")]
async fn rsa_webcrypto_generates_real_signing_pair_and_public_jwk() {
    let result = probe(r#"
        const pair = await crypto.subtle.generateKey(algorithm,false,['sign','verify']);
        const describe = key => [key instanceof CryptoKey,key.type,key.extractable,key.usages,
            key.algorithm.name,key.algorithm.modulusLength,Array.from(key.algorithm.publicExponent),key.algorithm.hash.name];
        const privateDescription = describe(pair.privateKey), publicDescription = describe(pair.publicKey);
        const jwk = await crypto.subtle.exportKey('jwk',pair.publicKey);
        const signature = await crypto.subtle.sign({name:'RSASSA-PKCS1-v1_5',hash:'SHA-256'},pair.privateKey,payload);
        const alteredPayload = new Uint8Array(payload); alteredPayload[0] ^= 1;
        const alteredSignature = new Uint8Array(signature.slice(0)); alteredSignature[0] ^= 1;
        pair.privateKey.algorithm.hash.name = 'SHA-512'; pair.publicKey.algorithm.name = 'HMAC';
        const afterMutation = new Uint8Array(await crypto.subtle.sign('RSASSA-PKCS1-v1_5',pair.privateKey,payload));
        const originalSignature = new Uint8Array(signature);
        return {
            privateKey:privateDescription, publicKey:publicDescription,
            boundAlgorithmUnchanged:afterMutation.length === originalSignature.length &&
                afterMutation.every((byte,index) => byte === originalSignature[index]),
            jwk:[jwk.kty === 'RSA',typeof jwk.n === 'string' && /^[A-Za-z0-9_-]{342}$/.test(jwk.n),
                jwk.e === 'AQAB',jwk.alg === 'RS256',jwk.ext === true,
                JSON.stringify(jwk.key_ops) === JSON.stringify(['verify']),
                ['d','p','q','dp','dq','qi'].every(name => !Object.prototype.hasOwnProperty.call(jwk,name))],
            signatureLength:signature.byteLength,
            verified:await crypto.subtle.verify('RSASSA-PKCS1-v1_5',pair.publicKey,signature,payload),
            alteredPayloadRejected:!(await crypto.subtle.verify('RSASSA-PKCS1-v1_5',pair.publicKey,signature,alteredPayload)),
            alteredSignatureRejected:!(await crypto.subtle.verify('RSASSA-PKCS1-v1_5',pair.publicKey,alteredSignature,payload)),
            emptySignatureRejected:!(await crypto.subtle.verify('RSASSA-PKCS1-v1_5',pair.publicKey,new Uint8Array(0),payload))
        };
    "#).await;
    assert_eq!(result, json!({
        "privateKey":[true,"private",false,["sign"],"RSASSA-PKCS1-v1_5",2048,[1,0,1],"SHA-256"],
        "publicKey":[true,"public",true,["verify"],"RSASSA-PKCS1-v1_5",2048,[1,0,1],"SHA-256"],
        "jwk":[true,true,true,true,true,true,true],"signatureLength":256,"boundAlgorithmUnchanged":true,
        "verified":true,"alteredPayloadRejected":true,"alteredSignatureRejected":true,"emptySignatureRejected":true
    }));
}

#[tokio::test(flavor = "current_thread")]
async fn rsa_webcrypto_rejects_private_export_wrong_usages_and_key_algorithms() {
    let result = probe(r#"
        const pair = await crypto.subtle.generateKey(algorithm,false,['sign','verify']);
        const secret = await crypto.subtle.importKey('raw',new Uint8Array([1,2,3]),{name:'HMAC',hash:'SHA-256'},false,['sign']);
        return {
            privateJwk:await rejected(() => crypto.subtle.exportKey('jwk',pair.privateKey)),
            privateRaw:await rejected(() => crypto.subtle.exportKey('raw',pair.privateKey)),
            invalidUsage:await rejected(() => crypto.subtle.generateKey(algorithm,false,['encrypt'])),
            emptyUsages:await rejected(() => crypto.subtle.generateKey(algorithm,false,[])),
            publicSigning:await rejected(() => crypto.subtle.sign('RSASSA-PKCS1-v1_5',pair.publicKey,payload)),
            privateVerifying:await rejected(() => crypto.subtle.verify('RSASSA-PKCS1-v1_5',pair.privateKey,new Uint8Array(256),payload)),
            wrongSigningAlgorithm:await rejected(() => crypto.subtle.sign('HMAC',pair.privateKey,payload)),
            wrongKeyAlgorithm:await rejected(() => crypto.subtle.sign('RSASSA-PKCS1-v1_5',secret,payload))
        };
    "#).await;
    assert_eq!(result, json!({
        "privateJwk":"InvalidAccessError","privateRaw":"InvalidAccessError",
        "invalidUsage":"SyntaxError","emptyUsages":"SyntaxError",
        "publicSigning":"InvalidAccessError","privateVerifying":"InvalidAccessError",
        "wrongSigningAlgorithm":"InvalidAccessError","wrongKeyAlgorithm":"InvalidAccessError"
    }));
}

#[tokio::test(flavor = "current_thread")]
async fn rsa_webcrypto_indexeddb_roundtrip_preserves_key_material_and_permissions() {
    let result = probe(r#"
        const pair = await crypto.subtle.generateKey(algorithm,false,['sign','verify']);
        const expected = new Uint8Array(await crypto.subtle.sign('RSASSA-PKCS1-v1_5',pair.privateKey,payload));
        const opened = () => new Promise((resolve,reject) => {
            const request = indexedDB.open('rsa-key-roundtrip',1);
            request.onupgradeneeded = () => request.result.createObjectStore('keys',{autoIncrement:true});
            request.onsuccess = () => resolve(request.result); request.onerror = () => reject(request.error);
        });
        const db = await opened();
        await new Promise((resolve,reject) => {
            const tx = db.transaction('keys','readwrite');
            tx.oncomplete = resolve; tx.onabort = tx.onerror = () => reject(tx.error);
            tx.objectStore('keys').put({publicKey:pair.publicKey,privateKey:pair.privateKey});
        });
        db.close();
        const reopened = await opened();
        const stored = await new Promise((resolve,reject) => {
            const tx = reopened.transaction('keys','readonly'), rows = [];
            const request = tx.objectStore('keys').openCursor();
            request.onsuccess = () => {
                const cursor = request.result;
                if (cursor) { rows.push(cursor.value); cursor.continue(); }
            };
            tx.oncomplete = () => resolve(rows); tx.onabort = tx.onerror = () => reject(tx.error);
        });
        const copy = stored[0];
        const actual = new Uint8Array(await crypto.subtle.sign('RSASSA-PKCS1-v1_5',copy.privateKey,payload));
        const publicJwk = await crypto.subtle.exportKey('jwk',copy.publicKey);
        const originalJwk = await crypto.subtle.exportKey('jwk',pair.publicKey);
        const privateExport = await rejected(() => crypto.subtle.exportKey('jwk',copy.privateKey));
        reopened.close(); indexedDB.deleteDatabase('rsa-key-roundtrip');
        return {
            rowCount:stored.length,
            privateKey:[copy.privateKey instanceof CryptoKey,copy.privateKey !== pair.privateKey,
                copy.privateKey.type,copy.privateKey.extractable,copy.privateKey.usages],
            publicKey:[copy.publicKey instanceof CryptoKey,copy.publicKey !== pair.publicKey,
                copy.publicKey.type,copy.publicKey.extractable,copy.publicKey.usages],
            sameSignature:actual.length === expected.length && actual.every((byte,index) => byte === expected[index]),
            verified:await crypto.subtle.verify('RSASSA-PKCS1-v1_5',pair.publicKey,actual,payload),
            samePublicJwk:publicJwk.n === originalJwk.n && publicJwk.e === originalJwk.e,
            privateExport
        };
    "#).await;
    assert_eq!(result, json!({
        "rowCount":1,"privateKey":[true,true,"private",false,["sign"]],
        "publicKey":[true,true,"public",true,["verify"]],
        "sameSignature":true,"verified":true,"samePublicJwk":true,"privateExport":"InvalidAccessError"
    }));
}

#[tokio::test(flavor = "current_thread")]
async fn rsa_webcrypto_nonextractable_material_survives_page_intrinsic_poisoning() {
    let result = probe(r#"
        const U8 = Uint8Array, set = WeakMap.prototype.set, push = Array.prototype.push;
        const isArray = Array.isArray, isView = ArrayBuffer.isView;
        // Parse the complete RSA PKCS#8 envelope, not a probabilistic first-byte
        // check that could mistake an encrypted capsule for DER.
        const isPrivateDer = bytes => {
            const read = (at,tag) => {
                if (bytes[at++] !== tag) return null;
                let size = bytes[at++];
                if (size & 128) {
                    const count = size & 127; size = 0;
                    if (!count || count > 4 || at + count > bytes.length) return null;
                    for (let i = 0; i < count; i++) size = size * 256 + bytes[at++];
                }
                return Number.isInteger(size) && at + size <= bytes.length ? {at,end:at+size} : null;
            };
            const outer = read(0,48);
            if (!outer || outer.end !== bytes.length) return false;
            const version = read(outer.at,2);
            if (!version || version.end !== version.at + 1 || bytes[version.at] !== 0) return false;
            const algorithm = read(version.end,48), oid = algorithm && read(algorithm.at,6);
            const expectedOid = [42,134,72,134,247,13,1,1,1];
            if (!oid || oid.end - oid.at !== expectedOid.length ||
                !expectedOid.every((byte,index) => bytes[oid.at+index] === byte)) return false;
            const octets = read(algorithm.end,4), rsa = octets && read(octets.at,48);
            if (!rsa || octets.end !== outer.end || rsa.end !== octets.end) return false;
            let at = rsa.at;
            for (let i = 0; i < 9; i++) {
                const integer = read(at,2);
                if (!integer || integer.at === integer.end || integer.end > rsa.end) return false;
                if (i === 0 && (integer.end !== integer.at+1 || bytes[integer.at] !== 0)) return false;
                at = integer.end;
            }
            return at === rsa.end;
        };
        const baseline = await crypto.subtle.generateKey(algorithm,true,['sign','verify']);
        const detectorRecognizesPrivateExport = isPrivateDer(new U8(await crypto.subtle.exportKey('pkcs8',baseline.privateKey)));
        let leakedPrivateDer = false, inspecting = false, observations = 0;
        const associations = [];
        const inspect = value => {
            if (inspecting) return;
            inspecting = true;
            try {
                let bytes;
                if (value instanceof ArrayBuffer) bytes = new U8(value);
                else if (isView(value)) bytes = new U8(value.buffer,value.byteOffset,value.byteLength);
                else if (isArray(value) && value.length > 256 && typeof value[0] === 'number') bytes = value;
                if (bytes && bytes.length > 256) {
                    observations++; leakedPrivateDer ||= isPrivateDer(bytes);
                }
            } finally { inspecting = false; }
        };
        globalThis.Uint8Array = new Proxy(U8, {construct(target,args,newTarget) {
            inspect(args[0]); const value = Reflect.construct(target,args,newTarget); inspect(value); return value;
        }});
        WeakMap.prototype.set = function(key,value) {
            inspect(value);
            if (key instanceof CryptoKey) associations[associations.length] = {map:this,key,value};
            return set.call(this,key,value);
        };
        Array.prototype.push = function(...values) {
            for (const value of values) inspect(value);
            const length = push.apply(this,values); inspect(this); return length;
        };
        let db;
        try {
            const pair = await crypto.subtle.generateKey(algorithm,false,['sign','verify']);
            db = await new Promise((resolve,reject) => {
                const request = indexedDB.open('rsa-poisoning',1);
                request.onupgradeneeded = () => request.result.createObjectStore('keys',{autoIncrement:true});
                request.onsuccess = () => resolve(request.result); request.onerror = () => reject(request.error);
            });
            await new Promise((resolve,reject) => {
                const tx = db.transaction('keys','readwrite');
                tx.oncomplete = resolve; tx.onabort = tx.onerror = () => reject(tx.error);
                tx.objectStore('keys').put(pair);
            });
            const copy = await new Promise((resolve,reject) => {
                const tx = db.transaction('keys','readonly'), request = tx.objectStore('keys').get(1);
                tx.oncomplete = () => resolve(request.result); tx.onabort = tx.onerror = () => reject(tx.error);
            });
            const signature = await crypto.subtle.sign('RSASSA-PKCS1-v1_5',copy.privateKey,payload);
            // If page hooks captured the private WeakMaps, replay their opaque
            // state onto a forged extractable key. Native permissions still win.
            const forged = Object.create(CryptoKey.prototype);
            Object.defineProperties(forged,{
                type:{value:'private'},extractable:{value:true},
                algorithm:{value:pair.privateKey.algorithm},usages:{value:['sign']}
            });
            for (const item of associations) if (item.key === pair.privateKey) set.call(item.map,forged,item.value);
            return {
                detectorRecognizesPrivateExport, observedBytes:observations > 0,
                leakedPrivateDer, nonextractable:!copy.privateKey.extractable,
                verified:await crypto.subtle.verify('RSASSA-PKCS1-v1_5',pair.publicKey,signature,payload),
                privateExport:await rejected(() => crypto.subtle.exportKey('pkcs8',copy.privateKey)),
                forgedExport:await rejected(() => crypto.subtle.exportKey('pkcs8',forged))
            };
        } finally {
            globalThis.Uint8Array = U8; WeakMap.prototype.set = set; Array.prototype.push = push;
            if (db) db.close(); indexedDB.deleteDatabase('rsa-poisoning');
        }
    "#).await;
    assert_eq!(result, json!({
        "detectorRecognizesPrivateExport":true,"observedBytes":true,"leakedPrivateDer":false,
        "nonextractable":true,"verified":true,
        // The forged JS object bypasses the public-property check, but the
        // native capsule rejects export and runOp maps that to OperationError.
        "privateExport":"InvalidAccessError","forgedExport":"OperationError"
    }));
}
