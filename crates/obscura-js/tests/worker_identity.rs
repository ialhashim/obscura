use obscura_js::runtime::ObscuraJsRuntime;
use serde_json::json;

fn runtime() -> ObscuraJsRuntime {
    let mut rt = ObscuraJsRuntime::new();
    rt.set_url("https://example.test/");
    rt.set_dom(obscura_dom::parse_html("<!doctype html><body></body>"));
    rt.set_user_agent("Mozilla/5.0 (X11; Linux x86_64) Chrome/153.0.0.0");
    rt.set_platform("Linux x86_64", "Linux", "7.0.0");
    rt.set_locale("ar-SA");
    rt.run_page_init();
    rt
}

#[tokio::test(flavor = "current_thread")]
async fn worker_navigator_has_its_own_interface_and_configured_identity() {
    let mut rt = runtime();
    rt.execute_script("worker-identity", r#"
        globalThis.__workerIdentity = null;
        const expected = {};
        for (const name of ['appVersion', 'platform', 'product', 'userAgent', 'language',
                            'languages', 'onLine', 'hardwareConcurrency', 'deviceMemory']) {
            expected[name] = navigator[name];
        }
        expected.uaData = navigator.userAgentData.toJSON();
        const source = `onmessage = event => {
            let illegalConstructor = false;
            try { new WorkerNavigator(); } catch (error) { illegalConstructor = error instanceof TypeError; }
            const expected = event.data;
            const fields = Object.keys(expected).filter(name => name !== 'uaData');
            postMessage({
                samePaths: navigator === self.navigator && navigator === globalThis.navigator,
                ownGlobal: Object.prototype.hasOwnProperty.call(self, 'navigator'),
                prototype: Object.getPrototypeOf(navigator) === WorkerNavigator.prototype,
                instance: navigator instanceof WorkerNavigator,
                tag: Object.prototype.toString.call(navigator), illegalConstructor,
                identity: fields.every(name => JSON.stringify(navigator[name]) === JSON.stringify(expected[name])),
                uaData: JSON.stringify(navigator.userAgentData.toJSON()) === JSON.stringify(expected.uaData),
                languagesFrozen: Object.isFrozen(navigator.languages),
                noWindowApis: ['plugins', 'mimeTypes', 'clipboard', 'geolocation', 'mediaDevices',
                    'sendBeacon', 'getGamepads', 'webdriver'].every(name => !(name in navigator)),
            });
        };`;
        const url = URL.createObjectURL(new Blob([source]));
        const worker = new Worker(url);
        worker.onmessage = event => {
            __workerIdentity = event.data; worker.terminate(); URL.revokeObjectURL(url);
        };
        worker.postMessage(expected);
    "#).unwrap();
    rt.run_event_loop_bounded(100).await.unwrap();
    assert_eq!(rt.evaluate("__workerIdentity").unwrap(), json!({
        "samePaths": true, "ownGlobal": true, "prototype": true, "instance": true,
        "tag": "[object WorkerNavigator]", "illegalConstructor": true, "identity": true,
        "uaData": true, "languagesFrozen": true, "noWindowApis": true,
    }));
    assert_eq!(rt.evaluate("typeof window.WorkerNavigator").unwrap(), json!("undefined"));
}

#[tokio::test(flavor = "current_thread")]
async fn worker_navigator_mutations_do_not_reach_window_or_other_workers() {
    let mut rt = runtime();
    rt.execute_script("worker-identity-isolation", r#"
        globalThis.__workerIsolation = [];
        globalThis.__windowBrands = JSON.stringify(navigator.userAgentData.brands);
        const source = `onmessage = async () => {
            const unmodified = navigator.marker === undefined && WorkerNavigator.prototype.marker === undefined;
            const originalUa = navigator.userAgent;
            try { navigator.userAgent = 'changed'; } catch (_) {}
            navigator.marker = true; WorkerNavigator.prototype.marker = true;
            navigator.userAgentData.marker = true;
            const originalBrands = JSON.stringify(navigator.userAgentData.brands);
            navigator.userAgentData.brands[0].brand = 'changed';
            const entropy = await navigator.userAgentData.getHighEntropyValues(['fullVersionList']);
            entropy.brands[0].brand = 'changed';
            const next = await navigator.userAgentData.getHighEntropyValues(['fullVersionList']);
            postMessage([unmodified, navigator.userAgent === originalUa,
                JSON.stringify(navigator.userAgentData.brands) === originalBrands,
                next.brands[0].brand !== 'changed']);
        };`;
        const url = URL.createObjectURL(new Blob([source]));
        for (let index = 0; index < 2; index++) {
            const worker = new Worker(url);
            worker.onmessage = event => { __workerIsolation[index] = event.data; worker.terminate(); };
            worker.postMessage(null);
        }
        globalThis.__cleanupWorkerUrl = () => URL.revokeObjectURL(url);
    "#).unwrap();
    rt.run_event_loop_bounded(100).await.unwrap();
    assert_eq!(rt.evaluate("__workerIsolation").unwrap(), json!([[true, true, true, true], [true, true, true, true]]));
    assert_eq!(rt.evaluate(r#"[
        navigator.marker === undefined, Object.getPrototypeOf(navigator).marker === undefined,
        navigator.userAgentData.marker === undefined,
        JSON.stringify(navigator.userAgentData.brands) === __windowBrands,
        navigator.userAgent.includes('Chrome/153.')
    ]"#).unwrap(), json!([true, true, true, true, true]));
    rt.evaluate("__cleanupWorkerUrl()").unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn worker_navigator_inherits_its_creator_frame_identity() {
    let mut rt = runtime();
    rt.execute_script("frame-worker-identity", r#"
        const frame = document.createElement('iframe'); document.body.appendChild(frame);
        globalThis.__workerFrame = frame.contentWindow;
        __workerFrame.eval(`
            globalThis.reply = null;
            const source = 'onmessage = event => postMessage([navigator === self.navigator, navigator.userAgent === event.data.ua, navigator.platform === event.data.platform, navigator.userAgentData.platform === event.data.uaPlatform]);';
            const url = URL.createObjectURL(new Blob([source]));
            const worker = new Worker(url);
            worker.onmessage = event => { reply = event.data; worker.terminate(); URL.revokeObjectURL(url); };
            worker.postMessage({ua:navigator.userAgent, platform:navigator.platform, uaPlatform:navigator.userAgentData.platform});
        `);
    "#).unwrap();
    rt.run_event_loop_bounded(100).await.unwrap();
    assert_eq!(rt.evaluate("__workerFrame.reply").unwrap(), json!([true, true, true, true]));
    assert_eq!(rt.evaluate("__workerFrame.navigator.userAgent === navigator.userAgent && __workerFrame.navigator.platform === navigator.platform").unwrap(), json!(true));
}
