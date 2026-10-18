//! Printable CDP input must expose the character event before editing.
//! These fixtures use data URLs and synthetic text only.
use obscura_cdp::dispatch::{dispatch, CdpContext};
use obscura_cdp::types::CdpRequest;
use serde_json::{json, Value};

async fn cdp(ctx: &mut CdpContext, method: &str, params: Value) -> Value {
    let response = dispatch(&CdpRequest {
        id: 1, method: method.to_string(), params,
        session_id: Some("printable".to_string()),
    }, ctx).await;
    assert!(response.error.is_none(), "{method}: {:?}", response.error);
    response.result.unwrap_or_else(|| json!({}))
}

async fn evaluate(ctx: &mut CdpContext, expression: &str) -> Value {
    let result = cdp(ctx, "Runtime.evaluate", json!({
        "expression": expression, "returnByValue": true,
    })).await;
    assert!(result.get("exceptionDetails").is_none(), "{result}");
    result["result"]["value"].clone()
}

async fn setup() -> CdpContext {
    let mut ctx = CdpContext::new();
    let page_id = ctx.create_page();
    ctx.sessions.insert("printable".to_string(), page_id);
    cdp(&mut ctx, "Page.navigate", json!({
        "url": "data:text/html,<input id='field'>", "waitUntil": "load",
    })).await;
    reset(&mut ctx, "").await;
    ctx
}

async fn reset(ctx: &mut CdpContext, cancel: &str) {
    evaluate(ctx, &format!(r#"(() => {{
        document.body.innerHTML = '<input id="field">';
        const field = document.getElementById('field');
        globalThis.events = [];
        const cancel = {};
        for (const type of ['keydown', 'keypress', 'beforeinput', 'input', 'keyup']) {{
            field.addEventListener(type, event => {{
                if (type === cancel) event.preventDefault();
                events.push({{type, key: event.key ?? null, code: event.code ?? null,
                    keyCode: event.keyCode ?? null, which: event.which ?? null, charCode: event.charCode ?? null,
                    trusted: event.isTrusted, canceled: event.defaultPrevented,
                    bubbles: event.bubbles, cancelable: event.cancelable, composed: event.composed,
                    viewIsWindow: event.view === window, value: field.value,
                    repeat: event.repeat ?? null, shift: event.shiftKey ?? null,
                    isComposing: event.isComposing ?? null}});
            }});
        }}
        field.focus();
    }})()"#, json!(cancel))).await;
}

async fn key(ctx: &mut CdpContext, event_type: &str, text: &str) {
    cdp(ctx, "Input.dispatchKeyEvent", json!({
        "type": event_type, "key": "a", "code": "KeyA", "text": text,
        "windowsVirtualKeyCode": 65,
    })).await;
}

async fn event_types(ctx: &mut CdpContext) -> Value {
    evaluate(ctx, "events.map(event => event.type)").await
}

#[tokio::test(flavor = "current_thread")]
async fn printable_keydown_dispatches_character_before_editing_with_native_codes_and_flags() {
    let mut ctx = setup().await;
    assert_eq!(evaluate(&mut ctx,
        "[new KeyboardEvent('keydown').isComposing, new KeyboardEvent('keydown', {isComposing: true}).isComposing]"
    ).await, json!([false, true]));
    key(&mut ctx, "keyDown", "a").await;
    key(&mut ctx, "keyUp", "").await;
    assert_eq!(event_types(&mut ctx).await,
        json!(["keydown", "keypress", "beforeinput", "input", "keyup"]));
    assert_eq!(evaluate(&mut ctx, "document.getElementById('field').value").await, "a");
    assert_eq!(evaluate(&mut ctx,
        "events.filter(e => e.type.startsWith('key')).map(e => [e.type,e.key,e.code,e.keyCode,e.which,e.charCode,e.trusted,e.canceled,e.bubbles,e.cancelable,e.composed,e.viewIsWindow,e.value])"
    ).await, json!([
        ["keydown", "a", "KeyA", 65, 65, 0, true, false, true, true, true, true, ""],
        ["keypress", "a", "KeyA", 97, 97, 97, true, false, true, true, true, true, ""],
        ["keyup", "a", "KeyA", 65, 65, 0, true, false, true, true, true, true, "a"]
    ]));
    assert_eq!(evaluate(&mut ctx, "events.map(e => e.value)").await, json!(["", "", "", "a", "a"]));
    assert_eq!(evaluate(&mut ctx, "events.filter(e => e.type.startsWith('key')).map(e => e.isComposing)").await,
        json!([false, false, false]));
}

#[tokio::test(flavor = "current_thread")]
async fn raw_keydown_leaves_character_phase_to_char_without_duplicate_insertion() {
    let mut ctx = setup().await;
    // A raw event must not insert even if a client also includes its text.
    key(&mut ctx, "rawKeyDown", "a").await;
    assert_eq!(event_types(&mut ctx).await, json!(["keydown"]));
    assert_eq!(evaluate(&mut ctx, "document.getElementById('field').value").await, "");
    key(&mut ctx, "char", "a").await;
    key(&mut ctx, "keyUp", "").await;
    assert_eq!(event_types(&mut ctx).await,
        json!(["keydown", "keypress", "beforeinput", "input", "keyup"]));
    assert_eq!(evaluate(&mut ctx, "document.getElementById('field').value").await, "a");
}

#[tokio::test(flavor = "current_thread")]
async fn canceling_each_pre_edit_stage_stops_later_editing_but_preserves_keyup() {
    let mut ctx = setup().await;
    for (cancel, expected) in [
        ("keydown", json!(["keydown", "keyup"])),
        ("keypress", json!(["keydown", "keypress", "keyup"])),
        ("beforeinput", json!(["keydown", "keypress", "beforeinput", "keyup"])),
    ] {
        reset(&mut ctx, cancel).await;
        key(&mut ctx, "keyDown", "a").await;
        key(&mut ctx, "keyUp", "").await;
        assert_eq!(event_types(&mut ctx).await, expected, "{cancel}");
        assert_eq!(evaluate(&mut ctx, "document.getElementById('field').value").await, "", "{cancel}");
        assert_eq!(evaluate(&mut ctx, "events.filter(e => e.canceled).length === 1").await, true);
    }
}

#[tokio::test(flavor = "current_thread")]
async fn canceling_a_separate_char_event_prevents_its_edit() {
    let mut ctx = setup().await;
    reset(&mut ctx, "keypress").await;
    key(&mut ctx, "rawKeyDown", "").await;
    key(&mut ctx, "char", "a").await;
    key(&mut ctx, "keyUp", "").await;
    assert_eq!(event_types(&mut ctx).await, json!(["keydown", "keypress", "keyup"]));
    assert_eq!(evaluate(&mut ctx, "document.getElementById('field').value").await, "");
}

#[tokio::test(flavor = "current_thread")]
async fn printable_character_codes_follow_text_and_preserve_modifiers_and_escaping() {
    let mut ctx = setup().await;
    for (key_value, code, virtual_code, modifiers, character_code) in [
        ("A", "KeyA", 65, 8, 65),
        ("'", "Quote", 222, 0, 39),
        ("\\", "Backslash", 220, 0, 92),
    ] {
        reset(&mut ctx, "").await;
        cdp(&mut ctx, "Input.dispatchKeyEvent", json!({
            "type": "keyDown", "key": key_value, "code": code, "text": key_value,
            "windowsVirtualKeyCode": virtual_code, "modifiers": modifiers, "autoRepeat": true,
        })).await;
        assert_eq!(evaluate(&mut ctx,
            "events.filter(e => e.type === 'keypress').map(e => [e.key,e.code,e.keyCode,e.which,e.charCode,e.shift,e.repeat])"
        ).await, json!([[key_value, code, character_code, character_code, character_code, modifiers == 8, true]]));
        assert_eq!(evaluate(&mut ctx, "document.getElementById('field').value").await, key_value);
    }
}

#[tokio::test(flavor = "current_thread")]
async fn readonly_still_receives_keyboard_events_and_insert_text_remains_keyboard_free() {
    let mut ctx = setup().await;
    evaluate(&mut ctx, "document.getElementById('field').readOnly = true").await;
    key(&mut ctx, "keyDown", "a").await;
    key(&mut ctx, "keyUp", "").await;
    assert_eq!(event_types(&mut ctx).await, json!(["keydown", "keypress", "keyup"]));
    assert_eq!(evaluate(&mut ctx, "document.getElementById('field').value").await, "");
    reset(&mut ctx, "").await;
    cdp(&mut ctx, "Input.insertText", json!({"text": "a"})).await;
    assert_eq!(event_types(&mut ctx).await, json!(["beforeinput", "input"]));
    assert_eq!(evaluate(&mut ctx, "document.getElementById('field').value").await, "a");
}
