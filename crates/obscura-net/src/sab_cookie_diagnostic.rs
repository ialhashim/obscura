//! Temporary, explicitly enabled cookie continuity observations. No request is
//! modified or replayed. Sensitive pairs stay in bounded, short-lived memory.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use url::Url;
use wreq::header::HeaderMap;

use crate::cookies::{CookieJar, SameSiteContext};

const MAX_CALLS: u8 = 4;
const TTL: Duration = Duration::from_secs(120);
const MAX_PAIRS: usize = 64;
const MAX_HEADER_BYTES: usize = 64 * 1024;

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
struct CookiePair(String, String);

#[derive(Default)]
struct State {
    started: Option<Instant>,
    calls: u8,
    closed: bool,
    response_call: u8,
    response_pairs: Vec<CookiePair>,
}

pub(crate) struct SabCookieDiagnostic {
    state: Mutex<State>,
}

#[derive(Debug)]
struct RequestObservation {
    call: u8,
    snapshot_available: bool,
    bounded: bool,
    cookie_header_count: Option<usize>,
    cookie_pair_count: Option<usize>,
    duplicate_cookie_names: Option<bool>,
    matches_current_jar: Option<bool>,
    prior_response_call: u8,
    prior_response_pair_count: usize,
    prior_pairs_still_in_jar: Option<usize>,
    prior_pairs_in_request: Option<usize>,
}

#[derive(Debug)]
struct ResponseObservation {
    call: u8,
    set_cookie_count: usize,
    bounded: bool,
    storage_enabled: bool,
    eligible_pair_count: Option<usize>,
    retained_pair_count: Option<usize>,
}

fn pairs(value: &str) -> Option<Vec<CookiePair>> {
    if value.len() > MAX_HEADER_BYTES {
        return None;
    }
    let mut result = Vec::new();
    for part in value.split(';').map(str::trim).filter(|part| !part.is_empty()) {
        if result.len() == MAX_PAIRS {
            return None;
        }
        let (name, value) = part.split_once('=')?;
        result.push(CookiePair(name.trim().into(), value.trim().into()));
    }
    result.sort();
    Some(result)
}

fn request_pairs(headers: &HeaderMap) -> Option<Vec<CookiePair>> {
    let mut total_bytes = 0usize;
    let mut result = Vec::new();
    for header in headers.get_all("cookie") {
        total_bytes = total_bytes.checked_add(header.as_bytes().len())?;
        if total_bytes > MAX_HEADER_BYTES {
            return None;
        }
        result.extend(pairs(header.to_str().ok()?)?);
        if result.len() > MAX_PAIRS {
            return None;
        }
    }
    result.sort();
    Some(result)
}

fn target(method: &str, url: &Url) -> bool {
    method == "POST"
        && url.scheme() == "https"
        && url.host_str() == Some("www.security.online-banking.sabbnet.com")
        && url.port_or_known_default() == Some(443)
        && url.username().is_empty()
        && url.password().is_none()
        && url.path() == "/am/json/realms/root/realms/external/authenticate"
}

impl SabCookieDiagnostic {
    pub(crate) fn from_env() -> Option<Arc<Self>> {
        (std::env::var("HLIFE_SAB_AUTH_SHAPE_DIAGNOSTIC").as_deref() == Ok("1"))
            .then(|| Arc::new(Self { state: Mutex::new(State::default()) }))
    }

    fn close(state: &mut State) {
        state.closed = true;
        state.response_pairs.clear();
    }

    fn reserve(&self, now: Instant) -> Option<(u8, bool)> {
        let mut state = self.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        if state.started.is_some_and(|started| now.saturating_duration_since(started) >= TTL) {
            Self::close(&mut state);
        }
        if state.closed || state.calls == MAX_CALLS {
            return None;
        }
        let first = state.started.is_none();
        state.started.get_or_insert(now);
        state.calls += 1;
        Some((state.calls, first))
    }

    pub(crate) fn request(
        self: &Arc<Self>, method: &str, url: &Url, request: &wreq::RequestBuilder,
        jar: &CookieJar, context: Option<SameSiteContext>,
    ) -> Option<u8> {
        if !target(method, url) {
            return None;
        }
        let (call, first) = self.reserve(Instant::now())?;
        if first {
            let weak = Arc::downgrade(self);
            tokio::spawn(async move {
                tokio::time::sleep(TTL).await;
                if let Some(diagnostic) = weak.upgrade() {
                    let mut state = diagnostic.state.lock().unwrap_or_else(|p| p.into_inner());
                    Self::close(&mut state);
                }
            });
        }
        // This clone is inspected, never executed. The original send path stays
        // unchanged. These are builder headers, not a TLS wire capture.
        let snapshot = request.try_clone().and_then(|copy| copy.build().ok());
        let expected = context.map(|context| jar.get_cookie_header_in_context(url, context))
            .unwrap_or_default();
        let observation = self.observe_request(call, snapshot.as_ref().map(|r| r.headers()), &expected);
        tracing::info!(target: "hlife_sab_cookie_continuity",
            call = observation.call, snapshot_available = observation.snapshot_available,
            credentials_allowed = context.is_some(),
            same_site_context = matches!(context, Some(SameSiteContext::SameSite)),
            bounded = observation.bounded, cookie_header_count = ?observation.cookie_header_count,
            cookie_pair_count = ?observation.cookie_pair_count,
            duplicate_cookie_names = ?observation.duplicate_cookie_names,
            matches_current_jar = ?observation.matches_current_jar,
            prior_response_call = observation.prior_response_call,
            prior_response_pair_count = observation.prior_response_pair_count,
            prior_pairs_still_in_jar = ?observation.prior_pairs_still_in_jar,
            prior_pairs_in_request = ?observation.prior_pairs_in_request,
            "SAB authentication built-request cookie continuity");
        Some(call)
    }

    fn observe_request(&self, call: u8, headers: Option<&HeaderMap>, expected: &str) -> RequestObservation {
        let actual = headers.and_then(request_pairs);
        let expected = pairs(expected);
        let state = self.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let applicable: Option<Vec<_>> = expected.as_ref().map(|expected| state.response_pairs.iter()
            .filter(|pair| expected.contains(pair)).collect());
        RequestObservation {
            call,
            snapshot_available: headers.is_some(),
            bounded: actual.is_some() && expected.is_some(),
            cookie_header_count: headers.map(|headers| headers.get_all("cookie").iter().count()),
            cookie_pair_count: actual.as_ref().map(Vec::len),
            duplicate_cookie_names: actual.as_ref().map(|pairs| pairs.windows(2)
                .any(|pair| pair[0].0 == pair[1].0)),
            matches_current_jar: actual.as_ref().zip(expected.as_ref()).map(|(a, e)| a == e),
            prior_response_call: state.response_call,
            prior_response_pair_count: state.response_pairs.len(),
            prior_pairs_still_in_jar: applicable.as_ref().map(Vec::len),
            prior_pairs_in_request: applicable.as_ref().zip(actual.as_ref())
                .map(|(previous, actual)| previous.iter().filter(|pair| actual.contains(pair)).count()),
        }
    }

    pub(crate) fn response(
        &self, call: u8, url: &Url, headers: &HeaderMap, jar: &CookieJar,
        context: Option<SameSiteContext>, storage_enabled: bool,
    ) {
        let Some(observation) = self.observe_response(
            Instant::now(), call, url, headers, jar, context, storage_enabled,
        ) else { return; };
        tracing::info!(target: "hlife_sab_cookie_continuity",
            call = observation.call, set_cookie_count = observation.set_cookie_count,
            bounded = observation.bounded, storage_enabled = observation.storage_enabled,
            eligible_pair_count = ?observation.eligible_pair_count,
            retained_pair_count = ?observation.retained_pair_count,
            "SAB authentication response cookie continuity");
    }

    fn observe_response(
        &self, now: Instant, call: u8, url: &Url, headers: &HeaderMap, jar: &CookieJar,
        context: Option<SameSiteContext>, storage_enabled: bool,
    ) -> Option<ResponseObservation> {
        let mut state = self.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        if state.started.is_some_and(|started| now.saturating_duration_since(started) >= TTL) {
            Self::close(&mut state);
        }
        if state.closed || call == 0 || call > state.calls {
            return None;
        }
        let count = headers.get_all("set-cookie").iter().count();
        let bounded = count <= MAX_PAIRS && headers.get_all("set-cookie").iter()
            .try_fold(0usize, |bytes, header| bytes.checked_add(header.as_bytes().len()))
            .is_some_and(|bytes| bytes <= MAX_HEADER_BYTES)
            && headers.get_all("set-cookie").iter().all(|header| header.to_str().is_ok());
        let eligible = bounded.then(|| {
            // Isolate the response's own accepted, unexpired, in-scope pairs.
            // Deletions and cookies for other paths are not expected next time.
            let isolated = CookieJar::new();
            for header in headers.get_all("set-cookie") {
                if let Ok(value) = header.to_str() {
                    isolated.set_cookie(value, url);
                }
            }
            pairs(&isolated.get_cookie_header_in_context(url, context.unwrap_or(SameSiteContext::SameSite)))
        }).flatten();
        let actual = context.map(|context| jar.get_cookie_header_in_context(url, context))
            .unwrap_or_default();
        let actual = pairs(&actual);
        let retained = eligible.as_ref().zip(actual.as_ref()).map(|(eligible, actual)| eligible.iter()
            .filter(|pair| actual.contains(pair)).cloned().collect::<Vec<_>>());
        let observation = ResponseObservation {
            call, set_cookie_count: count,
            bounded: bounded && eligible.is_some() && actual.is_some(),
            storage_enabled,
            eligible_pair_count: eligible.as_ref().map(Vec::len),
            retained_pair_count: retained.as_ref().map(Vec::len),
        };
        if call >= state.response_call {
            state.response_call = call;
            state.response_pairs = retained.unwrap_or_default();
        }
        if call == MAX_CALLS {
            Self::close(&mut state);
        }
        Some(observation)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn url() -> Url {
        Url::parse("https://www.security.online-banking.sabbnet.com/am/json/realms/root/realms/external/authenticate").unwrap()
    }

    fn diagnostic() -> SabCookieDiagnostic {
        SabCookieDiagnostic { state: Mutex::new(State::default()) }
    }

    fn headers(name: &'static str, values: &[&str]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for value in values {
            headers.append(name, value.parse().unwrap());
        }
        headers
    }

    #[test]
    fn sab_cookie_diagnostic_observes_rotation_without_modifying_jar() {
        let diagnostic = diagnostic();
        let now = Instant::now();
        let jar = CookieJar::new();
        jar.set_cookie("synthetic=before; Secure; HttpOnly; Path=/", &url());
        assert_eq!(diagnostic.reserve(now), Some((1, true)));
        let request = diagnostic.observe_request(1, Some(&headers("cookie", &["synthetic=before"])),
            &jar.get_cookie_header(&url()));
        assert_eq!(request.matches_current_jar, Some(true));
        let response = headers("set-cookie", &["synthetic=after; Secure; HttpOnly; SameSite=Lax; Path=/"]);
        jar.set_cookie("synthetic=after; Secure; HttpOnly; SameSite=Lax; Path=/", &url());
        let observed = diagnostic.observe_response(now, 1, &url(), &response, &jar,
            Some(SameSiteContext::SameSite), true).unwrap();
        assert_eq!(observed.eligible_pair_count, Some(1));
        assert_eq!(observed.retained_pair_count, Some(1));
        assert_eq!(diagnostic.reserve(now), Some((2, false)));
        let request = diagnostic.observe_request(2, Some(&headers("cookie", &["synthetic=after"])),
            &jar.get_cookie_header(&url()));
        assert_eq!(request.cookie_header_count, Some(1));
        assert_eq!(request.prior_pairs_still_in_jar, Some(1));
        assert_eq!(request.prior_pairs_in_request, Some(1));
        assert_eq!(request.matches_current_jar, Some(true));
        assert_eq!(jar.get_cookie_header(&url()), "synthetic=after");
    }

    #[test]
    fn sab_cookie_diagnostic_detects_missing_duplicate_and_unavailable_headers() {
        let diagnostic = diagnostic();
        let missing = diagnostic.observe_request(1, Some(&HeaderMap::new()), "synthetic=value");
        assert_eq!(missing.cookie_header_count, Some(0));
        assert_eq!(missing.matches_current_jar, Some(false));
        let duplicate = diagnostic.observe_request(1,
            Some(&headers("cookie", &["synthetic=value", "synthetic=value"])), "synthetic=value");
        assert_eq!(duplicate.cookie_header_count, Some(2));
        assert_eq!(duplicate.duplicate_cookie_names, Some(true));
        assert_eq!(duplicate.matches_current_jar, Some(false));
        let unavailable = diagnostic.observe_request(1, None, "synthetic=value");
        assert!(!unavailable.snapshot_available);
        assert_eq!(unavailable.matches_current_jar, None);
    }

    #[test]
    fn sab_cookie_diagnostic_excludes_deleted_expired_and_out_of_scope_pairs() {
        let diagnostic = diagnostic();
        let now = Instant::now();
        diagnostic.reserve(now);
        let values = ["removed=gone; Max-Age=0; Path=/", "past=gone; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Path=/",
            "elsewhere=value; Path=/different", "foreign=value; Domain=other.invalid; Path=/", "kept=value; Path=/"];
        let response = headers("set-cookie", &values);
        let jar = CookieJar::new();
        jar.set_cookie("removed=old; Path=/", &url());
        for value in values { jar.set_cookie(value, &url()); }
        let observed = diagnostic.observe_response(now, 1, &url(), &response, &jar,
            Some(SameSiteContext::SameSite), true).unwrap();
        assert_eq!(observed.set_cookie_count, 5);
        assert_eq!(observed.eligible_pair_count, Some(1));
        assert_eq!(observed.retained_pair_count, Some(1));
        jar.set_cookie("kept=gone; Max-Age=0; Path=/", &url());
        let next = diagnostic.observe_request(2, Some(&HeaderMap::new()), &jar.get_cookie_header(&url()));
        assert_eq!(next.prior_response_pair_count, 1);
        assert_eq!(next.prior_pairs_still_in_jar, Some(0));
        assert_eq!(next.matches_current_jar, Some(true));
    }

    #[test]
    fn sab_cookie_diagnostic_detects_response_cookie_not_retained() {
        let diagnostic = diagnostic();
        let now = Instant::now();
        diagnostic.reserve(now);
        let observed = diagnostic.observe_response(now, 1, &url(),
            &headers("set-cookie", &["synthetic=value; Path=/"]), &CookieJar::new(),
            Some(SameSiteContext::SameSite), true).unwrap();
        assert_eq!(observed.eligible_pair_count, Some(1));
        assert_eq!(observed.retained_pair_count, Some(0));
    }

    #[test]
    fn sab_cookie_diagnostic_is_bounded_and_clears_expired_state() {
        let diagnostic = diagnostic();
        let now = Instant::now();
        for call in 1..=MAX_CALLS { assert_eq!(diagnostic.reserve(now).unwrap().0, call); }
        assert!(diagnostic.reserve(now).is_none());
        let expiring = super::SabCookieDiagnostic { state: Mutex::new(State::default()) };
        expiring.reserve(now);
        expiring.state.lock().unwrap().response_pairs = pairs("synthetic=value").unwrap();
        assert!(expiring.reserve(now + TTL).is_none());
        assert!(expiring.state.lock().unwrap().response_pairs.is_empty());
        assert!(pairs(&format!("synthetic={}", "x".repeat(MAX_HEADER_BYTES))).is_none());
        assert!(pairs(&vec!["synthetic=value"; MAX_PAIRS + 1].join("; ")).is_none());
        let oversized = headers("set-cookie", &[&format!("synthetic={}", "x".repeat(MAX_HEADER_BYTES))]);
        let observed = diagnostic.observe_response(now, 4, &url(), &oversized, &CookieJar::new(),
            Some(SameSiteContext::SameSite), true).unwrap();
        assert!(!observed.bounded);
        assert_eq!(observed.eligible_pair_count, None);
        assert!(diagnostic.state.lock().unwrap().response_pairs.is_empty());
    }

    #[test]
    fn sab_cookie_diagnostic_matches_only_exact_authentication_posts() {
        assert!(target("POST", &url()));
        assert!(!target("GET", &url()));
        assert!(!target("POST", &Url::parse("http://www.security.online-banking.sabbnet.com/am/json/realms/root/realms/external/authenticate").unwrap()));
        assert!(!target("POST", &Url::parse("https://www.security.online-banking.sabbnet.com.evil.invalid/am/json/realms/root/realms/external/authenticate").unwrap()));
        assert!(!target("POST", &Url::parse("https://www.security.online-banking.sabbnet.com/am/json/realms/root/realms/external/authenticate/other").unwrap()));
    }
}
