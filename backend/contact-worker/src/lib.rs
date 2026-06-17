use serde::Deserialize;
use serde_json::json;
use std::collections::{HashMap, HashSet};
use url::form_urlencoded;
use worker::*;

const MIN_SUBMIT_MS: u64 = 5000;
const RESEND_API_URL: &str = "https://api.resend.com/emails";
const MAX_NAME_LENGTH: usize = 100;
const MAX_EMAIL_LENGTH: usize = 254;
const MAX_PHONE_LENGTH: usize = 40;
const MAX_MESSAGE_LENGTH: usize = 2000;

#[derive(Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
struct ContactForm {
    first_name: String,
    last_name: String,
    email: String,
    phone: String,
    message: Option<String>,
    interests: Option<Vec<String>>,
    consent: bool,
    form_start_ts: Option<String>,
    honeypot: Option<String>,
    turnstile_token: String,
}

#[derive(Deserialize)]
struct TurnstileVerifyResponse {
    success: bool,
    hostname: Option<String>,
    #[serde(default)]
    error_codes: Vec<String>,
}

#[event(fetch)]
pub async fn main(mut req: Request, env: Env, _ctx: Context) -> Result<Response> {
    let origin = req
        .headers()
        .get("Origin")
        .unwrap_or_else(|_| None)
        .unwrap_or_default();

    if req.method() == Method::Options {
        let cors_origin = match validate_origin(&origin, &env) {
            Ok(origin) => origin,
            Err(error) => {
                log_backend_error("origin_not_allowed", &format!("{error:?}"), &env);
                return error_response("origin_not_allowed", 400, None, &env);
            }
        };

        return preflight_response(&cors_origin);
    }

    let cors_origin = match validate_origin(&origin, &env) {
        Ok(origin) => origin,
        Err(error) => {
            log_backend_error("origin_not_allowed", &format!("{error:?}"), &env);
            return error_response("origin_not_allowed", 400, None, &env);
        }
    };

    if req.method() != Method::Post {
        log_backend_error("method_not_allowed", "Non-POST request received.", &env);
        return error_response("method_not_allowed", 405, Some(&cors_origin), &env);
    }

    let form = match parse_contact_form(&mut req).await {
        Ok(value) => value,
        Err(error) => {
            log_backend_error("invalid_request_body", &format!("{error:?}"), &env);
            return error_response("invalid_request_body", 400, Some(&cors_origin), &env);
        }
    };

    if form
        .honeypot
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .is_some()
    {
        log_backend_error("honeypot_filled", "Honeypot field was not empty.", &env);
        return error_response("invalid_submission", 400, Some(&cors_origin), &env);
    }

    if !form.consent {
        log_backend_error(
            "missing_consent",
            "Consent checkbox was not accepted.",
            &env,
        );
        return error_response("missing_consent", 400, Some(&cors_origin), &env);
    }

    if !validate_submission_timing(form.form_start_ts.as_deref()) {
        log_backend_error(
            "invalid_submission_timing",
            "Form timing check failed.",
            &env,
        );
        return error_response("invalid_submission_timing", 400, Some(&cors_origin), &env);
    }

    let first_name = normalize_text(&form.first_name, MAX_NAME_LENGTH);
    let last_name = normalize_text(&form.last_name, MAX_NAME_LENGTH);
    let email = form.email.trim();
    let phone = normalize_text(&form.phone, MAX_PHONE_LENGTH);
    let message = form
        .message
        .as_deref()
        .map(|value| normalize_text(value, MAX_MESSAGE_LENGTH))
        .filter(|value| !value.is_empty());
    let interests = form.interests.unwrap_or_default();

    if first_name.is_empty() || last_name.is_empty() {
        log_backend_error("invalid_name", "Required name field was empty.", &env);
        return error_response("invalid_name", 400, Some(&cors_origin), &env);
    }

    if !validate_email(email) {
        log_backend_error("invalid_email", "Email validation failed.", &env);
        return error_response("invalid_email", 400, Some(&cors_origin), &env);
    }

    if phone.is_empty() || !validate_phone(&phone) {
        log_backend_error("invalid_phone", "Phone validation failed.", &env);
        return error_response("invalid_phone", 400, Some(&cors_origin), &env);
    }

    let selected_interests = match validate_interests(&interests) {
        Some(items) => items,
        None => {
            log_backend_error(
                "invalid_interests",
                "Unknown interest value received.",
                &env,
            );
            return error_response("invalid_interests", 400, Some(&cors_origin), &env);
        }
    };

    let turnstile_token = form.turnstile_token.trim();
    if turnstile_token.is_empty() {
        log_backend_error(
            "missing_turnstile_token",
            "Turnstile token was empty.",
            &env,
        );
        return error_response("missing_turnstile_token", 400, Some(&cors_origin), &env);
    }

    let secret = match get_secret(&env, "TURNSTILE_SECRET_KEY") {
        Some(secret) => secret,
        None => {
            log_backend_error("missing_turnstile_secret", "Missing secret.", &env);
            return error_response("missing_turnstile_secret", 500, Some(&cors_origin), &env);
        }
    };

    let hostname = match verify_turnstile(turnstile_token, &secret).await {
        Ok(hostname) => hostname,
        Err(error) => {
            log_backend_error("turnstile_verification_failed", &format!("{error:?}"), &env);
            return error_response(
                "turnstile_verification_failed",
                400,
                Some(&cors_origin),
                &env,
            );
        }
    };

    if let Err(error) = validate_turnstile_hostname(&hostname, &env) {
        log_backend_error(
            "turnstile_hostname_rejected",
            &format!("{error:?}; hostname={hostname}"),
            &env,
        );
        return error_response("turnstile_hostname_rejected", 400, Some(&cors_origin), &env);
    }

    let recipient = match get_secret(&env, "CONTACT_RECIPIENT") {
        Some(secret) => secret,
        None => {
            log_backend_error("missing_contact_recipient", "Missing secret.", &env);
            return error_response("missing_contact_recipient", 500, Some(&cors_origin), &env);
        }
    };

    let from_address = match get_secret(&env, "CONTACT_FROM_ADDRESS") {
        Some(secret) => secret,
        None => {
            log_backend_error("missing_contact_from_address", "Missing secret.", &env);
            return error_response(
                "missing_contact_from_address",
                500,
                Some(&cors_origin),
                &env,
            );
        }
    };

    let subject = "Nova poptavka z webu 1Fin";
    let email_html = build_email_html(
        &first_name,
        &last_name,
        email,
        &phone,
        &selected_interests,
        message.as_deref(),
    );

    match send_email(
        &recipient,
        &from_address,
        email,
        subject,
        &email_html,
        &env,
        &cors_origin,
    )
    .await
    {
        Ok(response) => Ok(response),
        Err(error) => {
            log_backend_error("resend_send_failed", &format!("{error:?}"), &env);
            error_response("resend_send_failed", 502, Some(&cors_origin), &env)
        }
    }
}

async fn parse_contact_form(req: &mut Request) -> Result<ContactForm> {
    let content_type = req
        .headers()
        .get("Content-Type")?
        .unwrap_or_default()
        .to_ascii_lowercase();

    if content_type.starts_with("application/x-www-form-urlencoded") {
        parse_urlencoded_form(&req.text().await?)
    } else {
        req.json::<ContactForm>().await
    }
}

fn parse_urlencoded_form(body: &str) -> Result<ContactForm> {
    let allowed_keys = HashSet::from([
        "first_name",
        "last_name",
        "email",
        "phone",
        "message",
        "interests",
        "consent",
        "form_start_ts",
        "honeypot",
        "turnstile_token",
        "cf-turnstile-response",
    ]);
    let mut values: HashMap<String, Vec<String>> = HashMap::new();

    for (key, value) in form_urlencoded::parse(body.as_bytes()) {
        if !allowed_keys.contains(key.as_ref()) {
            return Err(Error::RustError(format!("Unexpected form field: {key}")));
        }
        values
            .entry(key.into_owned())
            .or_default()
            .push(value.into_owned());
    }

    let first_name = required_single(&values, "first_name")?;
    let last_name = required_single(&values, "last_name")?;
    let email = required_single(&values, "email")?;
    let phone = required_single(&values, "phone")?;
    let turnstile_token = match optional_single(&values, "turnstile_token")? {
        Some(value) => value,
        None => optional_single(&values, "cf-turnstile-response")?
            .ok_or_else(|| Error::RustError("Missing Turnstile token.".into()))?,
    };

    Ok(ContactForm {
        first_name,
        last_name,
        email,
        phone,
        message: optional_single(&values, "message")?,
        interests: values.get("interests").cloned(),
        consent: optional_single(&values, "consent")?
            .map(|value| matches!(value.as_str(), "on" | "true" | "1" | "yes"))
            .unwrap_or(false),
        form_start_ts: optional_single(&values, "form_start_ts")?,
        honeypot: optional_single(&values, "honeypot")?,
        turnstile_token,
    })
}

fn required_single(values: &HashMap<String, Vec<String>>, key: &str) -> Result<String> {
    optional_single(values, key)?.ok_or_else(|| Error::RustError(format!("Missing field: {key}")))
}

fn optional_single(values: &HashMap<String, Vec<String>>, key: &str) -> Result<Option<String>> {
    match values.get(key).map(Vec::as_slice) {
        None | Some([]) => Ok(None),
        Some([value]) => Ok(Some(value.clone())),
        Some(_) => Err(Error::RustError(format!("Duplicate field: {key}"))),
    }
}

fn validate_submission_timing(start_ts: Option<&str>) -> bool {
    let start_value = match start_ts.and_then(|value| value.trim().parse::<u64>().ok()) {
        Some(value) => value,
        None => return false,
    };

    let now = Date::now().as_millis();
    if start_value == 0 || start_value > now {
        return false;
    }

    now.saturating_sub(start_value) >= MIN_SUBMIT_MS
}

fn normalize_text(value: &str, max_len: usize) -> String {
    let normalized = value
        .trim()
        .split_whitespace()
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join(" ");

    if normalized.len() > max_len {
        normalized.chars().take(max_len).collect()
    } else {
        normalized
    }
}

fn validate_email(value: &str) -> bool {
    let email = value.trim();
    if email.is_empty()
        || email.len() > MAX_EMAIL_LENGTH
        || email.contains(char::is_control)
        || email.contains(' ')
    {
        return false;
    }

    let parts: Vec<&str> = email.split('@').collect();
    if parts.len() != 2 {
        return false;
    }

    let local = parts[0];
    let domain = parts[1];
    if local.is_empty() || domain.len() < 3 || !domain.contains('.') {
        return false;
    }

    if domain.starts_with('.') || domain.ends_with('.') {
        return false;
    }

    true
}

fn validate_phone(value: &str) -> bool {
    let phone = value.trim();
    if phone.is_empty() || phone.len() > MAX_PHONE_LENGTH {
        return false;
    }

    phone.chars().all(|c| {
        !c.is_control() && !matches!(c, '<' | '>' | '{' | '}' | '[' | ']' | '\\' | '^' | '`')
    })
}

fn validate_interests(interests: &[String]) -> Option<Vec<String>> {
    let allowed = allowed_interest_map();
    let mut selected = Vec::new();

    for interest in interests.iter() {
        if let Some(label) = allowed.get(interest.as_str()) {
            selected.push(label.to_string());
        } else {
            return None;
        }
    }

    Some(selected)
}

fn allowed_interest_map() -> HashMap<&'static str, &'static str> {
    HashMap::from([
        ("travel_insurance", "Travel insurance"),
        (
            "property_liability_insurance",
            "Property and liability insurance",
        ),
        ("business_insurance", "Business insurance"),
        ("life_accident_insurance", "Life and accident insurance"),
        ("investments_dip", "Investments and DIP"),
        ("pension_savings", "Pension savings"),
        ("mortgages_housing_finance", "Mortgages and housing finance"),
        ("personal_finance_audit", "Personal finance audit"),
        ("financial_planning", "Comprehensive financial planning"),
    ])
}

async fn verify_turnstile(token: &str, secret: &str) -> Result<String> {
    let body = form_urlencoded::Serializer::new(String::new())
        .append_pair("secret", secret)
        .append_pair("response", token)
        .finish();

    let headers = Headers::new();
    headers.set("Content-Type", "application/x-www-form-urlencoded")?;

    let verify_request = Request::new_with_init(
        "https://challenges.cloudflare.com/turnstile/v0/siteverify",
        &RequestInit {
            body: Some(body.into()),
            method: Method::Post,
            headers,
            ..Default::default()
        },
    )?;

    let mut verify_response = Fetch::Request(verify_request).send().await?;
    let verify_json: TurnstileVerifyResponse = verify_response
        .json()
        .await
        .map_err(|_| Error::RustError("Unable to parse Turnstile validation response.".into()))?;

    if !verify_json.success {
        return Err(Error::RustError(format!(
            "Turnstile challenge failed: {}",
            verify_json.error_codes.join(",")
        )));
    }

    verify_json
        .hostname
        .ok_or_else(|| Error::RustError("Turnstile hostname missing.".into()))
}

fn get_secret(env: &Env, key: &str) -> Option<String> {
    env.secret(key)
        .map(|secret| secret.to_string())
        .or_else(|_| env.var(key).map(|var| var.to_string()))
        .ok()
}

fn validate_turnstile_hostname(hostname: &str, env: &Env) -> Result<()> {
    let expected = get_secret(env, "EXPECTED_TURNSTILE_HOSTNAMES").ok_or_else(|| {
        Error::RustError("Missing expected Turnstile hostnames configuration.".into())
    })?;
    let expected_hosts: Vec<&str> = expected
        .split(',')
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .collect();

    if expected_hosts
        .iter()
        .any(|allowed| allowed.eq_ignore_ascii_case(hostname.trim()))
    {
        Ok(())
    } else {
        Err(Error::RustError("Unexpected Turnstile hostname.".into()))
    }
}

fn validate_origin(origin: &str, env: &Env) -> Result<String> {
    let allowed_raw = get_secret(env, "ALLOWED_ORIGINS")
        .ok_or_else(|| Error::RustError("Missing allowed origins configuration.".into()))?;

    let allowed_origins = parse_allowed_origins(&allowed_raw);
    log_origin_check(origin, &allowed_origins, env);

    if allowed_origins.iter().any(|allowed| allowed == origin) {
        Ok(origin.to_string())
    } else {
        Err(Error::RustError("Origin not allowed.".into()))
    }
}

fn parse_allowed_origins(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(clean_origin_entry)
        .filter(|origin| !origin.is_empty())
        .collect()
}

fn clean_origin_entry(origin: &str) -> String {
    origin
        .trim()
        .trim_matches(|value| value == '"' || value == '\'')
        .trim()
        .to_string()
}

fn preflight_response(cors_origin: &str) -> Result<Response> {
    let mut response = Response::empty()?.with_status(204);
    add_cors_headers(&mut response, cors_origin)?;
    response
        .headers_mut()
        .set("Access-Control-Allow-Methods", "POST, OPTIONS")?;
    response
        .headers_mut()
        .set("Access-Control-Allow-Headers", "Content-Type")?;
    response
        .headers_mut()
        .set("Access-Control-Max-Age", "86400")?;
    Ok(response)
}

fn error_response(
    code: &'static str,
    status: u16,
    cors_origin: Option<&str>,
    env: &Env,
) -> Result<Response> {
    let body = json!({
        "error": if is_development(env) {
            code
        } else {
            "Unable to send your request. Please try again later."
        },
        "code": if is_development(env) {
            code
        } else {
            "contact_submission_failed"
        },
    });
    let mut response = Response::from_json(&body)?.with_status(status);

    if let Some(origin) = cors_origin {
        add_cors_headers(&mut response, origin)?;
    }

    Ok(response)
}

fn add_cors_headers(response: &mut Response, origin: &str) -> Result<()> {
    response
        .headers_mut()
        .set("Access-Control-Allow-Origin", origin)?;
    response.headers_mut().set("Vary", "Origin")?;
    Ok(())
}

fn is_development(env: &Env) -> bool {
    env.var("ENVIRONMENT")
        .map(|value| value.to_string().eq_ignore_ascii_case("development"))
        .unwrap_or(false)
}

fn log_backend_error(code: &'static str, detail: &str, env: &Env) {
    console_log!(
        "{}",
        json!({
            "level": "error",
            "component": "contact-worker",
            "environment": if is_development(env) { "development" } else { "production" },
            "code": code,
            "detail": detail,
        })
        .to_string()
    );
}

fn log_origin_check(origin: &str, allowed_origins: &[String], env: &Env) {
    console_log!(
        "{}",
        json!({
            "level": "info",
            "component": "contact-worker",
            "environment": if is_development(env) { "development" } else { "production" },
            "code": "cors_origin_check",
            "incoming_origin": origin,
            "parsed_allowed_origins": allowed_origins,
        })
        .to_string()
    );
}

async fn send_email(
    recipient: &str,
    from_address: &str,
    reply_to: &str,
    subject: &str,
    html: &str,
    env: &Env,
    cors_origin: &str,
) -> Result<Response> {
    let resend_api_key = match get_resend_api_key(env) {
        ResendApiKeyConfig::Ready(key) => key,
        ResendApiKeyConfig::Missing => {
            log_resend_request_config(false, 0, false, env);
            log_backend_error("missing_resend_api_key", "Missing Resend API key.", env);
            return error_response("missing_resend_api_key", 500, Some(cors_origin), env);
        }
        ResendApiKeyConfig::Empty => {
            log_resend_request_config(true, 0, false, env);
            log_backend_error("empty_resend_api_key", "Resend API key was empty.", env);
            return error_response("empty_resend_api_key", 500, Some(cors_origin), env);
        }
    };

    let payload = json!({
        "from": from_address,
        "to": [recipient],
        "subject": subject,
        "html": html,
        "reply_to": reply_to,
    });

    let headers = Headers::new();
    headers.set("Authorization", &format!("Bearer {resend_api_key}"))?;
    headers.set("Content-Type", "application/json")?;
    log_resend_request_config(true, resend_api_key.len(), true, env);

    let request = Request::new_with_init(
        RESEND_API_URL,
        &RequestInit {
            body: Some(payload.to_string().into()),
            method: Method::Post,
            headers,
            ..Default::default()
        },
    )?;

    let response = Fetch::Request(request)
        .send()
        .await
        .map_err(|_| Error::RustError("Unable to send email with Resend.".into()))?;

    if !(200..=299).contains(&response.status_code()) {
        log_backend_error(
            "resend_api_error",
            &format!("Resend API returned status {}.", response.status_code()),
            env,
        );
        return Err(Error::RustError("Resend API returned an error.".into()));
    }

    let body = json!({"status": "ok", "message": "Request sent."});
    let mut response = Response::from_json(&body)?.with_status(200);
    add_cors_headers(&mut response, cors_origin)?;
    Ok(response)
}

enum ResendApiKeyConfig {
    Ready(String),
    Missing,
    Empty,
}

fn get_resend_api_key(env: &Env) -> ResendApiKeyConfig {
    match env.secret("RESEND_API_KEY") {
        Ok(secret) => {
            let key = clean_secret_value(&secret.to_string());
            if key.is_empty() {
                ResendApiKeyConfig::Empty
            } else {
                ResendApiKeyConfig::Ready(key)
            }
        }
        Err(_) => ResendApiKeyConfig::Missing,
    }
}

fn clean_secret_value(value: &str) -> String {
    value
        .trim()
        .trim_matches(|character| {
            character == '"' || character == '\'' || character == '<' || character == '>'
        })
        .trim()
        .to_string()
}

fn log_resend_request_config(
    resend_api_key_exists: bool,
    resend_api_key_length: usize,
    authorization_header_added: bool,
    env: &Env,
) {
    console_log!(
        "{}",
        json!({
            "level": "info",
            "component": "contact-worker",
            "environment": if is_development(env) { "development" } else { "production" },
            "code": "resend_request_config",
            "resend_api_key_exists": resend_api_key_exists,
            "resend_api_key_length": resend_api_key_length,
            "authorization_header_added": authorization_header_added,
            "resend_endpoint": RESEND_API_URL,
        })
        .to_string()
    );
}

fn build_email_html(
    first_name: &str,
    last_name: &str,
    email: &str,
    phone: &str,
    interests: &[String],
    message: Option<&str>,
) -> String {
    let submitted_at = Date::now().to_string();
    let interests_html = if interests.is_empty() {
        "<li>No selected interests.</li>".to_string()
    } else {
        interests
            .iter()
            .map(|interest| format!("<li>{}</li>", html_escape(interest)))
            .collect::<Vec<_>>()
            .join("")
    };

    let message_text = message
        .map(html_escape)
        .unwrap_or_else(|| "(No message provided)".to_string());

    format!(
        "<html><body><h2>Nova poptavka z webu 1Fin</h2><p><strong>Jmeno:</strong> {first_name} {last_name}</p><p><strong>Email:</strong> {email}</p><p><strong>Telefon:</strong> {phone}</p><p><strong>Zajmy:</strong></p><ul>{interests}</ul><p><strong>Zprava:</strong><br>{message}</p><p><strong>Cas odeslani:</strong> {timestamp}</p></body></html>",
        first_name = html_escape(first_name),
        last_name = html_escape(last_name),
        email = html_escape(email),
        phone = html_escape(phone),
        interests = interests_html,
        message = message_text,
        timestamp = html_escape(&submitted_at),
    )
}

fn html_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_trims_whitespace_and_limits_length() {
        assert_eq!(normalize_text("  Alice    Bob  ", 100), "Alice Bob");
        assert_eq!(normalize_text("x ".repeat(100).as_str(), 20).len(), 20);
    }

    #[test]
    fn email_validation_rejects_invalid_inputs() {
        assert!(validate_email("test@example.com"));
        assert!(!validate_email("bad email@example.com"));
        assert!(!validate_email("missing-at.com"));
        assert!(!validate_email("user@.com"));
    }

    #[test]
    fn phone_validation_rejects_controls_and_long_values() {
        assert!(validate_phone("+420 123 456 789"));
        assert!(!validate_phone(""));
        assert!(!validate_phone(&"1".repeat(MAX_PHONE_LENGTH + 1)));
        assert!(!validate_phone("123<456"));
    }

    #[test]
    fn allowed_origins_parser_splits_trims_quotes_and_ignores_empty_entries() {
        assert_eq!(
            parse_allowed_origins(r#" "https://jiribarta.github.io" , , 'https://www.1fin.cz' ,"#),
            vec![
                "https://jiribarta.github.io".to_string(),
                "https://www.1fin.cz".to_string(),
            ]
        );
    }

    #[test]
    fn allowed_origins_parser_handles_whole_list_wrapped_in_quotes() {
        assert_eq!(
            parse_allowed_origins(r#""https://jiribarta.github.io,https://www.1fin.cz""#),
            vec![
                "https://jiribarta.github.io".to_string(),
                "https://www.1fin.cz".to_string(),
            ]
        );
    }

    #[test]
    fn clean_secret_value_trims_whitespace_quotes_and_angle_brackets() {
        assert_eq!(clean_secret_value("  \"re_123\"  "), "re_123");
        assert_eq!(clean_secret_value("  <re_123>  "), "re_123");
    }

    #[test]
    fn clean_secret_value_can_be_empty_after_trimming() {
        assert_eq!(clean_secret_value("  \"\"  "), "");
        assert_eq!(clean_secret_value("  <>  "), "");
    }
}
