use js_sys::Date;
use serde::Deserialize;
use serde_json::json;
use std::collections::HashMap;
use url::form_urlencoded;
use worker::*;

const MIN_SUBMIT_MS: u128 = 5000;
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

    let cors_origin = match validate_origin(&origin, &env) {
        Ok(origin) => origin,
        Err(error) => {
            log_backend_error("origin_not_allowed", &format!("{error:?}"), &env);
            return error_response("origin_not_allowed", 400, None, &env);
        }
    };

    if req.method() == Method::Options {
        return preflight_response(&cors_origin);
    }

    if req.method() != Method::Post {
        log_backend_error("method_not_allowed", "Non-POST request received.", &env);
        return error_response("method_not_allowed", 405, Some(&cors_origin), &env);
    }

    let form: ContactForm = match req.json::<ContactForm>().await {
        Ok(value) => value,
        Err(error) => {
            log_backend_error("invalid_json", &format!("{error:?}"), &env);
            return error_response("invalid_json", 400, Some(&cors_origin), &env);
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

    let secret = match env.secret("TURNSTILE_SECRET_KEY") {
        Ok(secret) => secret.to_string(),
        Err(error) => {
            log_backend_error("missing_turnstile_secret", &format!("{error:?}"), &env);
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

    let recipient = match env.secret("CONTACT_RECIPIENT") {
        Ok(secret) => secret.to_string(),
        Err(error) => {
            log_backend_error("missing_contact_recipient", &format!("{error:?}"), &env);
            return error_response("missing_contact_recipient", 500, Some(&cors_origin), &env);
        }
    };

    let from_address = match env.secret("CONTACT_FROM_ADDRESS") {
        Ok(secret) => secret.to_string(),
        Err(error) => {
            log_backend_error("missing_contact_from_address", &format!("{error:?}"), &env);
            return error_response(
                "missing_contact_from_address",
                500,
                Some(&cors_origin),
                &env,
            );
        }
    };

    let subject = "Nová poptávka z webu 1Fin";
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

fn validate_submission_timing(start_ts: Option<&str>) -> bool {
    let start_value = match start_ts.and_then(|value| value.trim().parse::<u128>().ok()) {
        Some(value) => value,
        None => return false,
    };

    let now = Date::now() as u128;
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
    env.secret(key).ok().map(|secret| secret.to_string())
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

    let allowed_origins: Vec<&str> = allowed_raw
        .split(',')
        .map(|origin| origin.trim())
        .filter(|origin| !origin.is_empty())
        .collect();

    if allowed_origins
        .iter()
        .any(|allowed| allowed.eq_ignore_ascii_case(origin.trim()))
    {
        Ok(origin.to_string())
    } else {
        Err(Error::RustError("Origin not allowed.".into()))
    }
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

async fn send_email(
    recipient: &str,
    from_address: &str,
    reply_to: &str,
    subject: &str,
    html: &str,
    env: &Env,
    cors_origin: &str,
) -> Result<Response> {
    let resend_api_key = env
        .secret("RESEND_API_KEY")
        .map_err(|_| Error::RustError("Missing Resend API key.".into()))?
        .to_string();

    let payload = json!({
        "from": from_address,
        "to": [recipient],
        "subject": subject,
        "html": html,
        "reply_to": reply_to,
    });

    let headers = Headers::new();
    headers.set("Authorization", &format!("Bearer {}", resend_api_key))?;
    headers.set("Content-Type", "application/json")?;

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

fn build_email_html(
    first_name: &str,
    last_name: &str,
    email: &str,
    phone: &str,
    interests: &[String],
    message: Option<&str>,
) -> String {
    let submitted_at = String::from(Date::new_0().to_iso_string());
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
        "<html><body><h2>Nová poptávka z webu 1Fin</h2><p><strong>Jméno:</strong> {first_name} {last_name}</p><p><strong>Email:</strong> {email}</p><p><strong>Telefon:</strong> {phone}</p><p><strong>Zájmy:</strong></p><ul>{interests}</ul><p><strong>Zpráva:</strong><br>{message}</p><p><strong>Čas odeslání:</strong> {timestamp}</p></body></html>",
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
}
