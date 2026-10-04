//! O5/O6: account security settings (console setting `security`) and
//! administrator-initiated MFA enrollment.

use super::error::{ApiError, ApiResult};
use super::openapi::{BadRequest, Forbidden, NotFound, Unauthorized};
use super::routes::UserIdPath;
use super::session::{enroll_payload, public_user, Caller};
use super::settings::SettingSource;
use super::types::{EnrollPayload, PublicUser};
use super::AppState;
use crate::auth;
use crate::model::GlobalPerm;
use crate::mutation::accounts::UserChanges;
use crate::mutation::settings::{self, SecuritySettings, SECURITY_KEY};
use axum::extract::{Path, State};
use axum::Json;
use serde::Serialize;
use std::sync::Arc;
use utoipa::ToSchema;

type St = State<Arc<AppState>>;

/// The security settings in effect.
#[derive(Debug, Serialize, ToSchema)]
pub struct SecurityView {
    pub settings: SecuritySettings,
    /// `config`: the defaults (nothing saved); `console`: saved settings.
    pub source: SettingSource,
    #[schema(required = true)]
    pub updated_by: Option<String>,
    #[schema(required = true, format = DateTime)]
    pub updated_at: Option<String>,
}

fn security_view(s: &AppState) -> ApiResult<SecurityView> {
    Ok(match settings::load_security_stored(&s.storage)? {
        Some((settings, by, at)) => SecurityView {
            settings,
            source: SettingSource::Console,
            updated_by: Some(by),
            updated_at: Some(at),
        },
        None => SecurityView {
            settings: SecuritySettings::default(),
            source: SettingSource::Config,
            updated_by: None,
            updated_at: None,
        },
    })
}

#[utoipa::path(
    get,
    path = "/settings/security",
    tag = "Users",
    operation_id = "get_security_settings",
    summary = "Account security settings (admin)",
    description = "Who may enroll MFA authenticators. Needs `manage_users`.",
    responses(
        (status = 200, description = "Settings in effect.", body = SecurityView),
        (status = 401, response = Unauthorized),
        (status = 403, response = Forbidden),
    ),
)]
pub async fn get_security(State(s): St, caller: Caller) -> ApiResult<Json<SecurityView>> {
    s.require(&caller, GlobalPerm::ManageUsers)?;
    Ok(Json(security_view(&s)?))
}

#[utoipa::path(
    put,
    path = "/settings/security",
    tag = "Users",
    operation_id = "update_security_settings",
    summary = "Change account security settings (admin)",
    description = "Saves the settings; they apply at once and replicate to standbys. Omitted fields take their defaults. Audited as `settings.security.update`. Needs `manage_users`.",
    request_body(content = SecuritySettings, example = json!({ "mfa_enrollment": "admin" })),
    responses(
        (status = 200, description = "Saved.", body = SecurityView),
        (status = 400, response = BadRequest),
        (status = 401, response = Unauthorized),
        (status = 403, response = Forbidden),
    ),
)]
pub async fn update_security(
    State(s): St,
    caller: Caller,
    Json(input): Json<SecuritySettings>,
) -> ApiResult<Json<SecurityView>> {
    s.require(&caller, GlobalPerm::ManageUsers)?;
    let next = input
        .validate()
        .map_err(|errs| ApiError::bad_request(errs.join("; ")))?;
    let before = settings::load_security_stored(&s.storage)?.map(|(v, _, _)| v);
    let actor = caller.actor();
    s.accounts.run(&actor, "update_security", |t| {
        t.set_setting(
            SECURITY_KEY,
            "settings.security.update",
            &actor.name,
            before.as_ref(),
            &next,
        )
    })?;
    Ok(Json(security_view(&s)?))
}

#[utoipa::path(
    delete,
    path = "/settings/security",
    tag = "Users",
    operation_id = "reset_security_settings",
    summary = "Use the default security settings again (admin)",
    description = "Removes the saved settings (users enroll MFA themselves). Audited as `settings.security.reset`; no-op when nothing is saved. Needs `manage_users`.",
    responses(
        (status = 200, description = "Defaults in effect.", body = SecurityView),
        (status = 401, response = Unauthorized),
        (status = 403, response = Forbidden),
    ),
)]
pub async fn reset_security(State(s): St, caller: Caller) -> ApiResult<Json<SecurityView>> {
    s.require(&caller, GlobalPerm::ManageUsers)?;
    if let Some((before, _, _)) = settings::load_security_stored(&s.storage)? {
        let actor = caller.actor();
        s.accounts.run(&actor, "reset_security", |t| {
            t.clear_setting(SECURITY_KEY, "settings.security.reset", &before)
        })?;
    }
    Ok(Json(security_view(&s)?))
}

/// The new authenticator of a user, shown once.
#[derive(Debug, Serialize, ToSchema)]
pub struct AdminEnrollment {
    pub user: PublicUser,
    /// Hand the QR code (or the `otpauth://` link, or the secret) to the
    /// user out of band. It is not shown again.
    pub enroll: EnrollPayload,
}

#[utoipa::path(
    post,
    path = "/users/{id}/mfa/enroll",
    tag = "Users",
    operation_id = "admin_enroll_mfa",
    summary = "Enroll an authenticator for a user (admin)",
    description = "Generates a new TOTP secret for the user, makes MFA required and enrolled with it, removes their recovery codes and signs them out everywhere. The response holds the QR code, `otpauth://` link and secret: shown only this once, deliver it to the user out of band. The secret replicates to standbys like any enrollment; it is never logged or audited (the audit entry `mfa.admin_enroll` names the user only). Replaces an enrolled authenticator. Needs `manage_users`; only root may do this for root.",
    params(UserIdPath),
    responses(
        (status = 200, description = "Enrolled. The secret is in the response only.", body = AdminEnrollment),
        (status = 400, response = BadRequest),
        (status = 401, response = Unauthorized),
        (status = 403, response = Forbidden),
        (status = 404, response = NotFound),
    ),
)]
pub async fn admin_enroll(
    State(s): St,
    caller: Caller,
    Path(UserIdPath { id }): Path<UserIdPath>,
) -> ApiResult<Json<AdminEnrollment>> {
    s.require(&caller, GlobalPerm::ManageUsers)?;
    let user = s
        .storage
        .get_user(id)?
        .ok_or_else(|| ApiError::not_found("user not found"))?;
    if user.is_root && !caller.user.is_root {
        return Err(ApiError::forbidden("only root may modify the root account"));
    }
    let secret = auth::totp_new_secret();
    let u = s.accounts.run(&caller.actor(), "admin_enroll_mfa", |t| {
        let u = t.change_user(
            user.id,
            &UserChanges {
                mfa_required: Some(true),
                ..UserChanges::default()
            },
        )?;
        let u = t.set_mfa(u.id, Some(&secret))?;
        t.set_recovery_codes(&u, &[])?;
        t.delete_user_sessions(&u, "MFA enrolled by an administrator")?;
        t.note_admin_enrollment(&u);
        Ok(u)
    })?;
    tracing::info!(user = %u.username, by = %caller.user.username, "MFA enrolled by an administrator");
    Ok(Json(AdminEnrollment {
        enroll: enroll_payload(&u, &secret),
        user: public_user(&u),
    }))
}
