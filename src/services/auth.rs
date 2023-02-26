use crate::{AppState, TokenClaims};
use actix_web::{
    get, post, put,
    web::{Data, Json},
    HttpResponse, Responder,
};
use actix_web_httpauth::extractors::basic::BasicAuth;
use argonautica::{Hasher, Verifier};
use hmac::{Hmac, Mac};
use jwt::SignWithKey;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use sqlx::{self, FromRow};
use mail_send::{mail_builder::MessageBuilder, SmtpClientBuilder};
use uuid::Uuid;

#[derive(Deserialize)]
struct RegisterUserBody {
    email: String,
    password: String,
}

#[derive(Serialize, FromRow)]
struct UserNoPassword {
    id: i32,
    email: String,
}

#[derive(Serialize, FromRow)]
struct AuthUser {
    id: i32,
    email: String,
    password: String,
}

#[derive(Deserialize)]
struct ForgotPasswordBody {
    email: String,
}

#[derive(Serialize, FromRow)]
struct UserResetPassword {
    id: i32,
    email: String,
    reset_password_uuid: String,
}

#[post("/register")]
async fn register_user(state: Data<AppState>, body: Json<RegisterUserBody>) -> impl Responder {
    let user: RegisterUserBody = body.into_inner();

    let hash_secret = std::env::var("HASH_SECRET").expect("HASH_SECRET must be set!");
    let mut hasher = Hasher::default();
    let hash = hasher
        .with_password(user.password)
        .with_secret_key(hash_secret)
        .hash()
        .unwrap();

    match sqlx::query_as::<_, UserNoPassword>(
        "INSERT INTO users (email, password)
        VALUES ($1, $2)
        RETURNING id, email",
    )
    .bind(user.email)
    .bind(hash)
    .fetch_one(&state.db)
    .await
    {
        Ok(user) => HttpResponse::Ok().json(user),
        Err(error) => HttpResponse::InternalServerError().json(format!("{:?}", error)),
    }
}

#[get("/auth")]
async fn basic_auth(state: Data<AppState>, credentials: BasicAuth) -> impl Responder {
    let jwt_secret: Hmac<Sha256> = Hmac::new_from_slice(
        std::env::var("JWT_SECRET")
            .expect("JWT_SECRET must be set!")
            .as_bytes(),
    )
    .unwrap();
    let email = credentials.user_id();
    let password = credentials.password();
    match password {
        None => HttpResponse::Unauthorized().json("Must provide email and password"),
        Some(pass) => {
            match sqlx::query_as::<_, AuthUser>(
                "SELECT id, email, password FROM users WHERE email = $1",
            )
            .bind(email.to_string())
            .fetch_one(&state.db)
            .await
            {
                Ok(user) => {
                    let hash_secret =
                        std::env::var("HASH_SECRET").expect("HASH_SECRET must be set!");
                    let mut verifier = Verifier::default();
                    let is_valid = verifier
                        .with_hash(user.password)
                        .with_password(pass)
                        .with_secret_key(hash_secret)
                        .verify()
                        .unwrap();

                    if is_valid {
                        let claims = TokenClaims { id: user.id };
                        let token_str = claims.sign_with_key(&jwt_secret).unwrap();
                        HttpResponse::Ok().json(token_str)
                    } else {
                        HttpResponse::Unauthorized().json("Incorrect email or password")
                    }
                }
                Err(error) => HttpResponse::InternalServerError().json(format!("{:?}", error)),
            }
        }
    }
}

// WIP
#[put("/forgot-password")]
async fn forgot_password(state: Data<AppState>, body: Json<ForgotPasswordBody>) -> impl Responder {
    let params: ForgotPasswordBody = body.into_inner();
    match sqlx::query_as::<_, UserNoPassword>(
        "SELECT id, email
        FROM users
        WHERE email = $1",
    )
    .bind(params.email)
    .fetch_one(&state.db)
    .await
    {
        Ok(user) => {
            let _unique_id: Uuid = Uuid::new_v4();

            match sqlx::query_as::<_, UserResetPassword>(
                "UPDATE users
                SET reset_password_uuid = uuid_generate_v4(), reset_password_requested_at = NOW()
                WHERE id = $1
                RETURNING id, email, reset_password_uuid::text"
            )
            // .bind(format!("{}", unique_id))
            .bind(user.id)
            .fetch_one(&state.db)
            .await
            {
                Ok(user) => {

                    let message = MessageBuilder::new()
                        .from(("DoNotReply", "letteney.rory@outlook.com"))
                        .to(user.email)
                        .subject("Reset Password")
                        .html_body(format!("<a href=\"https://fraapp.com/reset-password?id={}\">https://fraapp.com/reset-password?id={}</a>", user.reset_password_uuid, user.reset_password_uuid));

                    // Connect to the SMTP submissions port, upgrade to TLS and
                    // authenticate using the provided credentials.
                    SmtpClientBuilder::new("mail.live.com", 587)
                        .connect()
                        .await
                        .unwrap()
                        .send(message)
                        .await
                        .unwrap();
                        
                    HttpResponse::Ok().json("Email to reset password has been sent.")
                },
                Err(error) => HttpResponse::InternalServerError().json(format!("{:?}", error))
            }
        },
        Err(_error) => HttpResponse::NotFound().json("User not found."),
    }
}