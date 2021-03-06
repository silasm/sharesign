#![cfg(feature = "http")]
use std::fmt::Debug;
use actix_web::{ web, App, HttpResponse, HttpServer, Responder };
use actix_service::IntoServiceFactory;
use serde_json::json;
use serde::{Serialize, Deserialize};

use sharesign::data;
use sharesign::state;
use sharesign::state::{State, ID};
use sharesign::error::SharkSignError as SSE;

async fn startsign(state: web::Data<State>, submission: web::Json<data::SignRequestSubmit>) -> impl Responder {
    let id = state::get_id(&*submission);
    let sign_request = state::SignRequest::from(submission.clone());
    {
        let mut sign_requests = state.sign_requests.lock().unwrap();
        sign_requests.insert(id, sign_request);
    }
    HttpResponse::Ok().json(json!({"id": id}))
}

async fn showsigns(state: web::Data<State>) -> Result<web::Json<Vec<ID>>, SSE> {
    let sign_requests = state.sign_requests.lock().unwrap();
    Ok(web::Json(sign_requests.keys().cloned().collect()))
}

async fn submitshare(state: web::Data<State>, id: web::Path<ID>, json: web::Json<data::ShareSubmit>) -> Result<web::Json<()>, SSE> {
    let mut sign_requests = state.sign_requests.lock().unwrap();
    match sign_requests.get_mut(&*id) {
        Some(sign_request) => {
            sign_request.submit_share(json.share.clone())?;
            Ok(web::Json(()))
        },
        None => {
            Err(SSE::SignRequestNotFound(*id))
        }
    }
}

async fn showsign(state: web::Data<State>, id: web::Path<ID>) -> Result<web::Json<state::SignRequest>, SSE> {
    let sign_requests = state.sign_requests.lock().unwrap();
    match sign_requests.get(&*id) {
        Some(sign_request) => Ok(web::Json(sign_request.clone())),
        None => Err(SSE::SignRequestNotFound(*id)),
    }
}

async fn newkey(state: web::Data<State>, key_gen_request: web::Json<data::KeyGenRequest>) -> Result<web::Json<state::GeneratedKey>, SSE> {
    let share_count = key_gen_request.approvers.len();
    if share_count > 255 {
        return Err(SSE::Config("Cannot generate >255 shares".to_owned()))
    }
    else if share_count < key_gen_request.shares_required.into() {
        return Err(SSE::Config("Refusing to generate fewer shares than required to regenerate key".to_owned()))
    }
    let generated = sharesign::generate(
        &key_gen_request.approvers,
        key_gen_request.shares_required,
        &key_gen_request.key_config,
    )?;
    let id = data::KeyID(generated.pubkey.keyid());
    {
        let mut key_gen_requests = state.key_gen_requests.lock().unwrap();
        key_gen_requests.insert(id, generated.clone());
    }
    Ok(web::Json(generated))
}

async fn showkeys(state: web::Data<State>) -> Result<web::Json<Vec<data::KeyID>>, SSE> {
    let key_gen_requests = state.key_gen_requests.lock().unwrap();
    Ok(web::Json(key_gen_requests.keys().cloned().collect()))
}

async fn getshare(state: web::Data<State>, path: web::Path<(data::KeyID, data::KeyID)>) -> Result<web::Json<Vec<data::EncryptedShare>>, SSE> {
    let key_gen_requests = state.key_gen_requests.lock().unwrap();
    let (managed_id, approver_id) = &*path;
    let genkey = match key_gen_requests.get(managed_id) {
        Some(gen) => Ok(gen),
        None => Err(SSE::ManagedKeyNotFound(managed_id.clone())),
    }?;
    let matching_shares: Vec<data::EncryptedShare> =
        genkey.lookup(approver_id).iter()
            .map(|(_, share, _)| (*share).clone())
            .collect();
    if matching_shares.is_empty() {
        Err(SSE::ApproverNotFound(approver_id.clone()))
    } else {
        Ok(web::Json(matching_shares))
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ConfirmRequest {
    pub confirmation: data::Confirm
}
async fn confirm_share(state: web::Data<State>, path: web::Path<(data::KeyID, data::KeyID)>, json: web::Json<ConfirmRequest>) -> Result<web::Json<()>, SSE> {
    let mut key_gen_requests = state.key_gen_requests.lock().unwrap();
    let (managed_id, approver_id) = &*path;
    let genkey = match key_gen_requests.get_mut(managed_id) {
        Some(gen) => Ok(gen),
        None => Err(SSE::ManagedKeyNotFound(managed_id.clone())),
    }?;
    Ok(web::Json(genkey.confirm_and_remove(approver_id, &json.confirmation)?))
}

async fn showkey(state: web::Data<State>, path: web::Path<data::KeyID>) -> Result<web::Json<state::GeneratedKey>, SSE> {
    let key_gen_requests = state.key_gen_requests.lock().unwrap();
    match key_gen_requests.get(&*path) {
        Some(gen) => Ok(web::Json(gen.clone())),
        None => Err(SSE::ManagedKeyNotFound(path.clone())),
    }
}

fn app(state: web::Data<State>) -> impl actix_service::ServiceFactory<
    Config = actix_web::dev::AppConfig,
    Request = actix_http::Request,
    Error = actix_web::Error,
    InitError = (),
    Response = actix_web::dev::ServiceResponse<actix_web::dev::Body>,
>
{
    use tracing_actix_web::TracingLogger;

    App::new()
        .app_data(state.clone())
        .wrap(TracingLogger)
        .service(
            web::scope("/api/keys")
                .route("/", web::post().to(newkey))
                .route("/", web::get().to(showkeys))
                .route("/{managed_fp}/", web::get().to(showkey))
                // TODO: .route("/{managed_fp}/", web::put().to(updatekey))
                .route("/{managed_fp}/share/{approver_fp}", web::get().to(getshare))
                .route("/{managed_fp}/share/{approver_fp}/confirm", web::post().to(confirm_share))
                .route("/{managed_fp}/signatures/", web::post().to(startsign))
                .route("/{managed_fp}/signatures/", web::get().to(showsigns))
                .route("/{managed_fp}/signatures/{hash}", web::put().to(submitshare))
                .route("/{managed_fp}/signatures/{hash}", web::get().to(showsign))
                // TODO: .route("/{managed_fp}/signatures/{hash}/approvers", web::get().to(showapprovers))
        ).into_factory()
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let state = web::Data::new(State::default());

    HttpServer::new(move || {app(state.clone())})
    .bind("127.0.0.1:8080")?
    .run()
    .await
}

#[cfg(test)]
#[path = "../test_data.rs"]
mod test_data;

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{test, http};
    use sequoia_openpgp::serialize::SerializeInto;
    use sequoia_openpgp::policy::StandardPolicy;

    #[actix_rt::test]
    async fn test_generate() {
        let td = test_data::load_test_data_3_5();
        let approvers: Vec<String> = td.approvers_pub.clone().into_iter().map(|cert| {
            let vec = cert.armored().to_vec().unwrap();
            String::from_utf8(vec).unwrap()
        }).collect();
        let keygen = json!({
            "keyConfig": {
                "cipherSuite": "RSA2k",
                "subkeys": [
                    {
                        "cipherSuite": "RSA2k",
                        "flags": ["signing"],
                        "validity": "doesNotExpire",
                    }
                ],
                "flags": ["certification"],
                "validity": "doesNotExpire",
                "userid": "alice@example.org",
                "revocationKeys": [],
            },
            "approvers": approvers,
            "sharesRequired": 3,
        });
        let _deserialized: data::KeyGenRequest =
            serde_json::from_value(keygen.clone()).unwrap();

        let state = web::Data::new(State::default());
        env_logger::init_from_env(
            env_logger::Env::default().default_filter_or("info")
        );

        let mut app = test::init_service(app(state)).await;

        // generate a new key
        let generated: state::GeneratedKey = {
            let req = test::TestRequest::post()
                .uri("/api/keys/")
                .set_json(&keygen)
                .to_request();
            let resp = test::call_service(&mut app, req).await;
            assert_eq!(resp.status(), http::StatusCode::OK, "{:?}", test::read_body(resp).await);
            test::read_body_json(resp).await
        };
        assert_eq!(generated.shares.len(), 5);

        // list the generated keys
        let ids: Vec<data::KeyID> = {
            let req = test::TestRequest::get()
                .uri("/api/keys/")
                .to_request();
            let resp = test::call_service(&mut app, req).await;
            assert_eq!(resp.status(), http::StatusCode::OK, "{:?}", test::read_body(resp).await);
            test::read_body_json(resp).await
        };
        assert_eq!(ids.len(), 1);

        let privcerts = td.approvers_priv();
        let zipped = td.approvers_pub.iter().zip(privcerts.iter());
        let mut shares = Vec::<data::Share>::new();
        for (pubcert, privcert) in zipped {
            let approver_id = {
                let policy = StandardPolicy::new();
                pubcert.keys()
                    .with_policy(&policy, None)
                    .supported().alive().revoked(false)
                    .for_transport_encryption().into_iter().next().unwrap().keyid()
            };

            // get and decrypt the share corresponding to the approver
            let matching_shares: Vec<data::EncryptedShare> = {
                let req = test::TestRequest::get()
                    .uri(&format!("/api/keys/{}/share/{}", ids[0].to_hex(), approver_id.to_hex()))
                    .to_request();
                let resp = test::call_service(&mut app, req).await;
                assert_eq!(resp.status(), http::StatusCode::OK, "{:?}", test::read_body(resp).await);
                test::read_body_json(resp).await
            };
            assert_eq!(matching_shares.len(), 1);
            let decrypted = matching_shares[0].clone().decrypt(privcert).unwrap();

            // confirm receipt and decryption of the share by sending back
            // the random bytes attached to it
            {
                let confirmation = ConfirmRequest {
                    confirmation: decrypted.confirm_receipt,
                };
                let req = test::TestRequest::post()
                    .uri(&format!("/api/keys/{}/share/{}/confirm", ids[0].to_hex(), approver_id.to_hex()))
                    .set_json(&confirmation)
                    .to_request();
                let resp = test::call_service(&mut app, req).await;
                assert_eq!(resp.status(), http::StatusCode::OK, "{:?}", test::read_body(resp).await);
            }

            // share is now removed from state, so requesting it again fails
            {
                let req = test::TestRequest::get()
                    .uri(&format!("/api/keys/{}/share/{}", ids[0].to_hex(), approver_id.to_hex()))
                    .to_request();
                let resp = test::call_service(&mut app, req).await;
                assert_eq!(resp.status(), http::StatusCode::NOT_FOUND);
            }

            shares.push(decrypted.signed);
        }
    }
}
