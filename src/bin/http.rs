#![cfg(feature = "http")]
use actix_web::{ web, App, HttpResponse, HttpServer, Responder };
use serde_json::json;

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

async fn newkey(state: web::Data<State>, key_gen_request: web::Json<data::KeyGenRequest>) -> Result<web::Json<data::GeneratedKey>, SSE> {
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
    let shares = match key_gen_requests.get(managed_id) {
        Some(gen) => Ok(&gen.shares),
        None => Err(SSE::ManagedKeyNotFound(managed_id.clone())),
    }?;
    let matching_shares: Vec<data::EncryptedShare> =
        shares.iter().flat_map(|(share, _confirm)| {
            // NOTE: if for some reason we can't get the recipients
            // (only reason would be failure to parse the PGP message we
            // generated ourselves), the .ok()? here will just pass over
            // that encrypted share.
            if share.recipients().ok()?.iter().any(|id| *id == *approver_id) {
                Some(share.clone())
            } else {
                None
            }
        }).collect();
    if matching_shares.is_empty() {
        Err(SSE::ApproverNotFound(approver_id.clone()))
    } else {
        Ok(web::Json(matching_shares))
    }
}

async fn showkey(state: web::Data<State>, path: web::Path<data::KeyID>) -> Result<web::Json<data::GeneratedKey>, SSE> {
    let key_gen_requests = state.key_gen_requests.lock().unwrap();
    match key_gen_requests.get(&*path) {
        Some(gen) => Ok(web::Json(gen.clone())),
        None => Err(SSE::ManagedKeyNotFound(path.clone())),
    }
}


#[actix_rt::main]
async fn main() -> std::io::Result<()> {
    let state = web::Data::new(State::default());
    HttpServer::new(move || {
        App::new()
            .app_data(state.clone())
            .service(
                web::scope("/api/keys")
                    .route("/", web::post().to(newkey))
                    .route("/", web::get().to(showkeys))
            )
            .service(
                web::scope("/api/keys/{managed_fp}/")
                    .route("/", web::get().to(showkey))
                    .route("/share/{approver_fp}", web::get().to(getshare))
                    // TODO: .route("/share/{approver_fp}/confirm", web::post().to(confirm_share))
                    // TODO: .route("/", web::put().to(updatekey))
            )
            .service(
                web::scope("/api/keys/{managed_fp}/signatures/")
                    .route("/", web::post().to(startsign))
                    .route("/", web::get().to(showsigns))
                    .route("/{hash}", web::put().to(submitshare))
                    .route("/{hash}", web::get().to(showsign))
                    // TODO: .route("/{hash}/approvers", web::get().to(showapprovers))
            )

    })
    .bind("127.0.0.1:9000")?
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

        let mut app = test::init_service(
            App::new()
                .app_data(state.clone())
                .route("/api/keys/", web::post().to(newkey))
                .route("/api/keys/", web::get().to(showkeys))
                .route("/api/keys/{managed_fp}/share/{approver_fp}", web::get().to(getshare)),
        ).await;

        let req = test::TestRequest::post()
            .uri("/api/keys/")
            .set_json(&keygen)
            .to_request();
        let resp = test::call_service(&mut app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);
        let generated: data::GeneratedKey = test::read_body_json(resp).await;
        assert_eq!(generated.shares.len(), 5);

        let req = test::TestRequest::get()
            .uri("/api/keys/")
            .to_request();
        let resp = test::call_service(&mut app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);
        let ids: Vec<data::KeyID> = test::read_body_json(resp).await;
        assert_eq!(ids.len(), 1);

        let policy = StandardPolicy::new();
        let approver_id = td.approvers_pub[0].keys()
            .with_policy(&policy, None)
            .supported().alive().revoked(false)
            .for_transport_encryption().into_iter().next().unwrap().keyid();

        let req = test::TestRequest::get()
            .uri(&format!("/api/keys/{}/share/{}", ids[0].to_hex(), approver_id.to_hex()))
            .to_request();
        let resp = test::call_service(&mut app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);
        let shares: Vec<data::EncryptedShare> = test::read_body_json(resp).await;
        assert_eq!(shares.len(), 1);
        println!("{:#?}", shares[0].0);
        let _decrypted = shares[0].clone().decrypt(&td.approvers_priv()[0]).unwrap();
    }
}
