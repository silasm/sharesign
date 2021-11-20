use std::collections::hash_map::DefaultHasher;
use std::convert::TryInto;
use std::hash::{Hash, Hasher};
use std::sync::Mutex;
use std::collections::HashMap;
use actix_web::{ http, web, App, HttpResponse, HttpServer, Responder };
use actix_rt;
// use json;
use serde_json::json;

mod sharksign;
use sharksign::data;
use sharksign::error;

struct State {
    sign_requests: Mutex<HashMap<ID, data::SignRequest>>,
    key_gen_requests: Mutex<HashMap<ID, data::KeyShares>>
}

type ID = u64;

fn get_id<T: Hash>(input: &T) -> ID{
    let mut s = DefaultHasher::new();
    input.hash(&mut s);
    // TODO: add random value here
    s.finish()
}

async fn startsign(state: web::Data<State>, submission: web::Json<data::SignRequestSubmit>) -> impl Responder {
    let id = get_id(&*submission);
    let sign_request = data::SignRequest::new(
        &submission.payload,
        submission.key_config.clone(),
        None
    );
    {
        let mut sign_requests = state.sign_requests.lock().unwrap();
        sign_requests.insert(id, sign_request);
    }
    HttpResponse::Ok().json(json!({"id": id}))
}

async fn showsigns(state: web::Data<State>) -> impl Responder {
    let mut signs: Vec<ID> = Vec::new();
    {
        let sign_requests = state.sign_requests.lock().unwrap();
        for (id, _sign_request) in &*sign_requests {
            signs.push(*id);
        }
    }
    HttpResponse::Ok().json(signs)
}

async fn submitshare(state: web::Data<State>, id: web::Path<ID>, share: web::Json<data::Share>) -> impl Responder {
    let mut sign_requests = state.sign_requests.lock().unwrap();
    match sign_requests.get_mut(&*id) {
        Some(sign_request) => {
            // TODO: any validation of the submitted share happens here
            sign_request.submit_share((*share).clone());
            (
                Ok(web::Json(())),
                http::StatusCode::OK,
            )
        },
        None => (
            Err(error::SharkSignError::from(format!("sign request with id {} not found", id))),
            http::StatusCode::NOT_FOUND,
        )
    }
}

async fn showsign(state: web::Data<State>, id: web::Path<ID>) -> impl Responder {
    let sign_requests = state.sign_requests.lock().unwrap();
    match sign_requests.get(&*id) {
        Some(sign_request) => (
            Ok(web::Json(sign_request.clone())),
            http::StatusCode::OK,
        ),
        None => (
            Err(error::SharkSignError::from(format!("sign request with id {} not found", id))),
            http::StatusCode::NOT_FOUND,
        )
    }
}

async fn showshares(_path: web::Path<(data::KeyRef, data::HashDigest)>) -> impl Responder {
    HttpResponse::Ok().json(())
}

async fn newkey(state: web::Data<State>, key_gen_request: web::Json<data::KeyGenRequest>) -> Result<HttpResponse, error::SharkSignError> {
    let shares = sharksign::generate(
        key_gen_request.shares_required.into(),
        key_gen_request.approvers.len().try_into().expect("cannot handle >255 approvers"),
        &key_gen_request.key_config,
    )?;
    let mut encrypted_shares = data::KeyShares::new();
    for (pubkey, share) in key_gen_request.approvers.iter().zip(shares.iter()) {
        encrypted_shares.push(sharksign::encrypt(pubkey.clone(), &share.data).unwrap());
    }
    let id = get_id(&*key_gen_request);
    {
        let mut key_gen_requests = state.key_gen_requests.lock().unwrap();
        key_gen_requests.insert(id, encrypted_shares);
    }
    Ok(HttpResponse::Ok().json(json!({"id": id})))
}

async fn showkeys() -> impl Responder {
    HttpResponse::Ok().json(())
}

async fn updatekey(_path: web::Path<data::KeyRef>) -> impl Responder {
    HttpResponse::Ok().json(())
}

async fn showkey(_path: web::Path<data::KeyRef>) -> impl Responder {
    HttpResponse::Ok().json(())
}


#[actix_rt::main]
async fn main() -> std::io::Result<()> {
    let state = web::Data::new(State {
        sign_requests: Mutex::new(HashMap::<ID, data::SignRequest>::new()),
        key_gen_requests: Mutex::new(HashMap::<ID, data::KeyShares>::new()),
    });
    HttpServer::new(move || {
        App::new()
            .app_data(state.clone())
            .service(
                web::scope("/api/keys")
                    .route("/", web::post().to(newkey))
                    .route("/", web::get().to(showkeys))
                    .route("/{keyref}", web::put().to(updatekey))
                    .route("/{keyref}", web::get().to(showkey))
            )
            .service(
                web::scope("/api/keys/{keyref}/signatures/")
                    .route("/", web::post().to(startsign))
                    .route("/", web::get().to(showsigns))
                    .route("/{hash}", web::put().to(submitshare))
                    .route("/{hash}", web::get().to(showsign))
                    .route("/{hash}/shares", web::get().to(showshares))
            )

    })
    .bind("127.0.0.1:9000")?
    .run()
    .await
}
