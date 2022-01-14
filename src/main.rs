use actix_web::{ http, web, App, HttpResponse, HttpServer, Responder };
use serde_json::json;

mod sharksign;
use sharksign::data;
use sharksign::error;
use sharksign::state;
use sharksign::state::{State, ID};

async fn startsign(state: web::Data<State>, submission: web::Json<data::SignRequestSubmit>) -> impl Responder {
    let id = state::get_id(&*submission);
    let mut sign_request = state::SignRequest::new(
        &submission.payload,
        submission.key_config.clone(),
    );
    if let Some(expiration) = submission.expires {
        sign_request.set_expiration(expiration);
    }
    if let Some(pubkey) = &submission.pubkey {
        sign_request.set_pubkey(pubkey);
    }

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
        for id in sign_requests.keys() {
            signs.push(*id);
        }
    }
    HttpResponse::Ok().json(signs)
}

async fn submitshare(state: web::Data<State>, id: web::Path<ID>, json: web::Json<data::ShareSubmit>) -> Result<web::Json<()>, error::SharkSignError> {
    let mut sign_requests = state.sign_requests.lock().unwrap();
    match sign_requests.get_mut(&*id) {
        Some(sign_request) => {
            sign_request.submit_share(json.share.clone())?;
            Ok(web::Json(()))
        },
        None => {
            Err(error::SharkSignError::from(format!("sign request with id {} not found", id)).with_status(http::StatusCode::NOT_FOUND))
        }
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
    let share_count = key_gen_request.approvers().len();
    if share_count > 255 {
        return Err("Cannot generate >255 shares".into())
    }
    else if share_count < key_gen_request.shares_required.into() {
        return Err("Asked to generate fewer shares than required to regenerate key".into())
    }
    let generated = sharksign::generate(
        &key_gen_request.approvers(),
        key_gen_request.shares_required,
        &key_gen_request.key_config,
    )?;
    let id = state::get_id(&*key_gen_request);
    {
        let mut key_gen_requests = state.key_gen_requests.lock().unwrap();
        key_gen_requests.insert(id, generated);
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
    let state = web::Data::new(State::new());
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

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::{test};
    use super::sharksign::test_data;
    use super::sharksign::data::serde_cert::CertDef;

    #[actix_rt::test]
    async fn test_generate() {
        let td = test_data::load_test_data_3_5();
        let approvers: Vec<CertDef> = td.approvers_pub().into_iter().map(|x| (*x).clone().into()).collect();
        let keygen = json!({
            "keyConfig": {
                "kind": "Rsa",
                "userid": "alice@example.org",
                "size": 2048,
            },
            "approvers": approvers,
            "sharesRequired": 3,
        });
        let state = web::Data::new(State::new());

        let mut app = test::init_service(
            App::new()
                .app_data(state.clone())
                .route("/", web::post().to(newkey)),
        ).await;
        let req = test::TestRequest::post()
            .uri("/")
            .set_json(&keygen)
            .to_request();
        let resp = test::call_service(&mut app, req).await;
        assert_eq!(resp.status(), http::StatusCode::OK);
    }
}
