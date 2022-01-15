use actix_web::{ web, App, HttpResponse, HttpServer, Responder };
use serde_json::json;

mod sharksign;
use sharksign::data;
use sharksign::state;
use sharksign::state::{State, ID};
use sharksign::error::SharkSignError as SSE;

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

async fn showshares(_path: web::Path<(data::KeyRef, data::HashDigest)>) -> impl Responder {
    HttpResponse::Ok().json(())
}

async fn newkey(state: web::Data<State>, key_gen_request: web::Json<data::KeyGenRequest>) -> Result<HttpResponse, SSE> {
    let share_count = key_gen_request.approvers.len();
    if share_count > 255 {
        return Err(SSE::Config("Cannot generate >255 shares".to_owned()))
    }
    else if share_count < key_gen_request.shares_required.into() {
        return Err(SSE::Config("Refusing to generate fewer shares than required to regenerate key".to_owned()))
    }
    let generated = sharksign::generate(
        &key_gen_request.approvers,
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
    use actix_web::{test, http};
    use super::sharksign::test_data;
    use sequoia_openpgp::serialize::SerializeInto;

    #[actix_rt::test]
    async fn test_generate() {
        let td = test_data::load_test_data_3_5();
        let approvers: Vec<String> = td.approvers_pub.into_iter().map(|cert| {
            let vec = cert.armored().to_vec().unwrap();
            String::from_utf8(vec).unwrap()
        }).collect();
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
