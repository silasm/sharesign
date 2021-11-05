
use actix_web::{ web, App, HttpResponse, HttpServer, Responder };
use actix_rt;
// use json;
use serde::{Serialize, Deserialize};
// use serde_json;

mod sharksign;

/* #[derive(Serialize, Deserialize)] */
struct SignRequest {
    // to_be_signed: HashDigest<'a>,
    // shareholders: Vec<KeyRef>,
    // shares: Vec<sharks::Share>,
    // signature: Option<Signature<'a>>,
    // ctime: u64,
    // expiration: u64,
}

/* #[derive(Serialize, Deserialize)] */
struct ShareSubmit {
    // to_be_signed: HashDigest<'a>,
    // share: sharks::Share,
}

#[derive(Serialize, Deserialize)]
struct Signature {
    // approvers: Vec<KeyRef>,
    // hash: HashDigest<'a>,
    // signature: &'a [u8],
}

#[derive(Serialize, Deserialize)]
struct HashDigest {
    // hasher: String,
    // digest: &'a [u8],
}

#[derive(Serialize, Deserialize)]
enum KeyRef {
    
}

async fn startsign() -> impl Responder {
    HttpResponse::Ok().json(())
}

async fn showsigns() -> impl Responder {
    HttpResponse::Ok().json(())
}

async fn submitshare(_req: web::HttpRequest) -> impl Responder {
    HttpResponse::Ok().json(())
}

async fn showsign(_path: web::Path<(KeyRef, HashDigest)>) -> impl Responder {
    HttpResponse::Ok().json(())
}

async fn showshares(_path: web::Path<(KeyRef, HashDigest)>) -> impl Responder {
    HttpResponse::Ok().json(())
}

async fn newkey() -> impl Responder {
    HttpResponse::Ok().json(())
}

async fn showkeys() -> impl Responder {
    HttpResponse::Ok().json(())
}

async fn updatekey(_path: web::Path<KeyRef>) -> impl Responder {
    HttpResponse::Ok().json(())
}

async fn showkey(_path: web::Path<KeyRef>) -> impl Responder {
    HttpResponse::Ok().json(())
}


#[actix_rt::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        App::new()
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
