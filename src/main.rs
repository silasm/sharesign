
use actix_web::{ web, App, HttpResponse, HttpServer, Responder };
use actix_rt;
// use json;
// use serde_json;

mod sharksign;
use sharksign::data;

async fn startsign() -> impl Responder {
    HttpResponse::Ok().json(())
}

async fn showsigns() -> impl Responder {
    HttpResponse::Ok().json(())
}

async fn submitshare(_req: web::HttpRequest) -> impl Responder {
    HttpResponse::Ok().json(())
}

async fn showsign(_path: web::Path<(data::KeyRef, data::HashDigest)>) -> impl Responder {
    HttpResponse::Ok().json(())
}

async fn showshares(_path: web::Path<(data::KeyRef, data::HashDigest)>) -> impl Responder {
    HttpResponse::Ok().json(())
}

async fn newkey() -> impl Responder {
    HttpResponse::Ok().json(())
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
