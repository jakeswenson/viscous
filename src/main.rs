use futures::Future;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use thrussh::server::{Auth, Session};
use thrussh::*;
use thrussh_keys::*;

#[tokio::main]
async fn main() {
    let client_key = thrussh_keys::key::KeyPair::generate_ed25519().unwrap();
    let client_pubkey = Arc::new(client_key.clone_public_key());
    let mut config = thrussh::server::Config::default();
    config.connection_timeout = Some(std::time::Duration::from_secs(3));
    config.auth_rejection_time = std::time::Duration::from_secs(3);
    config
        .keys
        .push(thrussh_keys::key::KeyPair::generate_ed25519().unwrap());
    let config = Arc::new(config);
    let sh = Server {
        client_pubkey,
        clients: Arc::new(Mutex::new(HashMap::new())),
        id: 0,
    };
    tokio::time::timeout(
        std::time::Duration::from_secs(1),
        thrussh::server::run(config, "0.0.0.0:2222", sh),
    )
    .await
    .unwrap_or(Ok(()));
}

#[derive(Clone)]
struct Server {
    client_pubkey: Arc<thrussh_keys::key::PublicKey>,
    clients: Arc<Mutex<HashMap<(usize, ChannelId), thrussh::server::Handle>>>,
    id: usize,
}

impl server::Server for Server {
    type Handler = Self;
    fn new(&mut self, _: Option<std::net::SocketAddr>) -> Self {
        let s = self.clone();
        self.id += 1;
        s
    }
}

impl server::Handler for Server {
    type FutureAuth = futures::future::Ready<Result<server::Auth, failure::Error>>;
    type FutureUnit = futures::future::Ready<Result<(), failure::Error>>;
    type FutureBool = futures::future::Ready<Result<bool, failure::Error>>;

    fn finished_auth(&mut self, auth: Auth) -> Self::FutureAuth {
        futures::future::ready(Ok(auth))
    }
    fn finished_bool(&mut self, b: bool, s: &mut Session) -> Self::FutureBool {
        futures::future::ready(Ok(b))
    }
    fn finished(&mut self, s: &mut Session) -> Self::FutureUnit {
        futures::future::ready(Ok(()))
    }
    fn channel_open_session(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Self::FutureUnit {
        {
            let mut clients = self.clients.lock().unwrap();
            clients.insert((self.id, channel), session.handle());
        }
        self.finished(session)
    }
    fn auth_publickey(&mut self, _: &str, _: &key::PublicKey) -> Self::FutureAuth {
        self.finished_auth(server::Auth::Accept)
    }
    fn data(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        mut session: &mut Session,
    ) -> Self::FutureUnit {
        {
            let mut clients = self.clients.lock().unwrap();
            for ((id, channel), ref mut s) in clients.iter_mut() {
                if *id != self.id {
                    s.data(*channel, CryptoVec::from_slice(data));
                }
            }
        }
        session.data(channel, data);
        self.finished(session)
    }
}
