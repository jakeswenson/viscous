use futures::Future;
use lru::LruCache;
use mini_fs::MiniFs;
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
        clients: Arc::new(Mutex::new(LruCache::new(10))),
        id: 0,
    };
    tokio::time::timeout(
        std::time::Duration::from_secs(1),
        thrussh::server::run(config, "0.0.0.0:2222", sh),
    )
    .await
    .unwrap_or(Ok(()));
}

#[derive(Debug, Clone)]
struct Server {
    client_pubkey: Arc<thrussh_keys::key::PublicKey>,
    clients: Arc<Mutex<lru::LruCache<HoneypotChannel, thrussh::server::Handle>>>,
    id: usize,
}

#[derive(Debug, Hash, Clone, Eq, Ord, PartialOrd, PartialEq, Copy)]
struct HoneypotId(usize);

#[derive(Debug, Hash, Clone)]
struct HoneypotChannel {
    honeypot_id: HoneyPotId,
    channel_id: ChannelId,
}

enum AuthStrategy {
    None,
    AllowAnyUserPassword,
}

#[derive(Debug, Hash, Clone, Eq, Ord, PartialOrd, PartialEq, Copy)]
struct Username(String);

#[derive(Debug, Clone)]
struct Honeypot {
    honeypot_id: HoneyPotId,
    victim_ip_address: Option<std::net::SocketAddr>,
    auth_strategy: AuthStrategy,
    virtual_file_system: mini_fs::MiniFs,
    environment: HashMap<String, String>,
    logins: Arc<LruCache<Username, Context>>,
}

struct Context {}

impl server::Server for Server {
    type Handler = HoneyPot;
    fn new(&mut self, client_ip: Option<std::net::SocketAddr>) -> Self::Handler {
        let s = self.clone();
        self.id += 1;
        Honeypot {
            victim_ip_address: client_ip,
            auth_strategy: AuthStrategy::AllowAnyUserPassword,
            virtual_file_system: MiniFs::new(),
        }
    }
}

impl server::Handler for Honeypot {
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

    fn auth_password(&mut self, user: &str, password: &str) -> Self::FutureAuth {
        self.finished_auth(Auth::Reject)
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
