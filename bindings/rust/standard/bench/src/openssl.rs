// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    get_cert_path,
    harness::{
        self, CipherSuite, CryptoConfig, HandshakeType, KXGroup, Mode, TlsBenchConfig,
        TlsConnection, TlsInfo, ViewIO,
    },
    PemType::*,
};
use openssl::ssl::{
    ErrorCode, ShutdownResult, Ssl, SslContext, SslFiletype, SslMethod, SslOptions, SslSession,
    SslSessionCacheMode, SslStream, SslVerifyMode, SslVersion,
};
use std::{
    error::Error,
    io::{Read, Write},
    sync::{Arc, Mutex},
};

// Creates session ticket callback handler
#[derive(Clone, Default)]
pub struct SessionTicketStorage {
    stored_ticket: Arc<Mutex<Option<SslSession>>>,
}

pub struct OpenSslConnection {
    connection: SslStream<ViewIO>,
}

impl Drop for OpenSslConnection {
    fn drop(&mut self) {
        // shutdown must be called for session resumption to work
        // https://www.openssl.org/docs/man1.1.1/man3/SSL_set_session.html
        self.connection.shutdown().unwrap();
    }
}

pub struct OpenSslConfig {
    config: SslContext,
    session_ticket_storage: SessionTicketStorage,
}

impl From<SslContext> for OpenSslConfig {
    fn from(value: SslContext) -> Self {
        OpenSslConfig {
            config: value,
            session_ticket_storage: Default::default(),
        }
    }
}

impl TlsBenchConfig for OpenSslConfig {
    fn make_config(
        mode: Mode,
        crypto_config: CryptoConfig,
        handshake_type: HandshakeType,
    ) -> Result<Self, Box<dyn Error>> {
        let cipher_suite = match crypto_config.cipher_suite {
            CipherSuite::AES_128_GCM_SHA256 => "TLS_AES_128_GCM_SHA256",
            CipherSuite::AES_256_GCM_SHA384 => "TLS_AES_256_GCM_SHA384",
        };

        let ec_key = match crypto_config.kx_group {
            KXGroup::Secp256R1 => "P-256",
            KXGroup::X25519 => "X25519",
        };

        let ssl_method = match mode {
            Mode::Client => SslMethod::tls_client(),
            Mode::Server => SslMethod::tls_server(),
        };

        let session_ticket_storage = SessionTicketStorage::default();

        let mut builder = SslContext::builder(ssl_method)?;
        builder.set_min_proto_version(Some(SslVersion::TLS1_3))?;
        builder.set_ciphersuites(cipher_suite)?;
        builder.set_groups_list(ec_key)?;

        match mode {
            Mode::Client => {
                builder.set_ca_file(get_cert_path(CACert, crypto_config.sig_type))?;
                builder.set_verify(SslVerifyMode::FAIL_IF_NO_PEER_CERT | SslVerifyMode::PEER);

                match handshake_type {
                    HandshakeType::MutualAuth => {
                        builder.set_certificate_chain_file(get_cert_path(
                            ClientCertChain,
                            crypto_config.sig_type,
                        ))?;
                        builder.set_private_key_file(
                            get_cert_path(ClientKey, crypto_config.sig_type),
                            SslFiletype::PEM,
                        )?;
                    }
                    HandshakeType::Resumption => {
                        builder.set_session_cache_mode(SslSessionCacheMode::CLIENT);
                        // do not attempt to define the callback outside of an
                        // expression directly passed into the function, because
                        // the compiler's type inference doesn't work for this
                        // scenario
                        // https://github.com/rust-lang/rust/issues/70263
                        builder.set_new_session_callback({
                            let sts = session_ticket_storage.clone();
                            move |_, ticket| {
                                let _ = sts.stored_ticket.lock().unwrap().insert(ticket);
                            }
                        });
                    }
                    HandshakeType::ServerAuth => {}
                }
            }
            Mode::Server => {
                builder.set_certificate_chain_file(get_cert_path(
                    ServerCertChain,
                    crypto_config.sig_type,
                ))?;
                builder.set_private_key_file(
                    get_cert_path(ServerKey, crypto_config.sig_type),
                    SslFiletype::PEM,
                )?;

                if handshake_type == HandshakeType::MutualAuth {
                    builder.set_ca_file(get_cert_path(CACert, crypto_config.sig_type))?;
                    builder.set_verify(SslVerifyMode::FAIL_IF_NO_PEER_CERT | SslVerifyMode::PEER);
                }
                if handshake_type == HandshakeType::Resumption {
                    builder.set_session_cache_mode(SslSessionCacheMode::CLIENT);
                } else {
                    builder.set_options(SslOptions::NO_TICKET);
                    builder.set_session_cache_mode(SslSessionCacheMode::OFF);
                    // OpenSSL Bug: https://github.com/openssl/openssl/issues/8077
                    // even with the above configuration, we must explicitly specify
                    // 0 tickets
                    builder.set_num_tickets(0)?;
                }
            }
        }
        Ok(Self {
            config: builder.build(),
            session_ticket_storage,
        })
    }
}

impl TlsConnection for OpenSslConnection {
    type Config = OpenSslConfig;

    fn new_from_config(
        mode: harness::Mode,
        config: &Self::Config,
        io: &harness::TestPairIO,
    ) -> Result<Self, Box<dyn Error>> {
        // check if there is a session ticket available
        // a session ticket will only be available if the Config was created
        // with session resumption enabled
        let maybe_ticket = config
            .session_ticket_storage
            .stored_ticket
            .lock()
            .unwrap()
            .take();
        if let Some(ticket) = &maybe_ticket {
            let _result = unsafe { config.config.add_session(ticket) };
        }

        let mut connection = Ssl::new(&config.config)?;
        if let Some(ticket) = &maybe_ticket {
            unsafe { connection.set_session(ticket)? };
        }

        let io = match mode {
            Mode::Client => io.client_view(),
            Mode::Server => io.server_view(),
        };

        let connection = SslStream::new(connection, io)?;
        Ok(Self { connection })
    }

    fn handshake(&mut self) -> Result<(), Box<dyn Error>> {
        let result = if self.connection.ssl().is_server() {
            self.connection.accept()
        } else {
            self.connection.connect()
        };

        // treat blocking (`ErrorCode::WANT_READ`) as `Ok`, expected during handshake
        match result {
            Ok(_) => Ok(()),
            Err(err) => {
                if err.code() != ErrorCode::WANT_READ {
                    Err(err.into())
                } else {
                    Ok(())
                }
            }
        }
    }

    fn handshake_completed(&self) -> bool {
        self.connection.ssl().is_init_finished()
    }

    fn send(&mut self, data: &[u8]) {
        let mut write_offset = 0;
        while write_offset < data.len() {
            write_offset += self
                .connection
                .write(&data[write_offset..data.len()])
                .unwrap();
            self.connection.flush().unwrap(); // make sure internal buffers don't fill up
        }
    }

    fn recv(&mut self, data: &mut [u8]) -> std::io::Result<()> {
        let data_len = data.len();
        let mut read_offset = 0;
        while read_offset < data.len() {
            read_offset += self.connection.read(&mut data[read_offset..data_len])?
        }
        Ok(())
    }

    fn shutdown_send(&mut self) {
        // this method will not read in a CloseNotify
        assert_eq!(self.connection.shutdown().unwrap(), ShutdownResult::Sent);
    }

    fn shutdown_finish(&mut self) -> bool {
        self.connection.shutdown().unwrap() == ShutdownResult::Received
    }
}

impl TlsInfo for OpenSslConnection {
    fn name() -> String {
        let version_num = openssl::version::number() as u64;
        let patch: u8 = (version_num >> 4) as u8;
        let fix = (version_num >> 12) as u8;
        let minor = (version_num >> 20) as u8;
        let major = (version_num >> 28) as u8;
        format!(
            "openssl{}.{}.{}{}",
            major,
            minor,
            fix,
            (b'a' + patch - 1) as char
        )
    }

    fn get_negotiated_cipher_suite(&self) -> CipherSuite {
        let cipher_suite = self
            .connection
            .ssl()
            .current_cipher()
            .expect("Handshake not completed")
            .name();
        match cipher_suite {
            "TLS_AES_128_GCM_SHA256" => CipherSuite::AES_128_GCM_SHA256,
            "TLS_AES_256_GCM_SHA384" => CipherSuite::AES_256_GCM_SHA384,
            _ => panic!("Unknown cipher suite"),
        }
    }

    fn negotiated_tls13(&self) -> bool {
        self.connection
            .ssl()
            .version2() // version() -> &str is deprecated, version2() returns an enum instead
            .expect("Handshake not completed")
            == SslVersion::TLS1_3
    }

    fn resumed_connection(&self) -> bool {
        self.connection.ssl().session_reused()
    }

    fn mutual_auth(&self) -> bool {
        assert!(self.connection.ssl().is_server());
        self.connection.ssl().verified_chain().is_some()
    }
}

#[cfg(test)]
mod tests {
    use crate::test_utilities;

    use super::*;

    #[test]
    fn sanity_check() {
        test_utilities::basic_handshake::<OpenSslConnection>();
    }

    #[test]
    fn all_handshakes() {
        test_utilities::all_handshakes::<OpenSslConnection>();
    }

    #[test]
    fn transfer() {
        test_utilities::transfer::<OpenSslConnection>();
    }
}
