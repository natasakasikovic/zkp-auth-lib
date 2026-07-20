    use std::collections::{HashMap, HashSet};

    use crate::{context::AuthContext, error::AuthVerificationError};

    #[derive(Clone, Debug)]
    pub struct ReplayProtectorConfig {
        pub max_clock_skew_secs: u64,
        pub nonce_ttl_secs: u64,
    }

    impl Default for ReplayProtectorConfig {
        fn default() -> Self {
            Self {
                max_clock_skew_secs: 300,
                nonce_ttl_secs: 600,
            }
        }
    }

    #[derive(Debug)]
    pub struct ReplayProtector {
        config: ReplayProtectorConfig,
        used_nonces: HashMap<String, u64>,
    }

    impl ReplayProtector {
        pub fn new(config: ReplayProtectorConfig) -> Self {
            Self {
                config,
                used_nonces: HashMap::new(),
            }
        }

        pub(crate) fn verify_and_store(
            &mut self,
            context: &AuthContext,
            now_unix_secs: u64,
        ) -> Result<(), AuthVerificationError> {
            let age = now_unix_secs.abs_diff(context.timestamp_unix_secs);

            // reject the request if the difference between its timestamp and the current time exceeds the allowed clock skew.
            if age > self.config.max_clock_skew_secs {  
                return Err(AuthVerificationError::ExpiredTimestamp);
            }

            // remove expired nonces to prevent the nonce store from growing indefinitely.
            self.remove_expired_nonces(now_unix_secs);

            let nonce_key = format!(
                "{}:{}:{}",
                context.service_id, context.audience, context.nonce
            );

            // reject the request if its nonce has already been used.
            if self.used_nonces.contains_key(&nonce_key) {
                return Err(AuthVerificationError::ReplayDetected);
            }

            // store the nonce until it expires to prevent the request from being replayed.
            self.used_nonces
                .insert(nonce_key, now_unix_secs + self.config.nonce_ttl_secs);

            Ok(())
        }

        fn remove_expired_nonces(&mut self, now_unix_secs: u64) {
            let expired = self
                .used_nonces
                .iter()
                .filter_map(|(nonce, expires_at)| {
                    if *expires_at <= now_unix_secs {
                        Some(nonce.clone())
                    } else {
                        None
                    }
                })
                .collect::<HashSet<_>>();

            for nonce in expired {
                self.used_nonces.remove(&nonce);
            }
        }
    }
