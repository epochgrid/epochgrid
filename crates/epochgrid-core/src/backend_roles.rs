//! Runtime capabilities. Resource creation belongs to the operator, not these roles.

/// The authority operates on existing resources and owns consumer reconciliation.
/// Consumer CREATE permissions also permit updates; the authority validates their
/// payloads against durable policy. NATS subjects cannot constrain those payloads.
pub fn authority_publish() -> Vec<String> {
    let mut subjects = vec!["$JS.API.INFO".to_owned()];
    for stream in [
        "CHAT",
        "MAILBOX",
        "KV_IDENTITIES",
        "KV_CHANNELS",
        "KV_TRANSPARENCY",
    ] {
        subjects.push(format!("$JS.API.STREAM.INFO.{stream}"));
    }
    for stream in ["CHAT", "MAILBOX"] {
        subjects.push(format!("$JS.API.CONSUMER.INFO.{stream}.*"));
        subjects.push(format!("$JS.API.CONSUMER.DELETE.{stream}.*"));
        subjects.push(format!("$JS.API.CONSUMER.CREATE.{stream}.>"));
    }
    for bucket in ["IDENTITIES", "TRANSPARENCY"] {
        subjects.push(format!("$JS.API.STREAM.MSG.GET.KV_{bucket}"));
        subjects.push(format!("$JS.API.DIRECT.GET.KV_{bucket}.>"));
        subjects.push(format!("$JS.API.DIRECT.GET.KV_{bucket}"));
        subjects.push(format!("$KV.{bucket}.>"));
    }
    subjects.push("epochgrid.v1.user.*.*.inbox".into());
    // The established authority identity also signs explicit local administration
    // requests. Preserve its narrow audit/revocation client workflow.
    subjects.extend(
        [
            crate::wire::AUDIT,
            crate::wire::REVOCATIONS,
            crate::wire::REVOKE,
        ]
        .map(str::to_owned),
    );
    subjects
}

/// The forwarding worker has no JetStream, KV, signing or admission capability.
pub fn worker_publish() -> Vec<String> {
    vec!["_INBOX.>".into()]
}

pub fn worker_subscribe() -> Vec<String> {
    vec![
        "epochgrid.v1.identity.*".into(),
        "epochgrid.v1.channel.*".into(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    // Independent subject matcher used to check dangerous operations against the
    // complete grants, rather than comparing the renderer with its own constants.
    fn permits(grants: &[String], subject: &str) -> bool {
        grants.iter().any(|grant| {
            let mut tokens = subject.split('.');
            for allowed in grant.split('.') {
                let Some(token) = tokens.next() else {
                    return false;
                };
                if allowed == ">" {
                    return true;
                }
                if allowed != "*" && allowed != token {
                    return false;
                }
            }
            tokens.next().is_none()
        })
    }

    #[test]
    fn runtime_roles_cannot_administer_streams_or_read_chat() {
        let authority = authority_publish();
        for subject in [
            "$JS.API.STREAM.CREATE.CHAT",
            "$JS.API.STREAM.UPDATE.CHAT",
            "$JS.API.STREAM.DELETE.CHAT",
            "$JS.API.STREAM.PURGE.CHAT",
            "$JS.API.STREAM.MSG.GET.CHAT",
            "$JS.API.DIRECT.GET.CHAT",
            "$JS.API.STREAM.MSG.GET.MAILBOX",
            "$JS.API.CONSUMER.CREATE.OTHER.device",
            "$JS.API.CONSUMER.MSG.NEXT.CHAT.device",
            "$SYS.REQ.SERVER.PING",
            "$KV.CHANNELS.arbitrary",
            "$KV.UNRELATED.arbitrary",
        ] {
            assert!(!permits(&authority, subject), "{subject}");
            assert!(!permits(&worker_publish(), subject), "{subject}");
        }
        assert!(permits(
            &authority,
            "$JS.API.CONSUMER.CREATE.CHAT.device_UABC"
        ));
        assert!(permits(&authority, "$JS.API.STREAM.INFO.CHAT"));
        assert!(permits(
            &authority,
            "$JS.API.STREAM.MSG.GET.KV_TRANSPARENCY"
        ));
        assert!(!permits(&worker_publish(), "$KV.TRANSPARENCY.snapshot"));
        assert!(!permits(
            &worker_subscribe(),
            "epochgrid.v1.group.secret.message"
        ));
    }
}
