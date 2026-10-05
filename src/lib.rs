//! bicameral — concurrence for minds with more than one chamber.
//!
//! A dual-brained organism is not one opinion with a coprocessor — it is
//! two reasoning faculties under one sovereignty. For consequential
//! decisions, `bicameral` treats them as *chambers*: a motion is tabled,
//! each chamber casts a signed vote, and the motion resolves only under
//! the concurrence rule the constitution sets (unanimous, majority, any).
//!
//! When the chambers split, the split is not smoothed over — it is
//! preserved as a signed [`DissentRecord`]: both positions, both
//! signatures, permanently in the [`Hansard`], the hash-chained
//! parliamentary record. An organism that can formally disagree with
//! itself is more trustworthy than one that pretends unanimity: the
//! dissent is the receipt that the vote was real.
//!
//! ```no_run
//! use bicameral::{Chamber, Identity, Hansard, Motion, Rule, Vote};
//!
//! let gpu = Identity::generate();
//! let ane = Identity::generate();
//! let chambers = vec![
//!     Chamber::new("gpu", &gpu.public_key()),
//!     Chamber::new("ane", &ane.public_key()),
//! ];
//! let mut hansard = Hansard::new(chambers, Rule::Unanimous);
//! let m = hansard.table("rotate escrow custodian set", "nagi ceremony 7");
//! hansard.vote(&gpu, &m.id, Vote::Aye, "custodian churn is due").unwrap();
//! hansard.vote(&ane, &m.id, Vote::Nay, "shard freshness < 24h").unwrap();
//! // unresolved — and the split is on the record forever.
//! ```

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt;

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

fn canonical(v: &Value) -> Vec<u8> {
    serde_json::to_vec(v).expect("canonical json")
}

#[derive(Debug)]
pub enum Error {
    UnknownChamber(String),
    BadSignature(String),
    DuplicateVote(String),
    UnknownMotion(String),
    ClosedMotion(String),
    BadRule(String),
    Serde(serde_json::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::UnknownChamber(m) => write!(f, "unknown chamber: {m}"),
            Error::BadSignature(m) => write!(f, "signature failure: {m}"),
            Error::DuplicateVote(m) => write!(f, "chamber already voted: {m}"),
            Error::UnknownMotion(m) => write!(f, "unknown motion: {m}"),
            Error::ClosedMotion(m) => write!(f, "motion already resolved: {m}"),
            Error::BadRule(m) => write!(f, "rule violation: {m}"),
            Error::Serde(e) => write!(f, "serde: {e}"),
        }
    }
}

impl std::error::Error for Error {}
impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::Serde(e)
    }
}

// ---------------------------------------------------------------- identity

/// Ed25519 identity for a chamber — each reasoning faculty signs its own
/// votes so no chamber can fabricate another's position.
pub struct Identity {
    key: SigningKey,
}

impl Identity {
    pub fn generate() -> Self {
        let mut seed = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut seed);
        Identity {
            key: SigningKey::from_bytes(&seed),
        }
    }

    pub fn from_bytes(seed: &[u8; 32]) -> Self {
        Identity {
            key: SigningKey::from_bytes(seed),
        }
    }

    pub fn seed(&self) -> [u8; 32] {
        self.key.to_bytes()
    }

    pub fn public_key(&self) -> String {
        hex::encode(self.key.verifying_key().to_bytes())
    }

    fn sign(&self, msg: &[u8]) -> String {
        hex::encode(self.key.sign(msg).to_bytes())
    }
}

pub fn verify_signature(pubkey_hex: &str, msg: &[u8], sig_hex: &str) -> Result<(), Error> {
    let pk_bytes =
        hex::decode(pubkey_hex).map_err(|e| Error::BadSignature(format!("pubkey hex: {e}")))?;
    let pk = VerifyingKey::from_bytes(
        pk_bytes
            .as_slice()
            .try_into()
            .map_err(|_| Error::BadSignature("pubkey not 32 bytes".into()))?,
    )
    .map_err(|e| Error::BadSignature(format!("pubkey: {e}")))?;
    let sig_bytes =
        hex::decode(sig_hex).map_err(|e| Error::BadSignature(format!("sig hex: {e}")))?;
    let sig = Signature::from_bytes(
        sig_bytes
            .as_slice()
            .try_into()
            .map_err(|_| Error::BadSignature("sig not 64 bytes".into()))?,
    );
    pk.verify(msg, &sig)
        .map_err(|_| Error::BadSignature("verification failed".into()))
}

// ---------------------------------------------------------------- chambers

/// A voting chamber: a name bound to an Ed25519 public key.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Chamber {
    pub name: String,
    pub pubkey: String,
}

impl Chamber {
    pub fn new(name: &str, pubkey: &str) -> Self {
        Chamber {
            name: name.to_string(),
            pubkey: pubkey.to_string(),
        }
    }
}

/// The concurrence rule a motion must satisfy.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum Rule {
    /// Every chamber must vote Aye.
    Unanimous,
    /// Strict majority of seated chambers must vote Aye.
    Majority,
    /// Any single Aye passes; used for advisory motions.
    Any,
}

// ---------------------------------------------------------------- motions

/// A tabled question awaiting concurrence.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Motion {
    /// Content-derived id.
    pub id: String,
    /// Plain-language subject ("rotate custodian set").
    pub subject: String,
    /// Detail / context reference (ceremony id, proposal hash, ...).
    pub context: String,
    /// Unix seconds the motion was tabled.
    pub ts: u64,
    /// Optional deadline — unresolved motions fail closed after this.
    pub deadline: Option<u64>,
}

impl Motion {
    fn new(subject: &str, context: &str, deadline: Option<u64>) -> Self {
        let ts = now_secs();
        let id = sha256_hex(&canonical(&json!({
            "subject": subject,
            "context": context,
            "ts": ts,
        })));
        Motion {
            id,
            subject: subject.to_string(),
            context: context.to_string(),
            ts,
            deadline,
        }
    }
}

// ---------------------------------------------------------------- votes

/// A chamber's signed position on a motion.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum Vote {
    Aye,
    Nay,
    Abstain,
}

/// One chamber's ballot: the vote, a digest of its reasoning, and the
/// signature binding both to the chamber key.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Ballot {
    pub motion_id: String,
    pub chamber: String,
    pub vote: Vote,
    /// SHA-256 of the chamber's stated reasoning — the reasoning itself
    /// may stay internal; the hash proves what was weighed.
    pub reasoning_hash: String,
    pub ts: u64,
    pub signature: String,
}

impl Ballot {
    fn body(&self) -> Value {
        json!({
            "motion_id": self.motion_id,
            "chamber": self.chamber,
            "vote": self.vote,
            "reasoning_hash": self.reasoning_hash,
            "ts": self.ts,
        })
    }

    pub fn verify(&self, chamber: &Chamber) -> Result<(), Error> {
        if chamber.name != self.chamber {
            return Err(Error::UnknownChamber(self.chamber.clone()));
        }
        verify_signature(&chamber.pubkey, &canonical(&self.body()), &self.signature)
    }
}

// ---------------------------------------------------------------- dissent

/// A preserved split: the positions each chamber signed when concurrence
/// failed. Not a failure of the record — the record working.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DissentRecord {
    pub motion_id: String,
    /// (chamber, vote, reasoning_hash) per dissenter.
    pub positions: Vec<(String, Vote, String)>,
    /// SHA-256 of the canonical position set — citable elsewhere.
    pub digest: String,
    pub ts: u64,
}

// ---------------------------------------------------------------- resolution

/// The state of a motion under the rule.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum Resolution {
    /// Still collecting ballots.
    #[default]
    Pending,
    /// Rule satisfied — the motion carries.
    Passed,
    /// Rule can no longer be satisfied (or deadline passed) — fails closed.
    Failed,
    /// Chambers have split in a way that preserves both positions —
    /// under `Unanimous`, any Aye+Nay split; the organism argued with
    /// itself and the argument is on the record.
    Dissent,
}

// ---------------------------------------------------------------- hansard

/// Kinds of entries in the parliamentary record.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum HansardEntry {
    MotionTabled(Motion),
    VoteCast(Ballot),
    Resolved {
        motion_id: String,
        resolution: Resolution,
    },
    DissentRecorded(DissentRecord),
}

/// One hash-chained record entry.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecordEvent {
    pub seq: u64,
    pub prev: String,
    pub hash: String,
    pub entry: HansardEntry,
}

/// The hash-chained parliamentary record: motions, ballots, resolutions,
/// and dissents in order. The organism cannot quietly forget it argued
/// with itself.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Hansard {
    pub chambers: Vec<Chamber>,
    pub rule: Rule,
    pub events: Vec<RecordEvent>,
    /// Live motion state: ballots collected so far and whether resolved.
    #[serde(default)]
    pub open: BTreeMap<String, MotionState>,
}

/// Mutable per-motion state (not itself chained — derived from events).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct MotionState {
    pub ballots: Vec<Ballot>,
    pub resolution: Resolution,
}

impl Hansard {
    pub fn new(chambers: Vec<Chamber>, rule: Rule) -> Self {
        Hansard {
            chambers,
            rule,
            events: Vec::new(),
            open: BTreeMap::new(),
        }
    }

    fn tip(&self) -> String {
        self.events
            .last()
            .map(|e| e.hash.clone())
            .unwrap_or_else(|| "0".repeat(64))
    }

    fn push(&mut self, entry: HansardEntry) {
        let seq = self.events.len() as u64;
        let prev = self.tip();
        let hash = sha256_hex(&canonical(&json!({
            "seq": seq,
            "prev": prev,
            "entry": entry,
        })));
        self.events.push(RecordEvent {
            seq,
            prev,
            hash,
            entry,
        });
    }

    /// Table a motion for concurrence.
    pub fn table(&mut self, subject: &str, context: &str) -> Motion {
        self.table_with_deadline(subject, context, None)
    }

    /// Table a motion that fails closed after `deadline` unix seconds.
    pub fn table_with_deadline(
        &mut self,
        subject: &str,
        context: &str,
        deadline: Option<u64>,
    ) -> Motion {
        let motion = Motion::new(subject, context, deadline);
        self.push(HansardEntry::MotionTabled(motion.clone()));
        self.open.insert(motion.id.clone(), MotionState::default());
        motion
    }

    fn chamber_of(&self, name: &str) -> Result<&Chamber, Error> {
        self.chambers
            .iter()
            .find(|c| c.name == name)
            .ok_or_else(|| Error::UnknownChamber(name.to_string()))
    }

    fn resolve_with(rule: Rule, seated: usize, state: &MotionState, motion: &Motion) -> Resolution {
        if state.resolution != Resolution::Pending {
            return state.resolution;
        }
        if let Some(dl) = motion.deadline {
            if now_secs() > dl {
                return Resolution::Failed;
            }
        }
        let ayes = state.ballots.iter().filter(|b| b.vote == Vote::Aye).count();
        let nays = state.ballots.iter().filter(|b| b.vote == Vote::Nay).count();
        let cast = state.ballots.len();
        match rule {
            Rule::Unanimous | Rule::Majority => {
                // Resolution waits for every seated chamber — a motion is
                // the chambers' conversation, and closing early would
                // erase positions from the record.
                if cast < seated {
                    return Resolution::Pending;
                }
                let carried = match rule {
                    Rule::Unanimous => ayes == seated,
                    _ => ayes > seated / 2,
                };
                if carried {
                    Resolution::Passed
                } else if ayes > 0 && nays > 0 {
                    Resolution::Dissent
                } else {
                    Resolution::Failed
                }
            }
            Rule::Any => {
                if ayes > 0 {
                    Resolution::Passed
                } else if state.ballots.len() == seated {
                    Resolution::Failed
                } else {
                    Resolution::Pending
                }
            }
        }
    }

    /// Cast a signed vote. The signing identity must match a seated
    /// chamber; each chamber votes once per motion.
    pub fn vote(
        &mut self,
        me: &Identity,
        motion_id: &str,
        vote: Vote,
        reasoning: &str,
    ) -> Result<Ballot, Error> {
        let motion = self
            .events
            .iter()
            .find_map(|e| match &e.entry {
                HansardEntry::MotionTabled(m) if m.id == motion_id => Some(m.clone()),
                _ => None,
            })
            .ok_or_else(|| Error::UnknownMotion(motion_id.to_string()))?;
        let state = self
            .open
            .get(motion_id)
            .ok_or_else(|| Error::UnknownMotion(motion_id.to_string()))?;
        if state.resolution != Resolution::Pending {
            return Err(Error::ClosedMotion(motion_id.to_string()));
        }

        let my_pubkey = me.public_key();
        let chamber = self
            .chambers
            .iter()
            .find(|c| c.pubkey == my_pubkey)
            .ok_or_else(|| Error::UnknownChamber(my_pubkey.clone()))?
            .clone();

        if state.ballots.iter().any(|b| b.chamber == chamber.name) {
            return Err(Error::DuplicateVote(chamber.name));
        }

        let mut ballot = Ballot {
            motion_id: motion_id.to_string(),
            chamber: chamber.name.clone(),
            vote,
            reasoning_hash: sha256_hex(reasoning.as_bytes()),
            ts: now_secs(),
            signature: String::new(),
        };
        ballot.signature = me.sign(&canonical(&ballot.body()));
        self.push(HansardEntry::VoteCast(ballot.clone()));

        let seated = self.chambers.len();
        let state = self.open.get_mut(motion_id).expect("state");
        state.ballots.push(ballot.clone());
        let resolution = Self::resolve_with(self.rule, seated, state, &motion);
        state.resolution = resolution;

        match resolution {
            Resolution::Passed | Resolution::Failed => {
                self.push(HansardEntry::Resolved {
                    motion_id: motion_id.to_string(),
                    resolution,
                });
            }
            Resolution::Dissent => {
                let positions: Vec<(String, Vote, String)> = self
                    .open
                    .get(motion_id)
                    .expect("state")
                    .ballots
                    .iter()
                    .map(|b| (b.chamber.clone(), b.vote, b.reasoning_hash.clone()))
                    .collect();
                let digest = sha256_hex(&canonical(&json!({
                    "motion_id": motion_id,
                    "positions": positions,
                })));
                let record = DissentRecord {
                    motion_id: motion_id.to_string(),
                    positions,
                    digest,
                    ts: now_secs(),
                };
                self.push(HansardEntry::DissentRecorded(record));
            }
            Resolution::Pending => {}
        }
        Ok(ballot)
    }

    /// Current resolution of a motion.
    pub fn resolution(&self, motion_id: &str) -> Result<Resolution, Error> {
        let motion = self
            .events
            .iter()
            .find_map(|e| match &e.entry {
                HansardEntry::MotionTabled(m) if m.id == motion_id => Some(m.clone()),
                _ => None,
            })
            .ok_or_else(|| Error::UnknownMotion(motion_id.to_string()))?;
        let state = self
            .open
            .get(motion_id)
            .ok_or_else(|| Error::UnknownMotion(motion_id.to_string()))?;
        Ok(Self::resolve_with(
            self.rule,
            self.chambers.len(),
            state,
            &motion,
        ))
    }

    /// Verify the whole record: chain integrity plus every ballot's
    /// signature against the seated chamber keys.
    pub fn verify(&self) -> Result<(), Error> {
        let mut prev = "0".repeat(64);
        for (i, ev) in self.events.iter().enumerate() {
            if ev.seq != i as u64 {
                return Err(Error::BadSignature(format!("seq gap at {i}")));
            }
            if ev.prev != prev {
                return Err(Error::BadSignature(format!("prev mismatch at {i}")));
            }
            let hash = sha256_hex(&canonical(&json!({
                "seq": ev.seq,
                "prev": ev.prev,
                "entry": ev.entry,
            })));
            if hash != ev.hash {
                return Err(Error::BadSignature(format!("hash mismatch at {i}")));
            }
            if let HansardEntry::VoteCast(b) = &ev.entry {
                let chamber = self.chamber_of(&b.chamber)?;
                b.verify(chamber)?;
            }
            prev = ev.hash.clone();
        }
        Ok(())
    }

    /// Current record head — notarizable by `kola` witnesses.
    pub fn head(&self) -> (u64, String) {
        (self.events.len() as u64, self.tip())
    }
}
