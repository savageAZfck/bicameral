use bicameral::*;

fn two_chambers() -> (Identity, Identity, Hansard) {
    let gpu = Identity::generate();
    let ane = Identity::generate();
    let h = Hansard::new(
        vec![
            Chamber::new("gpu", &gpu.public_key()),
            Chamber::new("ane", &ane.public_key()),
        ],
        Rule::Unanimous,
    );
    (gpu, ane, h)
}

#[test]
fn unanimous_pass() {
    let (gpu, ane, mut h) = two_chambers();
    let m = h.table("rotate custodians", "nagi-7");
    h.vote(&gpu, &m.id, Vote::Aye, "due").unwrap();
    assert_eq!(h.resolution(&m.id).unwrap(), Resolution::Pending);
    h.vote(&ane, &m.id, Vote::Aye, "agree").unwrap();
    assert_eq!(h.resolution(&m.id).unwrap(), Resolution::Passed);
    h.verify().unwrap();
}

#[test]
fn split_vote_records_dissent() {
    let (gpu, ane, mut h) = two_chambers();
    let m = h.table("adopt treaty x", "wolakota-9");
    h.vote(&gpu, &m.id, Vote::Aye, "peer is vouched").unwrap();
    h.vote(&ane, &m.id, Vote::Nay, "shard freshness low")
        .unwrap();
    assert_eq!(h.resolution(&m.id).unwrap(), Resolution::Dissent);
    // The dissent is a permanent record entry.
    let dissent = h
        .events
        .iter()
        .any(|e| matches!(e.entry, HansardEntry::DissentRecorded(_)));
    assert!(dissent);
    h.verify().unwrap();
}

#[test]
fn all_nay_fails_closed() {
    let (gpu, ane, mut h) = two_chambers();
    let m = h.table("erase memory root", "camazotz-1");
    h.vote(&gpu, &m.id, Vote::Nay, "no").unwrap();
    h.vote(&ane, &m.id, Vote::Nay, "no").unwrap();
    assert_eq!(h.resolution(&m.id).unwrap(), Resolution::Failed);
}

#[test]
fn unseated_key_cannot_vote() {
    let (gpu, _ane, mut h) = two_chambers();
    let outsider = Identity::generate();
    let m = h.table("x", "y");
    h.vote(&gpu, &m.id, Vote::Aye, "ok").unwrap();
    let r = h.vote(&outsider, &m.id, Vote::Aye, "sneaky");
    assert!(matches!(r, Err(Error::UnknownChamber(_))));
}

#[test]
fn chamber_votes_once() {
    let (gpu, _ane, mut h) = two_chambers();
    let m = h.table("x", "y");
    h.vote(&gpu, &m.id, Vote::Aye, "ok").unwrap();
    assert!(matches!(
        h.vote(&gpu, &m.id, Vote::Nay, "changed my mind"),
        Err(Error::DuplicateVote(_))
    ));
}

#[test]
fn closed_motion_rejects_votes() {
    let (gpu, ane, mut h) = two_chambers();
    let m = h.table("x", "y");
    h.vote(&gpu, &m.id, Vote::Aye, "ok").unwrap();
    h.vote(&ane, &m.id, Vote::Aye, "ok").unwrap();
    assert_eq!(h.resolution(&m.id).unwrap(), Resolution::Passed);
    // Late vote lands nowhere.
    let third = Identity::generate();
    assert!(h.vote(&third, &m.id, Vote::Nay, "late").is_err());
}

#[test]
fn forged_ballot_breaks_verify() {
    let (gpu, ane, mut h) = two_chambers();
    let m = h.table("x", "y");
    h.vote(&gpu, &m.id, Vote::Aye, "ok").unwrap();
    h.vote(&ane, &m.id, Vote::Aye, "ok").unwrap();
    // Flip a recorded vote — chain and signature both break.
    for ev in h.events.iter_mut() {
        if let HansardEntry::VoteCast(b) = &mut ev.entry {
            b.vote = Vote::Nay;
        }
    }
    assert!(h.verify().is_err());
}

#[test]
fn majority_rule() {
    let ids: Vec<Identity> = (0..3).map(|_| Identity::generate()).collect();
    let chambers: Vec<Chamber> = ids
        .iter()
        .enumerate()
        .map(|(i, id)| Chamber::new(&format!("c{i}"), &id.public_key()))
        .collect();
    let mut h = Hansard::new(chambers, Rule::Majority);
    let m = h.table("adopt", "ctx");
    h.vote(&ids[0], &m.id, Vote::Aye, "y").unwrap();
    h.vote(&ids[1], &m.id, Vote::Nay, "n").unwrap();
    assert_eq!(h.resolution(&m.id).unwrap(), Resolution::Pending);
    h.vote(&ids[2], &m.id, Vote::Aye, "y").unwrap();
    assert_eq!(h.resolution(&m.id).unwrap(), Resolution::Passed);
    h.verify().unwrap();
}

#[test]
fn deadline_fails_closed() {
    let (gpu, _ane, mut h) = two_chambers();
    let m = h.table_with_deadline("urgent", "ctx", Some(1)); // long past
    h.vote(&gpu, &m.id, Vote::Aye, "ok").unwrap();
    assert_eq!(h.resolution(&m.id).unwrap(), Resolution::Failed);
}

#[test]
fn hansard_head_is_notarizable() {
    let (gpu, ane, mut h) = two_chambers();
    let m = h.table("x", "y");
    h.vote(&gpu, &m.id, Vote::Aye, "ok").unwrap();
    h.vote(&ane, &m.id, Vote::Aye, "ok").unwrap();
    let (seq, tip) = h.head();
    assert_eq!(seq, h.events.len() as u64);
    assert_eq!(tip.len(), 64);
}

#[test]
fn serialization_roundtrip() {
    let (gpu, ane, mut h) = two_chambers();
    let m = h.table("x", "y");
    h.vote(&gpu, &m.id, Vote::Aye, "ok").unwrap();
    h.vote(&ane, &m.id, Vote::Nay, "no").unwrap();
    let text = serde_json::to_string_pretty(&h).unwrap();
    let loaded: Hansard = serde_json::from_str(&text).unwrap();
    loaded.verify().unwrap();
    assert_eq!(loaded.resolution(&m.id).unwrap(), Resolution::Dissent);
}
