//! A bicameral session: GPU brain and ANE brain vote on motions.
use bicameral::*;

fn main() {
    let gpu = Identity::generate();
    let ane = Identity::generate();
    let mut h = Hansard::new(
        vec![
            Chamber::new("gpu", &gpu.public_key()),
            Chamber::new("ane", &ane.public_key()),
        ],
        Rule::Unanimous,
    );

    // Motion 1: both chambers agree.
    let m1 = h.table("load dream adapter nightly-2026-10-03", "dreamcatcher");
    h.vote(&gpu, &m1.id, Vote::Aye, "adapter verified, ledger anchored")
        .unwrap();
    h.vote(&ane, &m1.id, Vote::Aye, "eval delta positive")
        .unwrap();
    println!(
        "motion 1 ({:?}) -> {:?}",
        &m1.subject[..30],
        h.resolution(&m1.id).unwrap()
    );

    // Motion 2: the chambers split — the argument is preserved.
    let m2 = h.table("ratify treaty with foreign organism 9f2e", "wolakota");
    h.vote(&gpu, &m2.id, Vote::Aye, "peer witnessed thrice by kola")
        .unwrap();
    h.vote(
        &ane,
        &m2.id,
        Vote::Nay,
        "no reciprocal escrow; asymmetric risk",
    )
    .unwrap();
    println!(
        "motion 2 ({:?}) -> {:?}",
        &m2.subject[..30],
        h.resolution(&m2.id).unwrap()
    );

    for ev in &h.events {
        if let HansardEntry::DissentRecorded(d) = &ev.entry {
            println!("\nDissent on record — digest {}", &d.digest[..16]);
            for (chamber, vote, _) in &d.positions {
                println!("  {chamber}: {vote:?}");
            }
        }
    }

    h.verify().expect("hansard verifies");
    let (seq, tip) = h.head();
    println!("\nhansard: {seq} entries, tip {}…", &tip[..16]);
}
