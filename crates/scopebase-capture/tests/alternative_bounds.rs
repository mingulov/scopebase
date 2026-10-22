// SPDX-License-Identifier: Apache-2.0
//! CP07: one physical observation supports alternative candidate bounds;
//! it is never copied into each alias, and unknown candidates prove nothing.
use scopebase_capture::{
    bounds::{classify_alternatives, combine_disjoint_sites, CandidateCoverage, MatchClass, SiteCount},
    domain::{CaptureId, Epoch, PhysicalSiteId, ProducerId},
    quantity::{Count, CountBounds, Events},
    ContractError,
};

fn epoch(ordinal: u64) -> Epoch {
    Epoch::new(
        CaptureId::new([1; 16]).unwrap(),
        ProducerId::new([2; 16]).unwrap(),
        ordinal,
    )
}
fn site(count: u64, candidates: CandidateCoverage<&str>) -> SiteCount<&str> {
    SiteCount::new(epoch(0), PhysicalSiteId::new(7), Count::new(count), candidates, 8).unwrap()
}
fn bounds(lower: u64, upper: Option<u64>) -> CountBounds<Events> {
    CountBounds::new(Count::new(lower), upper.map(Count::new)).unwrap()
}
use MatchClass::{Definite, Excluded, Possible};

#[test]
fn one_physical_count_is_not_duplicated_across_aliases() {
    // OSSL preview-r21 evidence_model.rs `shared_site_conserves_calls`:
    // n=5 at one site with two alias candidates stays one observation.
    let s = site(5, CandidateCoverage::Complete(vec!["a", "b"]));
    assert_eq!(s.count(), Count::new(5));
    // No per-alias replication: every classification bounds the single n=5.
    for classes in [
        vec![Definite, Definite],
        vec![Definite, Excluded],
        vec![Excluded, Definite],
        vec![Excluded, Excluded],
        vec![Possible, Definite],
        vec![Possible, Possible],
    ] {
        let got = classify_alternatives(&s, &classes).unwrap();
        assert!(got.upper().is_none_or(|u| u.get() <= 5), "upper must not exceed n=5");
        assert!(got.lower().get() <= 5, "lower must not exceed n=5");
    }
    // The alias-multiplication mutant (n per candidate, i.e. 10) is wrong.
    let all_yes = classify_alternatives(&s, &[Definite, Definite]).unwrap();
    assert_eq!(all_yes, bounds(5, Some(5)));
    assert_ne!(all_yes.upper().unwrap().get(), 10, "must not multiply n across aliases");
}

#[test]
fn unknown_candidates_cannot_prove_absence() {
    // Plan: unknown candidates with n=0 still yields [0,None].
    // DELTA vs OSSL `zero_call_unknown_candidates_bound_known_zero`
    // (0,Some(0)): H26/MemVeil withhold-occupancy rule keeps unknown
    // unknown even at zero; zero observed activity proves no absence
    // when the candidate set itself is incomplete.
    for n in [0, 1, 5, u64::MAX] {
        let s = site(n, CandidateCoverage::Unknown);
        assert_eq!(classify_alternatives(&s, &[]).unwrap(), bounds(0, None));
    }
    // Unknown-as-empty mutant: [0,Some(0)] or [0,Some(n)] would claim a
    // known upper over unlisted candidates.
    let s = site(0, CandidateCoverage::Unknown);
    assert_ne!(
        classify_alternatives(&s, &[]).unwrap(),
        bounds(0, Some(0)),
        "unknown candidates must not collapse to known-empty"
    );
    assert_ne!(
        classify_alternatives(&s, &[]).unwrap(),
        bounds(0, Some(5)),
        "unknown candidates must not reuse the observed count as upper"
    );
}

#[test]
fn all_candidates_vs_mixed_bounds() {
    // Plan vectors, n=5 over [A,B].
    let s = site(5, CandidateCoverage::Complete(vec!["a", "b"]));
    assert_eq!(classify_alternatives(&s, &[Definite, Excluded]).unwrap(), bounds(0, Some(5)));
    assert_eq!(classify_alternatives(&s, &[Definite, Definite]).unwrap(), bounds(5, Some(5)));
    assert_eq!(classify_alternatives(&s, &[Excluded, Excluded]).unwrap(), bounds(0, Some(0)));
    assert_eq!(classify_alternatives(&s, &[Possible, Definite]).unwrap(), bounds(0, Some(5)));
    // OSSL 00b135d H3 mixed-class rule: any Possible withholds definite.
    assert_eq!(classify_alternatives(&s, &[Possible, Possible]).unwrap(), bounds(0, Some(5)));
    assert_eq!(classify_alternatives(&s, &[Possible, Excluded]).unwrap(), bounds(0, Some(5)));
    assert_eq!(classify_alternatives(&s, &[Excluded, Definite]).unwrap(), bounds(0, Some(5)));
    // Single-candidate sites: the class decides directly.
    let one = site(5, CandidateCoverage::Complete(vec!["a"]));
    assert_eq!(classify_alternatives(&one, &[Definite]).unwrap(), bounds(5, Some(5)));
    assert_eq!(classify_alternatives(&one, &[Excluded]).unwrap(), bounds(0, Some(0)));
    assert_eq!(classify_alternatives(&one, &[Possible]).unwrap(), bounds(0, Some(5)));
    // Empty complete set refuses, including n=0; wrong class count refuses.
    assert_eq!(
        SiteCount::new(epoch(0), PhysicalSiteId::new(7), Count::new(5), CandidateCoverage::Complete(Vec::<&str>::new()), 8),
        Err(ContractError::MissingProvenance)
    );
    assert_eq!(
        SiteCount::new(epoch(0), PhysicalSiteId::new(7), Count::new(0), CandidateCoverage::Complete(Vec::<&str>::new()), 8),
        Err(ContractError::MissingProvenance)
    );
    assert_eq!(
        classify_alternatives(&s, &[Definite]),
        Err(ContractError::ConservationMismatch)
    );
    assert_eq!(
        classify_alternatives(&s, &[Definite, Definite, Definite]),
        Err(ContractError::ConservationMismatch)
    );
    assert_eq!(
        classify_alternatives(&site(5, CandidateCoverage::Unknown), &[Definite]),
        Err(ContractError::ConservationMismatch)
    );
}

#[test]
fn duplicate_site_or_epoch_refuses() {
    let a = SiteCount::new(epoch(0), PhysicalSiteId::new(1), Count::new(5), CandidateCoverage::Complete(vec!["a"]), 8).unwrap();
    let b = SiteCount::new(epoch(0), PhysicalSiteId::new(2), Count::new(7), CandidateCoverage::Complete(vec!["b"]), 8).unwrap();
    let ba = classify_alternatives(&a, &[Definite]).unwrap();
    let bb = classify_alternatives(&b, &[Definite]).unwrap();
    assert_eq!(combine_disjoint_sites(&[a, b], &[ba, bb]).unwrap(), bounds(12, Some(12)));
    // Duplicate same site refuses rather than summing to 10.
    let c = SiteCount::new(epoch(0), PhysicalSiteId::new(1), Count::new(5), CandidateCoverage::Complete(vec!["a"]), 8).unwrap();
    let d = SiteCount::new(epoch(0), PhysicalSiteId::new(1), Count::new(5), CandidateCoverage::Complete(vec!["a"]), 8).unwrap();
    let bc = classify_alternatives(&c, &[Definite]).unwrap();
    let bd = classify_alternatives(&d, &[Definite]).unwrap();
    assert_eq!(
        combine_disjoint_sites(&[c, d], &[bc, bd]),
        Err(ContractError::DuplicateKey)
    );
    // Mixed epochs refuse; a second counter view of the same site is not
    // a new physical site, so it cannot be combined either.
    let e = SiteCount::new(epoch(1), PhysicalSiteId::new(3), Count::new(5), CandidateCoverage::Complete(vec!["a"]), 8).unwrap();
    let f = SiteCount::new(epoch(0), PhysicalSiteId::new(4), Count::new(5), CandidateCoverage::Complete(vec!["a"]), 8).unwrap();
    let be = classify_alternatives(&e, &[Definite]).unwrap();
    let bf = classify_alternatives(&f, &[Definite]).unwrap();
    assert_eq!(
        combine_disjoint_sites(&[e, f], &[be, bf]),
        Err(ContractError::DomainMismatch)
    );
    // One unknown upper poisons the combined upper; lowers still add.
    let g = SiteCount::new(epoch(0), PhysicalSiteId::new(5), Count::new(5), CandidateCoverage::Unknown, 8).unwrap();
    let h = SiteCount::new(epoch(0), PhysicalSiteId::new(6), Count::new(7), CandidateCoverage::Complete(vec!["b"]), 8).unwrap();
    let bg = classify_alternatives(&g, &[]).unwrap();
    let bh = classify_alternatives(&h, &[Definite]).unwrap();
    assert_eq!(combine_disjoint_sites(&[g, h], &[bg, bh]).unwrap(), bounds(7, None));
    // Length mismatch and overflow refuse with state preserved (pure fn).
    let i = SiteCount::new(epoch(0), PhysicalSiteId::new(9), Count::new(1), CandidateCoverage::Complete(vec!["a"]), 8).unwrap();
    let bi = classify_alternatives(&i, &[Definite]).unwrap();
    assert_eq!(
        combine_disjoint_sites(std::slice::from_ref(&i), &[]),
        Err(ContractError::ConservationMismatch)
    );
    assert_eq!(
        combine_disjoint_sites::<&str>(&[], std::slice::from_ref(&bi)),
        Err(ContractError::ConservationMismatch)
    );
    let big = bounds(u64::MAX, Some(u64::MAX));
    let j = SiteCount::new(epoch(0), PhysicalSiteId::new(10), Count::new(1), CandidateCoverage::Complete(vec!["a"]), 8).unwrap();
    assert_eq!(
        combine_disjoint_sites(&[i, j], &[big.clone(), big]),
        Err(ContractError::ArithmeticOverflow)
    );
    // Duplicate candidates and over-limit admission refuse at construction.
    assert_eq!(
        SiteCount::new(epoch(0), PhysicalSiteId::new(7), Count::new(5), CandidateCoverage::Complete(vec!["a", "a"]), 8),
        Err(ContractError::DuplicateKey)
    );
    assert_eq!(
        SiteCount::new(epoch(0), PhysicalSiteId::new(7), Count::new(5), CandidateCoverage::Complete(vec!["a", "b"]), 1),
        Err(ContractError::CapacityExceeded)
    );
}

#[test]
fn small_world_oracle_agrees_on_all_class_pairs() {
    // Independent oracle: enumerate which single alternative could have
    // produced the physical count. It never calls production classification.
    fn oracle(n: u64, classes: &[MatchClass]) -> (u64, Option<u64>) {
        // Definite = only matching alternatives possible; Excluded =
        // alternative impossible; Possible = either way. The physical
        // count came from exactly one alternative.
        let any_possible_match = classes.iter().any(|c| !matches!(c, MatchClass::Excluded));
        let all_definite = classes.iter().all(|c| matches!(c, MatchClass::Definite));
        if all_definite {
            (n, Some(n))
        } else if any_possible_match {
            (0, Some(n))
        } else {
            (0, Some(0))
        }
    }
    let variants = [Definite, Possible, Excluded];
    for n in [0, 1, 5, u64::MAX] {
        for x in &variants {
            for y in &variants {
                let s = site(n, CandidateCoverage::Complete(vec!["a", "b"]));
                let (lo, hi) = oracle(n, &[*x, *y]);
                assert_eq!(
                    classify_alternatives(&s, &[*x, *y]).unwrap(),
                    bounds(lo, hi),
                    "n={n} classes={x:?},{y:?}"
                );
            }
        }
    }
    // Sum-counter-plus-detail mutant: adding the site count to the
    // classified upper (n + upper) double-counts the physical observation.
    let s = site(5, CandidateCoverage::Complete(vec!["a", "b"]));
    let got = classify_alternatives(&s, &[Definite, Excluded]).unwrap();
    assert_ne!(got.upper().unwrap().get(), 10, "must not add count to bound");
    assert_ne!(got.lower().get() + s.count().get(), 10, "must not add bound to count");
}
