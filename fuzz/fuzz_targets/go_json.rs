//! Image JSON read as containerd's Go decoder reads it (`snapshotter/src/go_json.rs`): untrusted
//! manifests, indexes and configs. Checks that decoding never panics, that the scanner accepts
//! whatever serde_json accepts (and the reverse where serde_json can judge: valid UTF-8, no
//! `\u` escapes, shallow nesting), and that each decoded document decodes back to itself.
#![no_main]

use libfuzzer_sys::fuzz_target;
use serde::Deserialize;
use serde::de::IgnoredAny;
use serde_json::Value;

#[path = "../../snapshotter/src/go_json.rs"]
mod go_json;

use go_json::{GoType, Shape, decode};

/// The shapes `containerd_lookup` decodes image documents into.
const PLATFORM: Shape = Shape::Struct(&[("architecture", Shape::Str), ("os", Shape::Str)]);
const DESCRIPTOR: Shape = Shape::Struct(&[
    ("mediaType", Shape::Str),
    ("digest", Shape::Str),
    ("annotations", Shape::StrMap),
    ("platform", Shape::Ptr(&PLATFORM)),
]);

macro_rules! go_type {
    ($name:ident, $shape:expr) => {
        #[derive(Deserialize)]
        #[serde(transparent)]
        struct $name(Value);
        impl GoType for $name {
            const SHAPE: Shape = $shape;
        }
    };
}

go_type!(Any, Shape::Raw);
go_type!(
    Unknown,
    Shape::Struct(&[
        ("mediaType", Shape::Str),
        ("config", Shape::Raw),
        ("layers", Shape::Raw),
        ("manifests", Shape::Raw),
        ("fsLayers", Shape::Raw),
    ])
);
go_type!(
    Manifest,
    Shape::Struct(&[("config", DESCRIPTOR), ("layers", Shape::List(&DESCRIPTOR))])
);
go_type!(
    Index,
    Shape::Struct(&[("manifests", Shape::List(&DESCRIPTOR))])
);
go_type!(
    Config,
    Shape::Struct(&[(
        "rootfs",
        Shape::Struct(&[("diff_ids", Shape::List(&Shape::Str))])
    )])
);

/// A decoded document re-encoded as plain JSON decodes to the same value.
fn roundtrips<T: GoType>(data: &[u8], unwrap: fn(T) -> Value) -> bool {
    let Ok(doc) = decode::<T>(data) else {
        return false;
    };
    let doc = unwrap(doc);
    let again = decode::<T>(&serde_json::to_vec(&doc).unwrap()).expect("re-encoded document");
    assert_eq!(unwrap(again), doc);
    true
}

fn serde_can_judge(data: &[u8]) -> bool {
    std::str::from_utf8(data).is_ok()
        && !data.windows(2).any(|w| w == b"\\u")
        && data.iter().filter(|&&c| c == b'[' || c == b'{').count() < 100
}

fuzz_target!(|data: &[u8]| {
    let valid = decode::<Any>(data).is_ok_and(|any| any.0 == Value::Bool(true));
    if serde_json::from_slice::<IgnoredAny>(data).is_ok() {
        assert!(valid, "rejects JSON serde_json accepts");
    } else if serde_can_judge(data) {
        assert!(!valid, "accepts JSON serde_json rejects");
    }
    let _ = decode::<Unknown>(data).map(|doc| assert!(valid && doc.0.is_object()));
    for ok in [
        roundtrips::<Manifest>(data, |d| d.0),
        roundtrips::<Index>(data, |d| d.0),
        roundtrips::<Config>(data, |d| d.0),
    ] {
        assert!(!ok || valid, "decodes JSON its scanner rejects");
    }
});
