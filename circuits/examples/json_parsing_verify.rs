//! Proof verification for verifying the validity of an ECDSA signed Atala identity JSON.
//!
//! This example reads a hex-encoded proof from stdin and verifies it.

use std::io::{self, Read};

use halo2curves::secp256k1::{Fq as secp256k1Scalar, Secp256k1};
use midnight_circuits::{
    compact_std_lib::{self, Relation, ZkStdLib, ZkStdLibArch},
    field::foreign::{params::MultiEmulationParams, AssignedField},
    instructions::{
        ArithInstructions, AssertionInstructions, AssignmentInstructions, Base64Instructions,
        DecompositionInstructions, EccInstructions, PublicInputInstructions,
        RangeCheckInstructions,
    },
    parsing::{DateFormat, Separator, StdLibParser},
    testing_utils::{
        ecdsa::{ECDSASig, FromBase64, PublicKey},
        plonk_api::filecoin_srs,
    },
    types::{AssignedByte, AssignedForeignPoint, AssignedNative, Instantiable},
};
use midnight_proofs::{
    circuit::{Layouter, Value},
    plonk::Error,
};
use num_bigint::BigUint;

type F = midnight_curves::Fq;

const HEADER_LEN: usize = 38;
const PAYLOAD_LEN: usize = 2463;

// Public Key of the issuer, signer of the credential.
const PUB_KEY: &[u8] =
    b"_bDXlQJ636HHOvXSe-flG0f-OkkRu8Jusm93PB2GBjoykg753nsOiW1vhEpCnxxybkMdarJLXIUJIYw1K2emQI";

const MAX_VALID_DATE: Date = Date {
    day: 1,
    month: 1,
    year: 2004,
};
const VALID_NAME: &[u8] = b"Alice";
const NAME_LEN: usize = VALID_NAME.len();
const BIRTHDATE_LEN: usize = 10;
const COORD_LEN: usize = 43;

// Issuer Public Key.
type PK = Secp256k1;
// Credential payload.
type Payload = [u8; PAYLOAD_LEN];
// Holder secret key.
type SK = secp256k1Scalar;

#[derive(Clone, Default)]
pub struct AtalaJsonECDSA;

impl Relation for AtalaJsonECDSA {
    type Instance = PK;
    type Witness = (Payload, ECDSASig, SK);

    fn format_instance(instance: &Self::Instance) -> Vec<F> {
        AssignedForeignPoint::<F, Secp256k1, MultiEmulationParams>::as_public_input(instance)
    }

    fn circuit(
        &self,
        std_lib: &ZkStdLib,
        layouter: &mut impl Layouter<F>,
        instance: Value<Self::Instance>,
        witness: Value<Self::Witness>,
    ) -> Result<(), Error> {
        let secp256k1_curve = std_lib.secp256k1_curve();
        let b64_chip = std_lib.base64();
        let automaton_chip = std_lib.automaton();

        // Assign the PK as public input.
        let pk = secp256k1_curve.assign_as_public_input(layouter, instance)?;

        let payload = witness.map(|(payload, _, _)| payload).transpose_array();
        let (sig, sk) = witness.map(|(_, sig, sk)| (sig, sk)).unzip();

        // Assign payload.
        let payload = std_lib.assign_many(layouter, &payload)?;

        // Verify credential signature.
        Self::verify_ecdsa(std_lib, layouter, pk, &payload, sig)?;

        // Decode Base64 JSON.
        let json =
            b64_chip.decode_base64(layouter, &payload[HEADER_LEN + 1..PAYLOAD_LEN], false)?;
        let parsed_json = automaton_chip.parse(layouter, &StdLibParser::Jwt, &json)?;

        // Check Name.
        let name = Self::get_property(std_lib, layouter, &json, &parsed_json, 3, NAME_LEN)?;
        Self::assert_str_match(std_lib, layouter, &name, VALID_NAME)?;

        // Check birth date.
        let birthdate =
            Self::get_property(std_lib, layouter, &json, &parsed_json, 4, BIRTHDATE_LEN)?;
        Self::assert_date_before(std_lib, layouter, &birthdate, MAX_VALID_DATE)?;

        // Get holder public key.
        let x = Self::get_property(std_lib, layouter, &json, &parsed_json, 5, COORD_LEN)?;
        let y = Self::get_property(std_lib, layouter, &json, &parsed_json, 6, COORD_LEN)?;
        let x_val = b64_chip.decode_base64url(layouter, &x, false)?;
        let y_val = b64_chip.decode_base64url(layouter, &y, false)?;

        // Check knowledge of corresponding sk.
        let x_coord = secp256k1_curve
            .base_field_chip()
            .assigned_from_be_bytes(layouter, &x_val[..32])?;
        let y_coord = secp256k1_curve
            .base_field_chip()
            .assigned_from_be_bytes(layouter, &y_val[..32])?;

        let holder_pk = secp256k1_curve.point_from_coordinates(layouter, &x_coord, &y_coord)?;
        let holder_sk: AssignedField<_, secp256k1Scalar, MultiEmulationParams> =
            std_lib.secp256k1_scalar().assign(layouter, sk)?;

        let gen: AssignedForeignPoint<_, Secp256k1, MultiEmulationParams> =
            secp256k1_curve.assign_fixed(layouter, Secp256k1::generator())?;
        let must_be_pk = secp256k1_curve.msm(layouter, &[holder_sk], &[gen])?;
        secp256k1_curve.assert_equal(layouter, &holder_pk, &must_be_pk)?;

        Ok(())
    }

    fn used_chips(&self) -> ZkStdLibArch {
        ZkStdLibArch {
            jubjub: false,
            poseidon: false,
            sha256: true,
            secp256k1: true,
            bls12_381: false,
            base64: true,
            nr_pow2range_cols: 3,
            automaton: true,
        }
    }

    fn write_relation<W: std::io::Write>(&self, _writer: &mut W) -> std::io::Result<()> {
        Ok(())
    }

    fn read_relation<R: std::io::Read>(_reader: &mut R) -> std::io::Result<Self> {
        Ok(AtalaJsonECDSA)
    }
}

impl AtalaJsonECDSA {
    /// Verifies the secp256k1 ECDSA signature of the given message.
    fn verify_ecdsa(
        std_lib: &ZkStdLib,
        layouter: &mut impl Layouter<F>,
        pk: AssignedForeignPoint<F, Secp256k1, MultiEmulationParams>,
        message: &[AssignedByte<F>],
        sig: Value<ECDSASig>,
    ) -> Result<(), Error> {
        let secp256k1_curve = std_lib.secp256k1_curve();
        let secp256k1_scalar = std_lib.secp256k1_scalar();
        let secp256k1_base = secp256k1_curve.base_field_chip();

        // Assign the message and hash it.
        let msg_hash: AssignedField<_, _, _> = {
            let hash_bytes = std_lib.sha256(layouter, message)?;
            secp256k1_scalar.assigned_from_be_bytes(layouter, &hash_bytes)?
        };

        // Assign the signature.
        let r_value = sig.map(|sig| sig.get_r());
        let r_le_bytes = std_lib.assign_many(layouter, &r_value.transpose_array())?;
        let s = secp256k1_scalar.assign(layouter, sig.map(|sig| sig.get_s()))?;

        let r_as_scalar = secp256k1_scalar.assigned_from_le_bytes(layouter, &r_le_bytes)?;
        let r_as_base = secp256k1_base.assigned_from_le_bytes(layouter, &r_le_bytes)?;

        // Verify the ECDSA signature: lhs.x =?= r, where
        // lhs := (msg_hash * s^-1) * G + (r * s^-1) * PK
        let r_over_s = secp256k1_scalar.div(layouter, &r_as_scalar, &s)?;
        let m_over_s = secp256k1_scalar.div(layouter, &msg_hash, &s)?;

        let gen = secp256k1_curve.assign_fixed(layouter, Secp256k1::generator())?;
        let lhs = secp256k1_curve.msm(layouter, &[m_over_s, r_over_s], &[gen, pk])?;
        let lhs_x = secp256k1_curve.x_coordinate(&lhs);

        secp256k1_base.assert_equal(layouter, &lhs_x, &r_as_base)
    }

    /// Searches for "property": and returns the following `val_len` characters.
    fn get_property(
        std_lib: &ZkStdLib,
        layouter: &mut impl Layouter<F>,
        body: &[AssignedByte<F>],
        parsed_body: &[AssignedNative<F>],
        marker: usize,
        val_len: usize,
    ) -> Result<Vec<AssignedByte<F>>, Error> {
        let parser = std_lib.parser();
        let parsed_seq: Value<Vec<F>> =
            Value::from_iter(parsed_body.iter().map(|b| b.value().copied()));
        let idx = parsed_seq.map(|parsed_seq| {
            let idx = parsed_seq
                .iter()
                .position(|&m| m == F::from(marker as u64))
                .expect("Property should appear in the credential.");
            F::from(idx as u64)
        });

        let idx = std_lib.assign(layouter, idx)?;
        parser.fetch_bytes(layouter, body, &idx, val_len)
    }

    fn assert_str_match(
        std_lib: &ZkStdLib,
        layouter: &mut impl Layouter<F>,
        str1: &[AssignedByte<F>],
        str2: &[u8],
    ) -> Result<(), Error> {
        assert_eq!(
            str1.len(),
            str2.len(),
            "Compared string lengths must match."
        );
        for (b1, b2) in str1.iter().zip(str2.iter()) {
            std_lib.assert_equal_to_fixed(layouter, b1, *b2)?
        }
        Ok(())
    }

    fn assert_date_before(
        std_lib: &ZkStdLib,
        layouter: &mut impl Layouter<F>,
        date: &[AssignedByte<F>],
        limit_date: Date,
    ) -> Result<(), Error> {
        let format = (DateFormat::YYYYMMDD, Separator::Sep('-'));
        let date = std_lib.parser().date_to_int(layouter, date, format)?;
        std_lib.assert_lower_than_fixed(layouter, &date, &limit_date.into())
    }
}

struct Date {
    day: u8,
    month: u8,
    year: u16,
}

impl From<Date> for BigUint {
    fn from(value: Date) -> Self {
        (value.year as u64 * 10_000 + value.month as u64 * 100 + value.day as u64).into()
    }
}

fn read_stdin() -> io::Result<String> {
    let mut buffer = String::new();
    io::stdin().read_to_string(&mut buffer)?;
    Ok(buffer.trim().to_string())
}

fn main() {
    const K: u32 = 17;
    let srs = filecoin_srs(K);

    let relation = AtalaJsonECDSA;

    eprintln!("Setting up the vk...");
    let vk = compact_std_lib::setup_vk(&srs, &relation);

    // Read hex-encoded proof from stdin
    let hex_proof = read_stdin().expect("Failed to read from stdin");
    if hex_proof.is_empty() {
        eprintln!("Error: No proof provided on stdin");
        println!("false");
        std::process::exit(1);
    }

    let proof = match hex::decode(&hex_proof) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Error decoding hex proof: {}", e);
            println!("false");
            std::process::exit(1);
        }
    };

    eprintln!("Computing instance...");
    let instance = PublicKey::from_base64(PUB_KEY).expect("Base64 encoded PK");

    eprintln!("Verifying proof...");
    let result = compact_std_lib::verify::<AtalaJsonECDSA, blake2b_simd::State>(
        &srs.verifier_params(),
        &vk,
        &instance,
        None,
        &proof,
    );

    match result {
        Ok(()) => println!("true"),
        Err(_) => println!("false"),
    }
}
