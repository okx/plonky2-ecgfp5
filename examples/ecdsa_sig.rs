// toy example of a circuit that checks a ecdsa signatuse

use env_logger::{try_init_from_env, Env, DEFAULT_FILTER_ENV};
use log::Level;
use plonky2::{
    hash::{
        hash_types::HashOut,
        hashing::{hash_n_to_hash_no_pad, hash_n_to_m_no_pad, SPONGE_WIDTH},
        poseidon::PoseidonPermutation,
    },
    iop::{target::Target, witness::PartialWitness},
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData},
        config::{GenericConfig, GenericHashOut, Hasher, PoseidonGoldilocksConfig},
        prover::prove,
    },
    util::timing::{self, TimingTree},
};
use plonky2_ecdsa::gadgets::{
    biguint::WitnessBigUint, curve::CircuitBuilderCurve, nonnative::CircuitBuilderNonNative,
};
use plonky2_ecgfp5::{
    curve::{curve::Point, scalar_field::Scalar},
    gadgets::{
        base_field::{CircuitBuilderGFp5, PartialWitnessQuinticExt, QuinticExtensionTarget},
        curve::{CircuitBuilderEcGFp5, CurveTarget, PartialWitnessCurve},
        scalar_field::CircuitBuilderScalar,
    },
};
use plonky2_field::{
    extension::quintic::QuinticExtension,
    types::{Field, PrimeField, Sample},
};
use rand::{thread_rng, Rng};

const D: usize = 2;
type C = PoseidonGoldilocksConfig;
type F = <C as GenericConfig<D>>::F;

pub const SPONGE_RATE: usize = 8;

// we define a hash function whose digest is 5 GFp5 elems
// note: this doesn't apply any padding, so this is vulnerable to length extension attacks
fn sig_hash(message: &[F]) -> [F; 5] {
    let mut res = [F::ZERO; 5];
    let out = hash_n_to_m_no_pad::<F, PoseidonPermutation>(message, 5);
    res.copy_from_slice(&out[..5]);

    res
}

pub fn main() {
    init_logger();
    let mut rng = thread_rng();

    /* Generate Keypair */
    let sk = Scalar::sample(&mut rng);
    let pk = Point::GENERATOR * sk;

    /* Signing */
    // 1. message digest & encoding
    // let message_bytes = b"I'm going to be the king of pirates!";
    // let message_elems = message_bytes.map(|b| F::from_canonical_u8(b));
    // let e = sig_hash(&message_elems);
    // 2. z = Ln lestmost bits of e = scalar of e
    // let z = Scalar::from_gfp5(QuinticExtension(e));

    // 1-2. Sample random z
    let z = Scalar::sample(&mut rng);
    // 3-5
    let (k, r) = {
        // 3. sample random k
        let mut k = Scalar::sample(&mut rng);
        // 4. compute (x1, y1) = k*G
        let mut rr = Point::GENERATOR * k;
        // If x1 is zero, we need to sample a new k.
        while rr.x.is_zero() {
            k = Scalar::sample(&mut rng);
            rr = Point::GENERATOR * k;
        }
        // 5. r = x1 mod n
        let r = Scalar::from_gfp5(rr.x);
        (k, r)
    };
    // 6. s = k^{-1} * (z + r*sk) mod n
    let s = k.inverse() * (z + r * sk);

    /* Verify in circuit */
    let config = CircuitConfig::wide_ecc_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    // Verify(meg_z, (r,s), pk)
    // let msg_target = builder.constant_quintic_ext(QuinticExtension(e));
    let msg_z_target = builder.constant_nonnative::<Scalar>(z);
    // Sig = (r, s)
    let r_target = builder.constant_nonnative::<Scalar>(r);
    let s_target = builder.constant_nonnative::<Scalar>(s);
    let pk_target = builder.curve_constant(pk.to_weierstrass());

    let g = builder.curve_constant(Point::GENERATOR.to_weierstrass());
    // 1. Check pk is a valid curve point
    // builder.curve_assert_valid(pk_target);

    // 2. Check r and s are in [1, n-1]

    // We get meg_z from witness directly
    // 3. e = HASH(msg)
    // 4. z = Ln leastmost bits of e

    // 5. u1 = z * s^{-1} mod n, u2 = r * s^{-1} mod n
    let s_inv = builder.inv_nonnative(&s_target);
    let u1 = builder.mul_nonnative(&msg_z_target, &s_inv);
    let u2 = builder.mul_nonnative(&r_target, &s_inv);

    // 6. (x1, y1) = u1*G + u2*pk
    let point = builder.curve_muladd_2(g, pk_target, &u1, &u2);

    // 7. Check r == x1 mod n and (x1, y1) != O (identity element)
    let CurveTarget(([x1_ext, y1_ext], is_inf)) = point;
    let x1 = builder.encode_quintic_ext_as_scalar(x1_ext);
    builder.connect_nonnative(&r_target, &x1);
    builder.assert_zero(is_inf.target);

    // build circuit
    builder.print_gate_counts(0);
    let circuit = builder.build::<C>();
    let CircuitData {
        prover_only,
        common,
        verifier_only: _,
    } = &circuit;

    let pw = PartialWitness::new();
    let mut timing = TimingTree::new("prove", Level::Debug);
    let proof = prove(prover_only, common, pw, &mut timing).expect("prover failed");
    timing.print();

    circuit.verify(proof).expect("verifier failed");
}

fn init_logger() {
    let _ = try_init_from_env(Env::default().filter_or(DEFAULT_FILTER_ENV, "debug"));
}
