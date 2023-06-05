use halo2_proofs::{
    halo2curves::bn256::{Bn256, Fq, Fr, G1Affine},
    plonk::{create_proof, keygen_pk, keygen_vk, verify_proof},
    poly::{
        commitment::ParamsProver,
        kzg::{
            commitment::{KZGCommitmentScheme, ParamsKZG},
            multiopen::{ProverGWC, VerifierGWC},
            strategy::SingleStrategy,
        },
    },
    transcript::{Keccak256Read, Keccak256Write, TranscriptReadBuffer, TranscriptWriterBuffer},
};
use snark_verifier::{
    //loader::evm::{self, encode_calldata, Address, EvmLoader, ExecutorBuilder},
    pcs::kzg::{Gwc19, KzgAs},
    //system::halo2::{compile, transcript::evm::EvmTranscript, Config},
    system::halo2::{compile, transcript::evm::EvmTranscript, Config},
    verifier::{self, SnarkVerifier, plonk::PlonkProtocol},
    util::arithmetic::{CurveAffine, PrimeField},
    loader::{evm::{self, EvmLoader, encode_calldata, deploy_and_call}, Loader, native::{NativeLoader, LOADER}},
};
use number::{BigInt, FieldElement};
use pil_analyzer::Analyzed;
use polyexen::plaf::PlafDisplayBaseTOML;
use rand::{rngs::StdRng, SeedableRng};

use crate::circuit_builder::analyzed_to_circuit;

use std::rc::Rc;

type PlonkVerifier = verifier::plonk::PlonkVerifier<KzgAs<Bn256, Gwc19>>;

/// Create a halo2 proof for a given PIL, fixed column values and witness column values
/// We use KZG ([GWC variant](https://eprint.iacr.org/2019/953)) and Keccak256
pub fn prove_ast<T: FieldElement>(
    pil: &Analyzed<T>,
    fixed: Vec<(&str, Vec<T>)>,
    witness: Vec<(&str, Vec<T>)>,
) -> Vec<u8> {
    if polyexen::expr::get_field_p::<Fr>() != T::modulus().to_arbitrary_integer() {
        panic!("powdr modulus doesn't match halo2 modulus. Make sure you are using Bn254");
    }

    let circuit = analyzed_to_circuit(pil, fixed, witness);

    let circuit_row_count_log = usize::BITS - circuit.plaf.info.num_rows.leading_zeros();

    let expanded_row_count_log = circuit_row_count_log + 1;

    log::debug!("{}", PlafDisplayBaseTOML(&circuit.plaf));

    let inputs = vec![];

    let params = ParamsKZG::<Bn256>::new(expanded_row_count_log);
    let vk = keygen_vk(&params, &circuit).unwrap();
    let pk = keygen_pk(&params, vk.clone(), &circuit).unwrap();
    let mut transcript: Keccak256Write<
        Vec<u8>,
        G1Affine,
        halo2_proofs::transcript::Challenge255<G1Affine>,
    > = Keccak256Write::init(vec![]);

    dbg!(create_proof::<KZGCommitmentScheme<Bn256>, ProverGWC<_>, _, _, _, _>(
        &params,
        &pk,
        &[circuit],
        &[&inputs],
        StdRng::from_entropy(),
        &mut transcript,
    ))
    .unwrap();

    let proof = transcript.finalize();

    let mut transcript = Keccak256Read::init(&proof[..]);

    assert!(verify_proof::<_, VerifierGWC<_>, _, _, _>(
        &params,
        &vk,
        SingleStrategy::new(&params),
        &[&inputs],
        &mut transcript
    )
    .is_ok());

    let loader = EvmLoader::new::<Fq, Fr>();
    let code = evm::compile_yul(&loader.yul_code());

    evm_verify(code, vec![], &proof);

    proof
}

fn evm_verify(deployment_code: Vec<u8>, instances: Vec<Vec<Fr>>, proof: &[u8]) {
    let calldata = encode_calldata(&instances, proof);
    let gas_cost = deploy_and_call(deployment_code, calldata).unwrap();
    dbg!(gas_cost);
}

/*
fn gen_proof<C: Circuit<Fr>>(
    params: &ParamsKZG<Bn256>,
    pk: &ProvingKey<G1Affine>,
    circuit: C,
    instances: Vec<Vec<Fr>>,
) -> Vec<u8> {
    MockProver::run(params.k(), &circuit, instances.clone())
        .unwrap()
        .assert_satisfied();

    let instances = instances
        .iter()
        .map(|instances| instances.as_slice())
        .collect_vec();
    let proof = {
        let mut transcript = TranscriptWriterBuffer::<_, G1Affine, _>::init(Vec::new());
        create_proof::<KZGCommitmentScheme<Bn256>, ProverGWC<_>, _, _, EvmTranscript<_, _, _, _>, _>(
            params,
            pk,
            &[circuit],
            &[instances.as_slice()],
            OsRng,
            &mut transcript,
        )
        .unwrap();
        transcript.finalize()
    };

    let accept = {
        let mut transcript = TranscriptReadBuffer::<_, G1Affine, _>::init(proof.as_slice());
        VerificationStrategy::<_, VerifierGWC<_>>::finalize(
            verify_proof::<_, VerifierGWC<_>, _, EvmTranscript<_, _, _, _>, _>(
                params.verifier_params(),
                pk.get_vk(),
                AccumulatorStrategy::new(params.verifier_params()),
                &[instances.as_slice()],
                &mut transcript,
            )
            .unwrap(),
        )
    };
    assert!(accept);

    proof
}
*/
