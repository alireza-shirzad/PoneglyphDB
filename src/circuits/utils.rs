use halo2_proofs::{
    halo2curves::bn256::{Bn256, Fr as Fp, G1Affine},
    plonk::{create_proof, keygen_pk, keygen_vk, verify_proof, Circuit},
    poly::{
        commitment::{Params, ParamsProver},
        kzg::{
            commitment::{KZGCommitmentScheme, ParamsKZG},
            multiopen::{ProverSHPLONK, VerifierSHPLONK},
            strategy::SingleStrategy,
        },
    },
    transcript::{
        Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer, TranscriptWriterBuffer,
    },
};
use rand::rngs::OsRng;
use serde::Serialize;
use std::time::Instant;
use std::{fs::File, io::Write, path::Path};

/// Timings (seconds) and proof size (bytes) from a single full_prover run.
///
/// Returned by [`full_prover`] so callers — both unit tests and external
/// benchmark harnesses — can record numbers without parsing stdout. `prove`,
/// `verify`, and `proof_size` are the headline metrics; keygen times are
/// included for completeness but typically excluded from prover/verifier
/// totals because they correspond to one-time setup work.
#[derive(Debug, Clone, Serialize)]
pub struct BenchResult {
    pub k: u32,
    pub vk_time_s: f64,
    pub pk_time_s: f64,
    pub prove_time_s: f64,
    pub verify_time_s: f64,
    pub proof_size_bytes: usize,
    pub verified: bool,
    pub params_bytes: u64,
    pub vk_bytes: u64,
    pub pk_bytes: u64,
}

/// Counts the bytes written to it.
struct ByteCounter(u64);

impl Write for ByteCounter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0 += buf.len() as u64;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn params_path(k: u32) -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("src")
        .join("sql")
        .join(format!("kzg_param{k}"))
}

/// The cached KZG parameters for degree `k`, generated first if missing.
fn load_params(k: u32) -> ParamsKZG<Bn256> {
    if !params_path(k).exists() {
        setup_params(k);
    }
    ParamsKZG::<Bn256>::read(&mut File::open(params_path(k)).unwrap()).unwrap()
}

/// Generates the KZG parameters for degree `k`, replacing any cached ones, and
/// returns the time it took.
pub fn setup_params(k: u32) -> std::time::Duration {
    let start = Instant::now();
    let params = ParamsKZG::<Bn256>::setup(k, OsRng);
    let elapsed = start.elapsed();
    let mut fd = std::fs::File::create(params_path(k)).unwrap();
    params.write(&mut fd).unwrap();
    elapsed
}

pub fn full_prover<C: Circuit<Fp> + Sync>(
    circuit: C,
    k: u32,
    public_input: &[Fp],
    proof_path: &str,
) -> BenchResult {
    full_prover_columns(circuit, k, &[public_input], &[], proof_path)
}

/// The data owner's commitments to table columns for a degree-`k` circuit:
/// each column zero-padded to the domain and committed with no blinding
/// factor, as the prover commits an unblinded advice column. Returns them and
/// the time spent committing (not loading the parameters).
pub fn commit_columns(k: u32, columns: &[Vec<Fp>]) -> (Vec<G1Affine>, std::time::Duration) {
    use halo2_proofs::halo2curves::group::Curve;
    use halo2_proofs::poly::{commitment::Blind, EvaluationDomain};
    let params = load_params(k);
    let domain = EvaluationDomain::<Fp>::new(1, k);
    let start = Instant::now();
    let commitments = columns
        .iter()
        .map(|column| {
            let mut values = column.clone();
            values.resize(params.n() as usize, Fp::zero());
            params
                .commit_lagrange(&domain.lagrange_from_vec(values), Blind::default())
                .to_affine()
        })
        .collect();
    (commitments, start.elapsed())
}

/// Whether `proof` commits the advice columns of `bound` to the given
/// commitments. The proof opens with the advice commitments, in column order.
fn binds(proof: &[u8], num_advice: usize, bound: &[(usize, G1Affine)]) -> bool {
    use halo2_proofs::transcript::TranscriptRead;
    let mut transcript = Blake2bRead::<_, G1Affine, Challenge255<_>>::init(proof);
    let advice: Result<Vec<G1Affine>, _> =
        (0..num_advice).map(|_| transcript.read_point()).collect();
    advice.is_ok_and(|advice| bound.iter().all(|&(i, c)| advice.get(i) == Some(&c)))
}

/// Pins the calling thread to `cpu`; threads it spawns inherit the pin.
pub fn pin_to_cpu(cpu: usize) {
    pin(&[cpu]);
}

fn pin(cpus: &[usize]) {
    // SAFETY: `set` is a zeroed `cpu_set_t` that CPU_SET only writes into.
    unsafe {
        let mut set: libc::cpu_set_t = std::mem::zeroed();
        for &cpu in cpus {
            libc::CPU_SET(cpu, &mut set);
        }
        assert_eq!(
            libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &set),
            0,
            "cannot pin to CPUs {cpus:?}"
        );
    }
}

/// Runs key generation on KEYGEN_THREADS threads over CPUs 0..KEYGEN_THREADS
/// when that is set, else on the calling thread. Only key generation fans out:
/// proving and verification stay on the calling thread's CPU.
fn keygen<T: Send>(f: impl FnOnce() -> T + Send) -> T {
    let Some(threads) = std::env::var("KEYGEN_THREADS")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|&n| n > 1)
    else {
        return f();
    };
    let cpus: Vec<usize> = (0..threads).collect();
    rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .start_handler(move |_| pin(&cpus))
        .build()
        .expect("key generation thread pool")
        .install(f)
}

/// [`full_prover`] for a circuit with one instance column per entry of
/// `public_inputs`. The verifier also checks that the proof's advice columns
/// of `bound` (column index, commitment) carry the data owner's commitments.
pub fn full_prover_columns<C: Circuit<Fp> + Sync>(
    circuit: C,
    k: u32,
    public_inputs: &[&[Fp]],
    bound: &[(usize, G1Affine)],
    proof_path: &str,
) -> BenchResult {
    let params = load_params(k);

    let (vk_time, pk, pk_time) = keygen(|| {
        let vk_time_start = Instant::now();
        let vk = keygen_vk(&params, &circuit).unwrap();
        let vk_time = vk_time_start.elapsed();
        let pk_time_start = Instant::now();
        let pk = keygen_pk(&params, vk, &circuit).unwrap();
        (vk_time, pk, pk_time_start.elapsed())
    });
    println!("Time to generate vk {:?}", vk_time);
    println!("Time to generate pk {:?}", pk_time);
    let key_bytes = |write: &dyn Fn(&mut ByteCounter) -> std::io::Result<()>| {
        let mut counter = ByteCounter(0);
        write(&mut counter).unwrap();
        counter.0
    };
    let vk_bytes = key_bytes(&|w| pk.get_vk().write(w, halo2_proofs::SerdeFormat::RawBytes));
    let pk_bytes = key_bytes(&|w| pk.write(w, halo2_proofs::SerdeFormat::RawBytes));

    let proof_time_start = Instant::now();
    let mut transcript = Blake2bWrite::<_, _, Challenge255<_>>::init(vec![]);
    create_proof::<
        KZGCommitmentScheme<Bn256>,
        ProverSHPLONK<'_, Bn256>,
        Challenge255<G1Affine>,
        _,
        Blake2bWrite<Vec<u8>, G1Affine, Challenge255<G1Affine>>,
        _,
    >(
        &params,
        &pk,
        &[circuit],
        &[public_inputs],
        OsRng,
        &mut transcript,
    )
    .expect("prover should not fail");
    let proof = transcript.finalize();
    let prove_time = proof_time_start.elapsed();
    println!("prove_time: {:?}", prove_time);
    println!("proof_size_bytes: {}", proof.len());

    File::create(Path::new(proof_path))
        .expect("Failed to create proof file")
        .write_all(&proof)
        .expect("Failed to write proof");
    println!("Proof written to: {}", proof_path);

    let verifier_params = params.verifier_params();
    let verify = || {
        let strategy = SingleStrategy::new(&params);
        let mut transcript = Blake2bRead::<_, _, Challenge255<_>>::init(&proof[..]);
        let start = Instant::now();
        let result = verify_proof::<
            KZGCommitmentScheme<Bn256>,
            VerifierSHPLONK<'_, Bn256>,
            Challenge255<G1Affine>,
            Blake2bRead<&[u8], G1Affine, Challenge255<G1Affine>>,
            SingleStrategy<'_, Bn256>,
        >(
            verifier_params,
            pk.get_vk(),
            strategy,
            &[public_inputs],
            &mut transcript,
        );
        let num_advice = pk.get_vk().cs().num_advice_columns();
        let bound_ok = binds(&proof, num_advice, bound);
        (
            result.map_err(|e| format!("{e:?}")).and_then(|()| {
                bound_ok
                    .then_some(())
                    .ok_or_else(|| "the tables are not the committed ones".to_string())
            }),
            start.elapsed(),
        )
    };
    // Verification repeats for up to a second; the median is reported.
    let (verify_result, first) = verify();
    let mut times = vec![first];
    while times.iter().sum::<std::time::Duration>() < std::time::Duration::from_secs(1) {
        times.push(verify().1);
    }
    times.sort();
    let verify_time = times[times.len() / 2];
    println!("verify_time: {:?}", verify_time);
    println!("verify_ok: {}", verify_result.is_ok());
    if let Err(err) = &verify_result {
        println!("verify_error: {:?}", err);
    }

    BenchResult {
        k,
        vk_time_s: vk_time.as_secs_f64(),
        pk_time_s: pk_time.as_secs_f64(),
        prove_time_s: prove_time.as_secs_f64(),
        verify_time_s: verify_time.as_secs_f64(),
        proof_size_bytes: proof.len(),
        verified: verify_result.is_ok(),
        params_bytes: std::fs::metadata(params_path(k)).map_or(0, |m| m.len()),
        vk_bytes,
        pk_bytes,
    }
}
