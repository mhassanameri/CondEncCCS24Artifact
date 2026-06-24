# Conditional Encryption — ACM CCS 2024 Artifact

This repository contains the implementation and evaluation artifact for our ACM CCS 2024 paper on **Conditional Encryption**.

Conditional Encryption is a public-key cryptographic primitive that allows a payload message to be encrypted conditionally on whether an encrypted hidden message satisfies a predicate with respect to a control message. This artifact includes:

- A C++ implementation of Conditional Encryption.
- Predicate families including equality, edit distance, Hamming distance, CAPSLOCK, and OR composition.
- Performance-evaluation scripts for reproducing the paper’s figures and tables.
- An application to TypTop showing how Conditional Encryption can strengthen typo-tolerant password checking.

This repository demonstrates research-to-implementation work in applied cryptography, privacy-preserving systems, provable security, and secure systems evaluation.

## Paper and links

- Link to the full version of the paper: [[arXiv]](https://arxiv.org/pdf/2409.06128)
- ACM CCS version: [[DOI]](https://dl.acm.org/doi/10.1145/3658644.3690374)
- Project page: [[Link]](https://mhassanameri.github.io/CondEncCCS24Artifact/)
- Artifact repository: `https://github.com/mhassanameri/CondEncCCS24Artifact`

## Why this matters

Many security systems need to determine whether a hidden value satisfies a condition without revealing the value itself. Conditional Encryption provides a cryptographic way to support such checks while preserving privacy and maintaining formal security guarantees, even against an adversary who holds a decryption secret key when the predicate is not satisfied.

This artifact connects cryptographic theory with implementation and evaluation. It shows how a provably secure primitive can be implemented, benchmarked, and applied to a real security system.

## My contribution

As part of the research team, I contributed to the design, implementation, and evaluation of Conditional Encryption constructions and their application to typo-tolerant password checking. The artifact involved cryptographic protocol design, C++ implementation, performance benchmarking, and reproducibility support for the ACM CCS 2024 paper.

## Conditional Encryption syntax

Let `pk` be a public key and let

```text
c_1 = Enc(pk, m_1)
```

be a regular ciphertext encrypting an unknown hidden message `m_1`. Conditional Encryption allows a party to compute

```text
c' = CondEnc(pk, c_1, m_2, m_3)
```

where `m_2` is a control message, `m_3` is a payload message, and `P(m_1, m_2)` is a binary predicate.

If the predicate holds, meaning `P(m_1, m_2) = 1`, then `c'` decrypts to the payload message `m_3`. If the predicate does not hold, meaning `P(m_1, m_2) = 0`, then `c'` hides the payload and behaves as an encryption of a random message unrelated to `m_1`, `m_2`, or `m_3`. In particular, `c'` does not leak information about `m_2` or `m_3`, even to an adversary who may know the decryption secret key.

The implementation supports predicates such as equality, edit distance at most one, Hamming distance at most `l`, CAPSLOCK errors, and OR compositions of these predicates. In particular, these predicates are defined as follows: 


## Repository structure

The project is divided into two main components:

- [`CondEncCPP`](CondEncCPP): implementation and evaluation of Conditional Encryption.
- [`CondTypTopCPP`](CondTypTopCPP): improved TypTop implementation using Conditional Encryption.

## Implemented predicate families

The following binary predicates `P(m_1, m_2)` are available in this implementation:

- **Equality test**: `P(m_1, m_2) = 1` if and only if `m_1 = m_2`.
- **Edit distance at most 1**: `P(m_1, m_2) = 1` if `EditDistance(m_1, m_2) <= 1`.
- **Hamming distance at most l**: `P(m_1, m_2) = 1` if `Ham(m_1, m_2) <= l`.
- **CAPSLOCK error**: `P(m_1, m_2) = 1` if and only if `m_1 = InvertCase(m_2)`.
- **OR composition**: an OR composition of any combination of the predicates above.

## Dependencies

To compile the project, install the following dependencies:

- `cmake >= 3.28`
- `protobuf` — on Debian/Ubuntu: `sudo apt install protobuf-compiler`
- `pam-dev` — on Debian/Ubuntu: `sudo apt-get install libpam0g-dev`
- `cURL` — on Debian/Ubuntu: `sudo apt install libcurl4-openssl-dev`
- `catch2` — build from source if it is not available through your package manager
- `cryptopp`, `zxcvbn`, and `plog` — included in the repository and built automatically
- `Argon2` memory-hard functions — included in the repository; required only for Conditional TypTop and built manually

To install CMake from source, if needed:

```bash
wget https://github.com/Kitware/CMake/releases/download/v3.30.3/cmake-3.30.3.tar.gz
tar -xvzf cmake-3.30.3.tar.gz
cd cmake-3.30.3
./configure
make
sudo make install
```

To build Catch2 from source, if needed:

```bash
git clone https://github.com/catchorg/Catch2.git
cd Catch2
cmake -Bbuild -H. -DBUILD_TESTING=OFF
sudo cmake --build build/ --target install
```

## Conditional Encryption

### Build

Clone the repository and enter the Conditional Encryption directory:

```bash
git clone https://github.com/mhassanameri/CondEncCCS24Artifact.git
cd CondEncCCS24Artifact/CondEncCPP
```

Create a build directory and compile the implementation:

```bash
mkdir build && cd build
cmake ../
make
```

If `make` fails with errors related to `g_argvPathHint`, run the following script from the build directory and then run `make` again:

```bash
./FixingTestInstallCryptoPP.sh
make
```

### Basic tests

After building, run the basic tests to check conditional encryption and decryption:

```bash
echo -e "all\n25\n1024\n32\n2" > BasicTestInputs.txt
./tests ArtifactCCS24BasicTests
```

Input parameters:

- `all`: test all predicates. For a specific predicate, use `HamDistT`, `EDOne`, `CAPSLOCK`, or `OR`.
- `25`: number of test messages `m_1` and corresponding typo/control-message examples.
- `1024`: public-key size.
- `32`: message length. Other options include `8`, `16`, `64`, and `128`.
- `2`: Hamming-distance threshold for the relevant tests.

### Reproducing paper results

The repository includes scripts for reproducing the paper’s evaluation results. The scripts generate `.dat` files that can be used to create the plots and tables in the paper.

#### Figure 1

Figure 1 contains nine subplots, labeled Figure 1a through Figure 1i. To generate data for a Figure 1 experiment, run:

```bash
# from build/test
rm *.dat
echo -e "option\n10\n2\n1" > input.txt
./tests ArtifactCCS24
```

Replace `option` with one of the following:

- `PlotFig1a1b1c`
- `PlotFig1d`
- `PlotFig1e`
- `PlotFig1f`

The three numeric inputs specify the number of test messages of length `(8, 16, 32)`, length `64`, and length `128`, respectively. To reduce running time, set the last number to `0` to skip tests for messages of length `128`.

After generating the `.dat` files, plot the results using:

```bash
python3 ./PlotFigure.py Figure1x
```

Replace `x` with the relevant subplot label.

#### Table 1

To generate the data for Table 1, run:

```bash
# from build/test
./TestScriptMakingTable1data.sh
```

After generating the `.dat` files, create the table using:

```bash
python2 ./PdfGenTable1.py
```

## Conditional TypTop

The `CondTypTopCPP` component applies Conditional Encryption to TypTop, a typo-tolerant password-checking system. The goal is to strengthen the privacy/security of typo-tolerant password checking by replacing the underlying public-key encryption component with Conditional Encryption.

### Build

Clone the repository and enter the Conditional TypTop directory:

```bash
git clone https://github.com/mhassanameri/CondEncCCS24Artifact.git
cd CondEncCCS24Artifact/CondTypTopCPP
```

Build the Argon2 libraries:

```bash
cd argon2/phcargon2
make
make test
sudo make install
cd ../../
```

Create a build directory and compile Conditional TypTop:

```bash
mkdir build && cd build
cmake ../
make
```

If `make` fails with errors related to `g_argvPathHint`, run the following script from the build directory and then run `make` again:

```bash
./FixingTestInstallCryptoPP.sh
make
```

### Basic tests

After building, run the basic test:

```bash
# from build/test
./tests
```

During execution, you may see:

```bash
"A valid typo is detected"
```

which indicates that the typo satisfies the predicate. You may also see:

```bash
CHECK_FALSE( tp.check(pws[1], FIRST_TIME, false) )
with expansion:
!true
```

which indicates that the tested typo does not satisfy the predicate.

### Reproducing Table 2

Table 2 in the paper compares the performance of the original TypTop system and Conditional TypTop under four configurations:

1. No optimization, using a memory-hard function (MHF).
2. No optimization, not using an MHF.
3. Optimization for the Hamming-distance-at-most-2 predicate, using an MHF.
4. Optimization for the Hamming-distance-at-most-2 predicate, not using an MHF.

To generate the data for Table 2, run:

```bash
# from build/test
./TestScript.sh
```

To visualize the results, run:

```bash
# from build/test
./PlotFigureCondTypTop.py
```

## Citation

If you use this artifact, please cite the ACM CCS 2024 paper:

```bibtex
@inproceedings{conditional-encryption-ccs2024,
  title     = {Conditional Encryption},
  author    = {[add author list]},
  booktitle = {Proceedings of the ACM Conference on Computer and Communications Security (CCS)},
  year      = {2024}
}
```

## Notes

- This artifact is intended for research reproducibility and experimental evaluation.
- Some scripts may take substantial time depending on the selected message lengths and number of test cases.
- For faster local checks, use the basic tests before running the full evaluation scripts.
