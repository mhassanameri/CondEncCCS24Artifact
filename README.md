# CondEnc-CPP #

## ACM-CCS24 Artifact Documentation
[comment]: <> ([![Build Status]&#40;https://www.cs.purdue.edu/homes/mameriek/CondEnccpp.svg?branch=master&#41;]&#40;https://travis-ci.org/rchatterjee/typtopcpp&#41;)

[comment]: <> ([![Build Status]&#40;https://www.cs.purdue.edu/homes/mameriek&#41;]&#40;https://www.cs.purdue.edu/homes/mameriek&#41;)

**tl;dr** Conditional Encryption: "acronymed CondEnc" is public key cryptographic primitive which helps us to conditionally (under a binary predicate like `P(m_1, m_2)`) encrypt a the payload message `m_3` given a regular ciphertext `c_1 = Enc(pk, m_1)` encrypting an unknown message `m_1`. In the predicate, we call `m_2` the control message. That is, if the predicate `P(m_1, m_2) = 1` then `c' = ConEnc(pk, c_1, m_2,m_3 )` is the encryption of the payload message `m_3`, and the person who knows the secret key can extract `m_3`. If the predicate does not hold, i.e., `P(m_1, m_2)= 0`, then `c' = CondEnc(pk, c, m_2, m_3)` is the encryption of a random message unrelated to `m_1, m_2, m_3` and does not leak any information about `m_2, m_3` to the adversary (who may even know the secret key). The predicate can simply be edit distance, hamming distance at most 2, etc. In this repository, we provided a comprehensive implementation of conditional encryption via CPP and evaluate its performance in terms of regualar encryption time, conditional encryption time, conditional decryption, as well the regular/conditional ciphertext size.
 
In summary, we implemented conditional encryption for groups of binary predicates which are: edit distance 1, arbitrary Hamming distnace [at most 1, at most 2, at most 3 and at most 4], CAPSLOCK_ON error, equality test and Or of 'Edit distance at most 1, Hamming distance at most 2, CAPSLOCK_ON' predicates. In addition, as a practical application of conditional encryption, we improved the security of the TypTop system [here](https://github.com/rchatterjee/typtopcpp) by replacing the public key encryption with our conditional encryption scheme. In what follows we mention the dependencies and the way to install and compile each project on your local machine.



## Dependencies
To compile the project from source, you will need the following:
* `cmake >= 3.6`
* `protobuf` [source](https://protobuf.dev/overview/) (in debian use sudo `apt install protobuf-compiler`)
* `pam-dev` (in debian use `sudo apt-get install libpam0g-dev`)
* `cURL` (in debian use `sudo apt install libcurl4-openssl-dev`)
* `catch2` [source](https://github.com/catchorg/Catch2) (to install, clone the repository and build)
* `cryptopp`, `zxcvbn` and `plog` (inside the repository, will automatically build)
* `Argon2` memory hard functions [Source](https://github.com/P-H-C/phc-winner-argon2) (inside the repository, requires manually building)


## Compile/Build Conditional Encryption
Clone the repository and create a build directory
```bash
$ git clone https://github.com/mhassanameri/CondEncCCS24Artifact.git
$ cd CondEncCCS24Artifact
```
Build the Argon2 libraries
```bash
$ cd argon2/phcargon2
$ make
$ cd ../../
```
Build the program
```bash
$ mkdir build && cd build
$ cmake ../
$ make
```
If the make command failed with errors related to `g_argvPathHint`, in the build directory run `FixingTestInstallCryptoPP.sh`, then run `make` again. Finally, use
```bash
$ ./test/tests
```
to execute a basic tests to vefify that the Conditional Encryption executed correctly.

## More Tests

More specifically, for the aim of this Artifact Evaluation, we provide the instruction how to generate the results demonstrated in the paper. We provide bash scripts which generates the ".dat" files, which can be used to generate the plots in latex.

### Generate Figure 1a and 1b 
After compiling the project, go to `build/test` and run `TestScript.sh`. For this script, we can modify the `input.txt` file to generate the desired output. The instruction on how to modify `input.txt` is commented in `TestScript.sh`. In the following, we will provide an examples on how to generate Figure 1a of the paper. 

#### Example
will be added here very soon. 


