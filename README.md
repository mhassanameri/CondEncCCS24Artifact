# CondEnc-CPP #

## ACM-CCS24 Artifact Documentation
[comment]: <> ([![Build Status]&#40;https://www.cs.purdue.edu/homes/mameriek/CondEnccpp.svg?branch=master&#41;]&#40;https://travis-ci.org/rchatterjee/typtopcpp&#41;)

[comment]: <> ([![Build Status]&#40;https://www.cs.purdue.edu/homes/mameriek&#41;]&#40;https://www.cs.purdue.edu/homes/mameriek&#41;)

**tl;dr** Conditional Encryption: 'acronymed CondEnc' is public key cryptographic premitive which helps us to conditionally under a binary predicate like `P(m_1, m_2)` encrypt a the payload message `m_3` given regular ciphertext `c_1 = Enc(pk, m_1)` encrypting an unknown message `m_1`. In the predicate, we call `m_2` the control message. That is if the predicate `P(m_1, m_2) = 1` then `c' = ConEnc(pk, c_1, m_2,m_3 )` is the encryption of the payload message `m_3` and the person who knows the secret key can extract `m_3`. If the predicate is not holding, i.e., `P(m_1, m_2)= 0`, then `c' = CondEnc(pk, c, m_2, m_3)` is encryption of a random message unrelated to `m_1, m_2, m_3` and does not leak any information about `m_2, m_3` to the adversary (who may even know the secret key). The predicate can simply be edit distance, hamming distance at most 2 etc. In this repository, we provided a comprehensive implementation of conditional encryption via CPP and evaluate its performance in terms of regualar encryption time, conditional encryption time conditional decryption as well the regular/conditional ciphertext size.
 
In summary, we implemented conditional encryption for group of binary predicates which are: edit distance 1, arbitrary Hamming distnace [at most 1, at most 2, at most 3 and at most 4], CAPSLOCK_ON error, Equality test and Or of 'Edit distance at most 1, Hamming distance at most 2, CAPSLOCK_ON' predicates. In addition, as a practical application of the conditional encryption, we improved the security of TypTop system [here](https://github.com/rchatterjee/typtopcpp) by replacing the public key encryption with our conditional encryption scheme. In what follows we mention the dependencies and the way to install and compile each project on your local machine.



## Dependencies
For compiling the project from source, you need following libraries.
* `cmake >= 3.6`
* Depends on Google `protobuf`
* `pam-dev`
* `cURL` (in debian install `libcurl4-openssl-dev`)
* Includes `cryptopp`, `zxcvbn` and `plog` (inside)
* Installing `Argon2` Memoery hard functions ([Source](https://github.com/P-H-C/phc-winner-argon2))


## Install

## Compile/Build Conditional Encryption
### The corrsponding working directory: ``./CondEncCPP''
```bash
$ cd CondEncPP && mkdir build 
$ cd build && cmake .. 
$ make -j 
$ ./test/tests #basically you can run the test cases and see how the conditional encryption works. ... 
```

More specifically, for the aime of Artifact Evaluation, In what follows we provide the instruction how to generate the results mentioned in the paper. We prrovide bash scripts which is run to generate the ".dat" files to be used in latex to generate the plots. 

### Generate Figure 1a and 1b 
After compiling the project in build directory, go to path build/test and run the TestScript.sh script. In this script we can modify the input.txt to generate the desired output (The instruction on how to modify the input.txt file is commented in the TestScript.sh file as well) In the following we will provide the example on how to generate Figure 1a of the paper. 

#### Example
will be added here very soon. 


