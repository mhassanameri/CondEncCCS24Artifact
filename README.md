# Conditional Encryption

## Introduction

**Conditional Encryption** is public key cryptographic primitive which helps us to conditionally, under a binary predicate like $P(m_1, m_2)$, encrypt a the payload message $m_3$ given a regular ciphertext $c_1 = \text{Enc}(pk, m_1)$ encrypting an unknown message $m_1$. In the predicate, we call $m_2$ the control message. If the predicate holds, i.e. $P(m_1, m_2) = 1$, $c' = \text{CondEnc}(pk, c_1, m_2,m_3 )$ is the encryption of the payload message $m_3$, and the person who knows the secret key can extract $m_3$; if the predicate does not hold, i.e., $P(m_1, m_2) = 0$, $c' = \text{CondEnc}(pk, c, m_2, m_3)$ is the encryption of a random message **unrelated** to $m_1$, $m_2$, or $m_3$, and $c'$ does not leak any information about $m_2$ or $m_3$ to the adversary (who may even know the secret key!). The predicate can be edit distance at most 1, hamming distance at most 2, etc. In this repository, we provide a comprehensive implementation of conditional encryption in CPP and evaluate its performance in terms of regualar/conditional encryption time, conditional decryption time, and regular/conditional ciphertext sizes. In addition, as an application of conditional encryption, we improved the security of the [TypTop system](https://github.com/rchatterjee/typtopcpp) by replacing the public key encryption with our conditional encryption scheme.
 
The following groups of binary predicates $P(m_1, m_2)$ are available in our implementation: 

- **Equality Test**: $P(m_1, m_2) = 1$ if and only if $m_1 = m_2$
- **Edit-Distance at most 1**: $P(m_1, m_2) = \text{EditDistance}(m_1, m_2) \leq 1$
- **Hamming distance at most $l$**: $P(m_1, m_2) = \text{Ham}(m_1, m_2) \leq l$
- **CAPSLOCK error**: $P(m_1, m_2) = 1$ if and only if $m_1 = \text{InvertCase}(m_2)$
- **OR Composition**: the OR composition of any combination of the predicates mentioned above

The project is divided into two parts, the Conditional Encryption implementation, and the improved TypTop implementation, located in [CondEncCPP](CondEncCPP) and [CondTypTopCPP](CondTypTopCPP) respectively. For instructions on building and testing, see [CondEnc](#conditional-encryption) and [CondTypTop](#Conditional-TypTop).

## Dependencies
To compile the project, you will need the following:
* `cmake >= 3.28`
  ```bash
    wget https://github.com/Kitware/CMake/releases/download/v3.30.3/cmake-3.30.3.tar.gz
    tar -xvzf cmake-3.30.3.tar.gz
    ./configure
    make
    sudo make install
  ```
* `protobuf` ([source](https://protobuf.dev/overview/), in debian use `sudo apt install protobuf-compiler`)
* `pam-dev` (in debian use `sudo apt-get install libpam0g-dev`)
* `cURL` (in debian use `sudo apt install libcurl4-openssl-dev`)
* `catch2` ([source](https://github.com/catchorg/Catch2), clone the repository and build)
  ```bash
    git clone https://github.com/catchorg/Catch2.git
    cd Catch2
    cmake -Bbuild -H. -DBUILD_TESTING=OFF
    sudo cmake --build build/ --target install
  ```
* `cryptopp`, `zxcvbn` and `plog` (inside the repository, will automatically build)
* `Argon2` memory hard functions ([Source](https://github.com/P-H-C/phc-winner-argon2), only required for Conditional TypTop, inside the repository and requires manually building)

## Conditional Encryption

### Building

Clone the repository
```bash
git clone https://github.com/mhassanameri/CondEncCCS24Artifact.git
cd CondEncCCS24Artifact/CondEncCPP
```

Create a build directory and build the program

```bash
mkdir build && cd build
cmake ../
make
```
If the make command failed with errors related to `g_argvPathHint`, in the build directory run `FixingTestInstallCryptoPP.sh`, then run `make` again.

### Basic Tests

After building, run some basic tests to ensure that conditional encryption and decryption are functioning correctly:

```bash
echo -e "all\n25\n1024\n32\n2" > BasicTestInputs.txt
./tests ArtifactCCS24BasicTests
```
* `all` means testing all predicates, for specific predicates, change to `HamDistT`, `EDOne`, `CAPSLOCK`, and `OR` for specific predicates.
* 25 specifies the number of different messages $m_1$ and its corresponding typos that are being tested
* 1024 specifies the size of the public key
* 32 specifies the length of the messages $m_1$, other options are 8, 16, 64, or 128
* 2

Under normal conditoins, the basic tests should take at most <expected time> to complete.

### Reproducing Results 

We provide scripts that reproduce the results demonstrated in the paper, follow the instructions to generate `.dat` files that can be used to create plots in latex.

#### Figure 1

Figure 1 contains nine subplots, (1a) to (1i). To generate the data for figure (1x) for some x, use

```bash
# in directory build/test
rm *.dat
echo -e "option\n10\n2\n1" > input.txt
./tests ArtifactCCS24
```

`option` can be `PlotFig1a1b1c`, `PlotFig1d`, `PlotFig1e`, or `PlotFig1f`, depending the figure you want to generate. The following three numbers are the number of test messages of length (8, 16, 32), the number of test messages of length 64, and the number of test messages of length 128, respectively. To avoid the program taking too long to run, set the last number to be $0$ to avoid running tests for messages of length 128.

Under normal conditions, this command should take time at most <expected time>. After generating the `.dat` files, one can visualize the results using

```bash
python3 ./PlotFigure.py Figure1x
```
where `x` is the figure you want to plot.

#### Table 1

Use the command to generate the data form table 1

```bash
# in directory build/test
./TestScriptMakingTable1data.sh
```

Under normal conditions, this command should take time at most <insert expected time>. After generating the `.dat` files, one can visualize the results using

```bash
python2 ./PdfGenTable1.py
```

## Conditional TypTop

### Building

Clone the repository
```bash
git clone https://github.com/mhassanameri/CondEncCCS24Artifact.git
cd CondEncCCS24Artifact/CondTypTopCPP
```
Build the Argon2 libraries
```bash
cd argon2/phcargon2
make
make test 
sudo make install
cd ../../
```

Create a build directory and build the program

```bash
mkdir build && cd build
cmake ../
make
```

If the make command failed with errors related to `g_argvPathHint`, in the build directory run `FixingTestInstallCryptoPP.sh`, then run `make` again.

### Basic Tests

After building, run a basic test to ensure that conditional encryption and decryption are functioning correctly:

```bash
<insert basic test script>
```

## More details on Tests

More specifically, for the aim of this Artifact Evaluation, we provide instructions on reproducing the results demonstrated in the paper. We provide bash scripts called 'TestScript.sh' that creates `CondTypTopEval.dat` file, which can be used to generate a pdf file containing a table which shpws the performance evaluation of our target CondTypTop under for difference cases: 

1. No Optimization and Using Memory Hard Function (MHF)
2. No Optimization and not Using MHF
3. HamingDistanceAtmost2 specific Optimization and using MHF
4. HamingDistanceAtmost2 specific Optimization and not using MHF

After compiling the project by executing `./test/TestScript.sh` the file `CondTypTopEval.dat` will be generated. 
Then you can run 'python ./PlotFigureCondTypTop.py' you can see Table 2 (of the paper) in on-page pdf comparing the above four cases.  Note that, to have the output file as pdf, you need to have 'pandas' install in your machine. 

#### Example
Once you executed `./test/TestScript.sh` on terminal you may see the following lines which indicates that typtop usage of conditional 
encryption is working correctly. 


if the random chosen typo is not satisfying the OR predicate (while logging in with wrong password)
```bash
CHECK_FALSE( tp.check(pws[1], FIRST_TIME, false) ) 
with expansion:
!true
```

Or 
```bash
A valid typo is detected
```
And finally once the test is finished sucecesfully, the terminal shows 
```bash
round #100
```
if you specify 100 as the number of test cases in (`TestScript.sh`). 

The numbers in generated table by `./PlotFigureCondTypTop.py` corresponding to the execution time are computed in microseconds. 

<!-- old

# CondEnc-CPP #

## ACM-CCS24 Artifact Documentation
[comment]: <> ([![Build Status]&#40;https://www.cs.purdue.edu/homes/mameriek/CondEnccpp.svg?branch=master&#41;]&#40;https://travis-ci.org/rchatterjee/typtopcpp&#41;)

[comment]: <> ([![Build Status]&#40;https://www.cs.purdue.edu/homes/mameriek&#41;]&#40;https://www.cs.purdue.edu/homes/mameriek&#41;)

**tl;dr** Conditional Encryption: "acronymed CondEnc" is public key cryptographic primitive which helps us to conditionally (under a binary predicate like `P(m_1, m_2)`) encrypt a the payload message `m_3` given a regular ciphertext `c_1 = Enc(pk, m_1)` encrypting an unknown message `m_1`. In the predicate, we call `m_2` the control message. That is, if the predicate `P(m_1, m_2) = 1` then `c' = ConEnc(pk, c_1, m_2,m_3 )` is the encryption of the payload message `m_3`, and the person who knows the secret key can extract `m_3`. If the predicate does not hold, i.e., `P(m_1, m_2)= 0`, then `c' = CondEnc(pk, c, m_2, m_3)` is the encryption of a random message unrelated to `m_1, m_2, m_3` and does not leak any information about `m_2, m_3` to the adversary (who may even know the secret key). The predicate can simply be edit distance, hamming distance at most 2, etc. In this repository, we provided a comprehensive implementation of conditional encryption via CPP and evaluate its performance in terms of regualar encryption time, conditional encryption time, conditional decryption, as well the regular/conditional ciphertext size.
 
In summary, we implemented conditional encryption for groups of binary predicates which are: edit distance 1, arbitrary Hamming distnace [at most 1, at most 2, at most 3 and at most 4], CAPSLOCK_ON error, equality test and Or of 'Edit distance at most 1, Hamming distance at most 2, CAPSLOCK_ON' predicates. In addition, as a practical application of conditional encryption, we improved the security of the TypTop system [here](https://github.com/rchatterjee/typtopcpp) by replacing the public key encryption with our conditional encryption scheme. In what follows we mention the dependencies and the way to install and compile each project on your local machine.

## Dependencies
To compile the project from source, you will need the following:
* `cmake >= 3.28`
     ```bash
      $ wget https://github.com/Kitware/CMake/releases/download/v3.30.3/cmake-3.30.3.tar.gz
      $ tar -xvzf cmake-3.30.3.tar.gz
      $ ./configure
      $ make
      $ sudo make install
  
* `protobuf` [source](https://protobuf.dev/overview/) (in debian use sudo `apt install protobuf-compiler`)
* `pam-dev` (in debian use `sudo apt-get install libpam0g-dev`)
* `cURL` (in debian use `sudo apt install libcurl4-openssl-dev`)
* `catch2` [source](https://github.com/catchorg/Catch2) (to install, clone the repository and build)
     ```bash
      $ git clone https://github.com/catchorg/Catch2.git
      $ cd Catch2
      $ cmake -Bbuild -H. -DBUILD_TESTING=OFF
      $ sudo cmake --build build/ --target install
* `cryptopp`, `zxcvbn` and `plog` (inside the repository, will automatically build)
* `Argon2` memory hard functions [Source](https://github.com/P-H-C/phc-winner-argon2) (inside the repository, requires manually building)



## Building the project (Just Conditional Encryption)
Clone the repository
```bash
$ git clone https://github.com/mhassanameri/CondEncCCS24Artifact.git
$ cd CondEncCCS24Artifact/CondEncCPP
```
Build the Argon2 libraries
```bash
$ cd argon2/phcargon2
$ make
$ make test # to verify that build produced valid results
$ sudo make install # install argon2 to system
$ cd ../../
```
Create a build directory and build the program
```bash
$ mkdir build && cd build
$ cmake ../
$ make
```
If the make command failed with errors related to `g_argvPathHint`, in the build directory run `FixingTestInstallCryptoPP.sh`, then run `make` again. Finally, use
```bash
$ ./test/tests
```
to execute a tests to verify that implementations of all Conditional Encryption schemes associated with the predicates: Hamming Distance at most T, Edit distance at most one, CAPSLOCK_ON, and OR_of_CAPSLOCK_HamDist2_EditDist1 are working correctly.


## More details on Tests

More specifically, for the aim of this Artifact Evaluation, we provide instructions on reproducing the results demonstrated in the paper. We provide bash scripts that create `.dat` files, which can be used to generate the plots in latex.

### Generate Figure 1a and 1b 
After compiling the project, go to `build/test` and run `TestScript.sh`. For this script, we can modify the `input.txt` file to generate the desired output. The instruction on how to modify `input.txt` is commented in `TestScript.sh`. In the following, we will provide an examples on how to generate Figure 1a of the paper. 

#### Example
```bash
$ ./TestScript.sh
$ python3 ./PlotFigure.py Figure1a
```

and for Table 1 (CondEnc messge len =32)

```bash
$ ./TestScriptMakingTable1data.sh
$ python3 ./PdfGenTable1.py
```
Or for CondTypTop (Table 2)
```bash 
$ ./TestScript.sh
$ python3 ./PlotFigureCondTypTop.py
```



## Building the project (CondTypTop: TyoTop System using CondEnc)
Clone the repository
```bash
$ git clone https://github.com/mhassanameri/CondEncCCS24Artifact.git
$ cd CondEncCCS24Artifact/CondTypTopCPP
```
Build the Argon2 libraries
```bash
$ cd argon2/phcargon2
$ make
$ make test 
$ sudo make install
$ cd ../../
```
Create a build directory and build the program
```bash
$ mkdir build && cd build
$ cmake ../
$ make
```
If the make command failed with errors related to `g_argvPathHint`, in the build directory run `FixingTestInstallCryptoPP.sh`, then run `make` again. Finally, use
```bash
$ ./test/tests
```
to execute a tests to verify that implementations of all CondTypTop schemes associated with the OR of Hamming Distance at most 2, Edit distance at most one, CAPSLOCK_ON is working correctly.


## More details on Tests

More specifically, for the aim of this Artifact Evaluation, we provide instructions on reproducing the results demonstrated in the paper. We provide bash scripts called 'TestScript.sh' that creates `CondTypTopEval.dat` file, which can be used to generate a pdf file containing a table which shpws the performance evaluation of our target CondTypTop under for difference cases: 

1. No Optimization and Using Memory Hard Function (MHF)
2. No Optimization and not Using MHF
3. HamingDistanceAtmost2 specific Optimization and using MHF
4. HamingDistanceAtmost2 specific Optimization and not using MHF

After compiling the project by executing `./test/TestScript.sh` the file `CondTypTopEval.dat` will be generated. 
Then you can run 'python ./PlotFigureCondTypTop.py' you can see Table 2 (of the paper) in on-page pdf comparing the above four cases.  Note that, to have the output file as pdf, you need to have 'pandas' install in your machine. 

#### Example
Once you executed `./test/TestScript.sh` on terminal you may see the following lines which indicates that typtop usage of conditional 
encryption is working correctly. 


if the random chosen typo is not satisfying the OR predicate (while logging in with wrong password)
```bash
$ CHECK_FALSE( tp.check(pws[1], FIRST_TIME, false) ) 
$ with expansion:
$ !true
```

Or 
```bash
$ A valid typo is detected
```
And finally once the test is finished sucecesfully, the terminal shows 
```bash
$ round #100
```
if you specify 100 as the number of test cases in (`TestScript.sh`). 

The numbers in generated table by `./PlotFigureCondTypTop.py` corresponding to the execution time are computed in microseconds. 

-->

