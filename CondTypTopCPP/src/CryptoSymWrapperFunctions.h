//
// Created by mameriek on 9/7/21.
//

#ifndef CONDENCCPP_CRYPTOSYMWRAPPERFUNCTIONS_H
#define CONDENCCPP_CRYPTOSYMWRAPPERFUNCTIONS_H

#include <string>
#include <iostream>
#include <random>
using std::ostream;
using std::cout;
using std::cerr;
using std::endl;
using std::ios;

#include <iomanip>
#include <string>
#include <cassert>
//#include <math.h>       /* pow */
#include <cmath>       /* pow */


#include<tuple>
#include<vector>
#include <iostream>
#include <string>
#include <cstring>
#include <sstream>
using std::string;

#include <cstdio>
#include <cstdlib>

//#include <../../argon2/phcargon2/include/argon2.h>
#include <argon2.h>
#define HASHLEN 16
#define SALTLEN 16



using namespace std;
#include "ecp.h"
//#include "../3rdparty/cryptopp565/ecp.h"
//#include "ecp.h"
//#include "ecp.h"
using CryptoPP::ECP;

//#include "../3rdparty/cryptopp565/eccrypto.h"
#include "eccrypto.h"
using CryptoPP::ECDH;

#include "osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include "asn.h"
#include "oids.h"
using CryptoPP::OID;
using CryptoPP::ASN1::secp256r1;

#include "cryptlib.h"
using CryptoPP::lword;
using CryptoPP::word32;
using CryptoPP::word64;
using CryptoPP::Exception;
using CryptoPP::DEFAULT_CHANNEL;
using CryptoPP::AAD_CHANNEL;
using CryptoPP::PrivateKey;
using CryptoPP::PublicKey;
using CryptoPP::DL_PrivateKey_EC;
using CryptoPP::DL_PublicKey_EC;

#include "pch.h"

//#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#include "ida.h"
//#include "cryptlib.h"
#include "cpu.h"
#include "validate.h"
using CryptoPP::RandomNumberGenerator;
//#include <validate.h>

#include "asn.h"
#include "gf2n.h"
#include "default.h"
#include "integer.h"
#include "polynomi.h"
#include "channels.h"

//#include "ida.h"
#include "gzip.h"
#include "zlib.h"


#include "secblock.h"
using CryptoPP::SecByteBlock;
using CryptoPP::SecBlock;

#include "hex.h"
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

#include "filters.h"
#include "aes.h"
#include "gcm.h"

using CryptoPP::Redirector;
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::StreamTransformationFilter;
using CryptoPP::HashVerificationFilter;
using CryptoPP::HashFilter;
using CryptoPP::AuthenticatedEncryptionFilter;
using CryptoPP::AuthenticatedDecryptionFilter;
using CryptoPP::AES;
using CryptoPP::GCM;
using CryptoPP::SecByteBlock;

#include "files.h"
using CryptoPP::FileSink;

#include "sha.h"
using CryptoPP::SHA256;
using CryptoPP::SHA512;

#include "aes.h"
using CryptoPP::AES;

#include "modes.h"
using CryptoPP::CBC_Mode;

#include "pwdbased.h"
using CryptoPP::PKCS5_PBKDF2_HMAC;

#include "hmac.h"
using CryptoPP::HMAC;

#include "base64.h"
using CryptoPP::Base64URLEncoder;
using CryptoPP::Base64URLDecoder;

//#include "scrypt.h"
//#include "../3rdparty/cryptopp/include/cryptopp/scrypt.h"
//#include "opt/local/include/cryptopp/scrypt.h"
/*Added by Hassan. */
//#include "db.pb.h"


//#include "../paillier/pailliercpp.h"



//#include "db.pb.h"

#define DEFAULT_SEED_LENGTH 16
// typedef unsigned char CondEnc_byte;


typedef unsigned long ulong;
static const uint8_t KEYSIZE_BYTES = AES::DEFAULT_KEYLENGTH;  // key size 16 bytes
static const uint8_t SALTSIZE_BYTES_HASH = AES::DEFAULT_KEYLENGTH;  // The salt size as the inout of hash function.(16 bytes)
static const uint8_t HASHOUT_BYTES_SIZE = AES::DEFAULT_KEYLENGTH;  // The output size of hash funciton (16 bytes)

/*Settimg the paramaters of the used memory hard function, Arogn2*/
static const uint32_t T_COST        = 2;                   // 2-pass computation for the memory hard function, Argon2 library.
static const uint32_t M_COST        = 16 * (1<<16);        // 1 Giga bibytes memory usage
static const uint32_t PARALLELISM   = 4;       // number of threads and the cpus, the value of 4 is a normal value which can be supported by most of operating systems.

static const uint32_t PBKDF_ITERATION_CNT = 20000;   // number of hash iterations
static const uint32_t MAC_SIZE_BYTES = 16; // size of tag
static AutoSeededRandomPool PRNG;  // instantiate only one class
static const OID CURVE = secp256r1();

typedef CryptoPP::ECIES<ECP, CryptoPP::IncompatibleCofactorMultiplication> myECIES;
//typedef CryptoPP::ECIES<ECP, CryptoPP::IncompatibleCofactorMultiplication, true> myECIES; //TODO: working with the older version of cryptopp.



class CryptoSymWrapperFunctions {
    public:


    /*
     * The function which will be used for padding and unpadding the the imput message. Sometimes, we need to
     * pad the input message to certain lenght before encrypting it.
     * */

    static string Wrapper_pad(const string& msg, size_t len);
    static string Wrapper_unpad(const string& msg);

    static string Wrapper_pad_PKCS(const string& msg, size_t len);
    static string Wrapper_unpad_PKCS(const string& msg);
    /*
     * Useful utility fuctions for encoding the byte strings to Base64 space.
     * */
    static void Wrapper_b64encode(const CryptoPP::byte* raw_bytes, ulong len, string& str);
    static void Wrapper_b64decode(const string& str, string& byte_str);
    static string Wrapper_b64encode(SecByteBlock& raw_bytes);
    static string Wrapper_b64encode(const string& in);
    static  string Wrapper_b64decode(const string& in);



    /* Hashing and hardening related functions */
    static void Wrapper_hash256(const vector<string>&, SecByteBlock&);
    static bool Wrapper_harden_pw(const string pw, SecByteBlock& salt, SecByteBlock& key);



    /*
     * The following slow hash function, is basically a memory hard function. In our implementation, we just
     * used Scrypt which is also provided by the cryptoPP. The parameters are selected based on the Scrypt documentaion
     * which is available at the following link:
     *                      https://datatracker.ietf.org/doc/html/rfc7914
     * Based on the document suggestion we selected CPU/memory cost N = TODO: Determine N and say why?
     *  ="pleaseletmein", S="SodiumChloride",
           N=1048576 (CPU/Memory Cost), r=8 (Block Size), p=1, dkLen=6
     * */
    static void Wrapper_slow_hash(const string& msg, const SecByteBlock& salt,
                    SecByteBlock& hash);



    static string Wrapper_hmac256(const SecByteBlock& key, const string& msg);
    static uint32_t compute_id(const SecByteBlock& key, const string& msg) {
        // cheap way to convert byte array to int, susceptible to machine endianness, but fine for me
        return *(uint32_t*)Wrapper_hmac256(key, msg).substr(0, 4).data();
    }



    /* Symmetric key functions
 * Will be used with the purpose of authenticated encryption based on a symmetric key encryption scheme, like AES.
 * */

    /*
     * This function takes as input the symmetric secret key k and the secure message msg as input a
     * and outputs the reseulting ciphertext ctx. Inside this functiion, we first extract a key
     * using hardening function like typical memory hard function (in our implementation we used scrypt which
     * is proided by the CryptoPP library.
     * */
    static bool Wrapper_AuthEncrypt_Hardened(const string& k, const string& msg, string& ctx, const bool MHF_ON);
    static bool Wrapper_AuthDecrypt_Hardened(const string& k, const string& ctx, string& msg, const bool MHF_ON);


    /*
     * The smae functionality as described above, withoud hardening option.
     * */
    static bool Wrapper_AuthEncrypt(const string& k, const string& msg, string& ctx);
    static bool Wrapper_AuthDecrypt(const string& k, const string& ctx, string& msg);


//    static bool Wrapper_pwdecrypt_V2(const string& pw,const string& ctx, string& msg);


    static bool Wrapper_encrypt(const SecByteBlock& key, const string& msg, const string& extra_data, string& ctx);
    static bool Wrapper_decrypt(const SecByteBlock& key, const string& ctx, const string& extra_data, string& msg);

//    static void Pad(RandomNumberGenerator& rng, const byte *input, size_t inputLen, byte *pkcsBlock, size_t pkcsBlockLen);

};


class ShamirSecretSharing {
public:
    ShamirSecretSharing(int threshold, int numShares)
       : threshold(threshold), numShares(numShares) {
        assert(threshold > 0 && numShares >= threshold);
    }


    // Function to split the secret (0 or 1 bit) into shares
    std::vector<uint8_t> split(uint8_t secret);

    // Function to combine the shares and recover the secret
    uint8_t combine(const std::vector<uint8_t>& shares, const std::vector<uint8_t>& x_values);

private:
     int threshold;
     int numShares;

    // Generate random coefficients for the polynomial
    void generateRandomCoefficients(std::vector<uint8_t>& coefficients);

    // Evaluate the polynomial at a given x value
    uint8_t evaluatePolynomial(uint8_t secret, const std::vector<uint8_t>& coefficients, uint8_t x);

    // Compute the multiplicative inverse of a modulo m
    uint8_t modInverse(uint8_t a, uint8_t m);
};





#endif //TYPTOP_CRYPTOSYMWRAPPERFUNCTIONS_H
