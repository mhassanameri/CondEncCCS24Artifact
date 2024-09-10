//
// Created by Rahul Chatterjee on 3/27/17.
//

#ifndef TYPTOP_C_PW_CRYPTO_H
#define TYPTOP_C_PW_CRYPTO_H

#if defined(CRYPTOPP_CXX11_NULLPTR) && !defined(NULLPTR)
# define NULLPTR nullptr
#elif !defined(NULLPTR)
# define NULLPTR NULL
#endif // CRYPTOPP_CXX11_NULLPTR

#include <string>
#include <iostream>
using std::ostream;
using std::cout;
using std::cerr;
using std::endl;
using std::ios;

#include <iomanip>
#include <string>
#include <cassert>

#include<tuple>
#include<vector>
#include <iostream>
#include <string>
#include <cstring>
#include <sstream>
#include <math.h>       /* pow */

/*Added by Hassan. */
#include "db.pb.h"

#include "../paillier/pailliercpp.h"
//#include"conditionalcrypto.h"
#include "PaillierWrapperFunctions.h"
#include "CryptoSymWrapperFunctions.h"


//#include "db.pb.h"
using namespace std;

//#include "ConditionalEncryptionOR.h"


//#include "ConditionalEncryptionEditDistOne.h"
//#include "ConditionalEncryptionEditDistOne.h"



#define DEFAULT_SEED_LENGTH 16
#define AE_CTXT_SIZ 24
typedef unsigned long ulong;

//static const uint8_t KEYSIZE_BYTES = AES::DEFAULT_KEYLENGTH;  // key size 16 bytes
//static const uint32_t PBKDF_ITERATION_CNT = 20000;   // number of hash iterations
//static const uint32_t MAC_SIZE_BYTES = 16; // size of tag
//static AutoSeededRandomPool PRNG;  // instantiate only one class
//static const OID CURVE = secp256r1();


//typedef CryptoPP::ECIES<ECP, CryptoPP::IncompatibleCofactorMultiplication, true> myECIES; //
//typedef CryptoPP::ECIES<ECP, CryptoPP::IncompatibleCofactorMultiplication> myECIES;



/* Public Key Functions */
class PkCrypto {
private:
//    unsigned int _len;
//    myECIES::PublicKey _pk;
//    myECIES::PrivateKey _sk;
    bool _can_decrypt = false;
    bool _can_encrypt = false;
    bool Typt_EdisOne = false;

public:
//    EditDistOne s;

//    mutable bool _can_init_Paill = false;
    long n_lambda = 1024;
//    int p = 2^32;
    paillier_pubkey_t* _ppk;
    paillier_prvkey_t* _psk;
    bool _can_decrypt_Pail = false;
    bool _can_encrypt_Pail = false;
    bool _trad_enc_Paill = false;
    bool _Edit_distOne = false;
    // PkCrypto();
    void set_sk_Pail(const string& sk, bool gen_pk=false);
    size_t Return_pk_size(paillier_pubkey_t* _ppk) {return PAILLIER_BITS_TO_BYTES(_ppk->bits)*2; };
    void set_pk_Pail(const string& pk);
    void set_pk(const string& pk);
    void set_sk(const string& sk, bool gen_pk=false);
    void initialize();
//    const bool allow_encrypt() const;
    const string serialize_pk();
    const string serialize_sk();
    inline bool can_decrypt() const { return _can_decrypt; }
    inline bool can_encrypt() const { return _can_encrypt; }
    void pk_encrypt(const string &msg, string &ctx) const;
    void pk_decrypt(const string& ctx, string& msg) const;

    static paillier_pubkey_t* pk_Pail_Extract(){
        std::fstream pubKeyFile("pubkey.txt", std::fstream::in);
        assert(pubKeyFile.is_open());
        std::string hexPubKey;
        std::getline(pubKeyFile, hexPubKey);
        pubKeyFile.close();
        paillier_pubkey_t*  Pail_Pk;
        Pail_Pk = paillier_pubkey_from_hex(&hexPubKey[0]);
        return Pail_Pk;
    };
/*
 * The pk_Pail_Serialzie extracts the hex format of the public key and outputs it as a string.
 * */
    static string pk_Pail_Serialize(paillier_pubkey_t* ppk){

//        std::fstream pubKeyFile("pubkey.txt", std::fstream::in);
//        assert(pubKeyFile.is_open());
        std::string hexPubKey;
        hexPubKey = paillier_pubkey_to_hex(ppk);
//        std::getline(pubKeyFile, hexPubKey);
//        pubKeyFile.close();
        return hexPubKey;
    };

    static paillier_prvkey_t* sk_Pail_Extract(){
        paillier_pubkey_t* ppk;
        ppk = pk_Pail_Extract();
        std::fstream secKeyFile("seckey.txt", std::fstream::in);
        assert(secKeyFile.is_open());
        std::string hexSecKey;
        std::getline(secKeyFile, hexSecKey);
        secKeyFile.close();
        paillier_prvkey_t*  Pail_Sk;
        Pail_Sk = paillier_prvkey_from_hex(&hexSecKey[0], ppk);
        paillier_freepubkey(ppk);
        return Pail_Sk;
    };

    static string sk_Pail_Serialize(){
        std::fstream secKeyFile("seckey.txt", std::fstream::in);
        assert(secKeyFile.is_open());
        std::string hexSecKey;
        std::getline(secKeyFile, hexSecKey);
        secKeyFile.close();
        return hexSecKey;
    };


    void Paill_pk_init(int n_lambda);
    void Paill_pk_encrypt(const string &msg, string &ctx) const;
    void Paill_pk_decrypt(const string& ctx, string& msg, int b) const;

    /*
   *Inputs:
   *  paillier_pubkey_t* ppk                   - pallier public key
   *  const string& ctx                        - the constant input ciphertext vector as string
   *  int b                                    - a number determines the type of ciphertext
   *                                                  -> b = 0: ctx is concatenation of the paillier ciphertexts of
   *                                                      encoded as decimal string separated by the token "%VVV"
   *                                                      The ciphertext is is byte-by-byte encryption of an
   *                                                      unknown message msg.
   *                                                  -> b = 1: The ciphertext contains Authenticated encryption of
   *                                                       unknown message msg under the symmetric key k and a vector
   *                                                       Paillier ciphertexts [encoded as string of integers] and
   *                                                       separated by the string token "%VVV".
   * Outputs:
   *  int VecSize                             - size of the ouput vector of paillier ciphertexts
   *  string &CtxAE                           - if b=1, then the algorithm extract the Authenticated Encryption of
   *                                              an unknown message msg
   *  vector<paillier_ciphertext_t*> vctx     - the vector of paillier ciphertexts extracted from  ctx.
   *
   * */
    inline vector<paillier_ciphertext_t*> Parse_Real_Pass_Ctx(paillier_pubkey_t* ppk,
                                                              const string& ctx,
                                                              int& VecSize,
                                                              string &CtxAE, int b) const;



    /*Conditional Encryption Tools and Algorithms*/
//    inline void HE_Pk_Dec(const string& ctx, string& msg, int &indx, char &typo_c) const;
//    inline void Paill_pk_Cond_decrypt(const string& ctx, string &msg, int &indx, char &typo_char) const;

protected:
    void set_params();
};

class Bytes;



void PrintKeyAndIV(SecByteBlock& ekey,
                   SecByteBlock& iv,
                   SecByteBlock& akey);




// Some extra useful functions
//string hmac256(const SecByteBlock& key, const string& msg);

// id size is only 8


//inline string b64encode(const string& in){ string out; b64encode((const byte*)in.data(), in.size(), out); return out; }
//inline string b64decode(const string& in) { string out; b64decode(in, out); return out; }

/*
 string bytes_to_str(const SecByteBlock& b) {
    return string((char*)b.data(), b.size());
}*/

inline std::ostream& operator<< (std::ostream& os, SecByteBlock const& value){
    string s;
    StringSource(value.data(), value.size(), true, new HexEncoder(new StringSink(s)));
    os << s;
    return os;
}



class PwPkCrypto: public PkCrypto  {
private:
    unsigned int _len = 32;
//    unsigned int _ShareStreamSizer = 38; //20 bytes for the shares of the secret key and its corresponiding index and 8 bytes for the smale secret hsaring. And as it is encoded b64encide the size will be roof of 28 * 4/3 = 38
    unsigned int _ShareStreamSizer = 28; //without any encoding scheme
    unsigned int AECTXTSIZE = 24; //without any encoding scheme

//    paillier_pubkey_t* _ppk;
//    paillier_prvkey_t* _psk;
//    bool _can_decrypt_Pail = false;
//    bool _can_encrypt_Pail = false;


public:

//    OrPredicate ORPRedFuncs;
//    EditDistOne EdiDisFuncs;
    int len_limit() const {
        return _len;
    }


    inline string pad(const string& msg) const {
        string s;
        s = msg;
        s.resize(_len, '\1');
        return s;
    }
    inline string unpad(const string& msg) const {
        string s;
        size_t n;
        for(n = 0; n < msg.size(); n++){
            if(msg[n] == '\1')
                break;
        }
        s = msg;
        s.resize(n);
        return s;
    }
    /*
     * Ensures the msg is padded to certain length before encrypting
     */
    inline void pw_pk_encrypt(const string &msg, string &ctx, paillier_pubkey_t* ppk) const {
//        PkCrypto::pk_encrypt(pad(msg), ctx);
        std::string message = msg;
        size_t ctxt_size =  PAILLIER_BITS_TO_BYTES(ppk->bits)*2;

        if (_Edit_distOne == true)
        {
            char* ctx_Classic = (char*) malloc(ctxt_size);
//            PkCrypto::Paill_pk_encrypt(msg, ctx);
            int Classic_Enc_Rslt = 0;
            Classic_Enc_Rslt = PaillerWrapperFunctions::Pail_Classic_Enc( message, ppk, ctx_Classic);
            string* ctx_poitnter = (string*) malloc(ctxt_size);

            memcpy(&ctx_poitnter[0], ctx_Classic,ctxt_size);
            ctx = ctx_Classic[0];
            free(ctx_Classic);
            free(ctx_poitnter);
        } else
            PkCrypto::Paill_pk_encrypt(pad(msg), ctx);


    }

    inline void pw_pk_decrypt(const string& ctx, string& msg) const {
        string _tmsg;
//        PkCrypto::pk_decrypt(ctx, _tmsg);
        PkCrypto::Paill_pk_decrypt(ctx, _tmsg, 0);
        msg = unpad(_tmsg);
    }

};


inline void debug_print(CryptoPP::byte* m, size_t len, string name="") {
#ifdef DEBUG
    string key_str;
    CryptoSymWrapperFunctions::Wrapper_b64encode(m, len, key_str);
    cout << name << " -> " << key_str << endl;
#endif
}




#endif //TYPTOP_C_PW_CRYPTO_H
