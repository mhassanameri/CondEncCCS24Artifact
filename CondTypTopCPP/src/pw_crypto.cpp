//
// Created by Rahul Chatterjee on 3/27/17.
//

//#include "library.h"
#include <cassert>
#include "gcm.h"
using CryptoPP::GCM;

#include "pw_crypto.h"
//#include "paillierh.h"

//#include <gmp.h>

//bool _can_init_Paill = false;
//bool _can_init_Paill = false;



string hmac256(const SecByteBlock& key, const string& msg) {
    HMAC< SHA256 > hmac(key, key.size());
    string res;
    StringSource ss(msg, true, new HashFilter(hmac, new StringSink(res)));
    return res;
}

void PkCrypto::set_params() {
//    _sk.AccessGroupParameters().SetPointCompression(true);
//    _sk.AccessGroupParameters().SetEncodeAsOID(true);
//    _pk.AccessGroupParameters().SetPointCompression(true);
//    _pk.AccessGroupParameters().SetEncodeAsOID(true);
}

void PkCrypto::set_pk(const string& pk) {
    StringSource ss((const CryptoPP::byte*)pk.data(), pk.size(), true);
    // _pk.BERDecode(ss);
//    _pk.Load(ss);
//    _pk.ThrowIfInvalid(PRNG, 3);
    _can_encrypt = true;
    set_params();
//    Paill_pk_init(n_lambda);
}

void PkCrypto::set_pk_Pail(const string& pk) {
    std::string hexPK = pk;
    _ppk = paillier_pubkey_from_hex(&hexPK[0]);

//    _ppk = pk_Pail_Extract();
    _can_encrypt_Pail = true;
}

void PkCrypto::set_sk_Pail(const string& sk, bool gen_pk) {


//    _ppk = pk_Pail_Extract();
//    char* hexPubKey = sk;
//    _psk = paillier_prvkey_from_hex((char*)sk[0], _ppk);
    std::string Sk_hex = sk;

    _psk = paillier_prvkey_from_hex(&Sk_hex[0], _ppk);
    if (gen_pk)
    {
        Paill_pk_init(n_lambda);
        _can_encrypt_Pail = true;

    }

    _can_decrypt_Pail = true;
//    _can_encrypt = false;
}
void PkCrypto::set_sk(const string& sk, bool gen_pk) {
    StringSource ss((const CryptoPP::byte*)sk.data(), sk.size(), true);
    // _sk.BERDecode(ss);

//    _sk.Load(ss);
//    _sk.ThrowIfInvalid(PRNG, 3);
    if(gen_pk) {
//        _sk.MakePublicKey(_pk);
        _can_encrypt = true;
    }
    _can_decrypt = true;
    set_params();
}
void PkCrypto::initialize() {
//    _sk.Initialize(PRNG, CURVE);
//    _sk.MakePublicKey(_pk);
//    /* Added By Hassan */
//    int n = 1024; //This value is selected based on the fact the the size pwds is less thant 32 chars.
    Paill_pk_init(n_lambda);
//    this->_psk = sk_Pail_Extract();//TODO: make sure this way of allocation is ok or not., I  think no need for this part
//    this->_ppk = pk_Pail_Extract();
    /* ++++ + +++ */

    _can_encrypt = true;
    _can_decrypt = true;
//    this->_can_init_Paill = true;
    _can_decrypt_Pail = true;
    _can_encrypt_Pail = true;
}

//const bool PkCrypto::allow_encrypt() const
//{
//    allow_init_paillier = true;
//}

const string PkCrypto::serialize_pk() {
    assert(_can_encrypt);
    string s;
    StringSink ss(s);
    set_params();
    //_pk.DEREncode(StringSink(s).Ref());
//    _pk.Save(ss);
    return s;
}

const string PkCrypto::serialize_sk() {
    assert(_can_decrypt);
    string s;
    set_params();
    StringSink ss(s);
    // _sk.BEREncode(ss);
//    _sk.Save(ss);
    return s;
}

void PkCrypto::pk_encrypt(const string &msg, string &ctx) const {
//    ctx.clear();
//    if(!_can_encrypt) throw("Cannot encrypt");
//    auto e = myECIES::Encryptor(_pk);
//    StringSource((const byte*)msg.data(), msg.size(), true,
//                 new CryptoPP::PK_EncryptorFilter(PRNG, e, new StringSink(ctx)));

}

void PkCrypto::pk_decrypt(const string& ctx, string& msg) const {
    if(!_can_decrypt) throw("Cannot decrypt");

//    msg.clear();
//    auto d = myECIES::Decryptor(_sk);
//    StringSource ss((const byte*)ctx.data(), ctx.size(), true,
//                    new CryptoPP::PK_DecryptorFilter(PRNG, d, new StringSink(msg)));
}


/*
 * This function takes as input the givnen ciphertext as string and output a vector of size at most "_len + 1"
 * vector depending on the value b,
 * If b =  0, then the ciphertextxt is traditional ciphertext of byte-by-byte encryption of the input messag, otherwise
 * If b = 1, it indecates that the input ciphrtext is result of conditional encrytpion and will be tokenized accordingly.
* */
inline vector<paillier_ciphertext_t*> PkCrypto::Parse_Real_Pass_Ctx(paillier_pubkey_t* ppk, const string& ctx,
                                                                    int& VecSize, string &CtxAE, int b) const {

    vector<paillier_ciphertext_t*> vctx;

    char* byteCtxt1;
//    = (char*)malloc(PAILLIER_BITS_TO_BYTES(ppk->bits)*2 );

    std::string delimiter = "%VVV";
    string s =  ctx;
    int counter = 0;
    int AECtxContr = 0;
    size_t pos = 0;
    std::string token;
    while ((pos = s.find(delimiter)) != std::string::npos) {
        token = s.substr(0, pos);
        if (AECtxContr == 0 && b == 1)
        {
            CtxAE = token;
            s.erase(0, pos + delimiter.length());
            AECtxContr++;
        }else {
            vctx.push_back (paillier_create_enc_zero());
            mpz_set_str(vctx[counter]->c,token.c_str(),10);
            s.erase(0, pos + delimiter.length());
            counter++;
        }
    }
    VecSize = counter;
    return  vctx;

}



/*This function takes the padded pwssword as input.*/
//void PkCrypto::Paill_pk_encrypt(const string &msg, string &ctx) const
//void PkCrypto::Paill_pk_encrypt(const string &msg, vector<paillier_ciphertext_t*> &ctx) const

void PkCrypto::Paill_pk_init( int n)
{

    paillier_keygen(n, &_ppk, &_psk, paillier_get_rand_devurandom);
//     _can_init_Paill = true;

//     free(hexSecKey);
//     free(hexPubKey);
}
//void PkCrypto::Paill_pk_encrypt(vector<paillier_ciphertext_t*> &vctx, const string &msg, string &ctx) const

void PkCrypto::Paill_pk_encrypt(const string &msg, string &ctx) const
//void PkCrypto::Paill_pk_encrypt(const string &msg, vector<paillier_ciphertext_t*> vctx) const
{
    if(!_can_encrypt_Pail) throw("Cannot encrypt using paillier");
    paillier_pubkey_t* ppk;
    ppk =_ppk; //TODO: Double chekc this part as well.
    std::string msg_e = msg;
    msg_e[msg_e.size()] = '\0';
    ctx.clear();

    if (_Edit_distOne == true)
    {
        /*
         * If _Edit_distanceOne = True, we need to encrypt the m_{-i}s. This part handle that part
         * */

        auto& str_Shrs = msg;
        int msg_size =str_Shrs.size();
        vector<char*> byteVCtx(msg_size);
        paillier_ciphertext_t * Ctxt_z;
        vector<paillier_ciphertext_t *> VCtxt_z(msg_size);

        unsigned char a_z[msg.size()];
        for (int i = 0; i <= msg.size(); i++)
        {
            a_z[i] = str_Shrs[i];
        }
        mpz_t aux;
        paillier_plaintext_t* m;
        m = (paillier_plaintext_t*) malloc(sizeof(paillier_plaintext_t));
        mpz_import(aux, msg.size(), -1, 1, 0, 0, &a_z[0]);
        mpz_init_set(m->m, aux);
        Ctxt_z = paillier_enc(NULL, ppk, m, paillier_get_rand_devrandom);
        ctx = mpz_get_str(NULL, 10, Ctxt_z->c);
        ctx = ctx + "%VVV";
        for (int i = 0; i < msg_size; i++)
        {
            string sub_i = str_Shrs.substr (0,i) +  str_Shrs.substr (i+1,msg_size);
            unsigned char a[sub_i.size() ];
            for (int j = 0; j <sub_i.size(); ++j)
            {
                    a[j] =  sub_i[j];
            }
            paillier_plaintext_t* m;
            mpz_t aux;
            mpz_init(aux);
            m = (paillier_plaintext_t*) malloc(sizeof(paillier_plaintext_t));
            mpz_import(aux, sub_i.size(), -1, 1, 0, 0, &a[0]);
            mpz_init_set(m->m, aux);
            VCtxt_z[i] = paillier_enc(NULL, ppk, m, paillier_get_rand_devrandom);
            byteVCtx[i] = mpz_get_str(NULL, 10, VCtxt_z[i]->c);
        }
        for (int i=0; i< msg.size();  i++)
        {
            ctx = ctx + byteVCtx[i];
            ctx = ctx + "%VVV";
        }
        ctx[ctx.size()+1] = NULL;
    }else if (_trad_enc_Paill == true)
    {
        auto& str = msg;
        std::string s(std::begin(str), std::end(str));
//        string m_str = b64encode(s);
        char m_cpy[s.size()];
        for (int j = 0; j <= s.size() ; ++j)
        {
            m_cpy[j] = s[j];
        }


        paillier_plaintext_t * message;
        paillier_ciphertext_t * c_message;

        message = paillier_plaintext_from_bytes( m_cpy, s.size());
//        message = paillier_plaintext_from_str(m_cpy);
        char* bytes_c_msg;

//        message = paillier_plaintext_from_str( (char*)msg.data());
        c_message = paillier_enc(NULL, ppk, message, paillier_get_rand_devrandom);
        bytes_c_msg =(char*) paillier_ciphertext_to_bytes(PAILLIER_BITS_TO_BYTES(ppk->bits)*2, c_message);
//        strncpy((char*) &ctx, bytes_c_msg, PAILLIER_BITS_TO_BYTES(ppk->bits)*2 );
        ctx = bytes_c_msg;
    } else
    {
        paillier_plaintext_t* m;
        paillier_ciphertext_t* vctx;
        auto& str = msg;
        std::string s(std::begin(str), std::end(str));
        void* byteCtxt1;
        vector<char*> byteVCtx(s.size());
        vector<paillier_ciphertext_t*> SV(s.size());
        for (int j = 0; j < s.size() ; ++j)
        {
            unsigned muint;
//            muint = cc;
            muint = s[j];
//            int iu  = uc - UINT_MAX - 1;
//            m = pallier_plaintext_from_ui(cc);
            m = paillier_plaintext_from_ui(muint);

            vctx = (paillier_ciphertext_t *) malloc(sizeof(paillier_ciphertext_t));
            vctx = paillier_create_enc_zero();
            vctx = paillier_enc(NULL, _ppk, m, paillier_get_rand_devrandom);
            SV[j] = vctx;
            byteVCtx[j] = mpz_get_str(NULL, 10, vctx->c);
            byteCtxt1 =  paillier_ciphertext_to_bytes(PAILLIER_BITS_TO_BYTES(ppk->bits) *2 , vctx);
            size_t Bsze = strlen(byteVCtx[j]);

        }


        for (int i=0; i< s.size();  ++i)
        {
            ctx = ctx + byteVCtx[i];
            ctx = ctx + "%VVV";

        }
        ctx[ctx.size()+1] = NULL;

        vector<paillier_ciphertext_t*> RV;
        int VecSize =0;
        string Ctxt_0;  //For non-conditional ciphertext we expect Ctxt_0 be zero
        RV = Parse_Real_Pass_Ctx(ppk, ctx, VecSize, Ctxt_0, 0);

        for (int h=0; h< VecSize; ++h)
        {
//            assert(RV[h]->c->_mp_d == SV[h]->c->_mp_d);
            assert(mpz_cmp(RV[h]->c,SV[h]->c) == 0);
            paillier_ciphertext_t* Rctx;
//            Rctx = paillier_ciphertext_from_bytes(RV[h], PAILLIER_BITS_TO_BYTES(ppk->bits) *2);

            paillier_prvkey_t * psk;
            psk = sk_Pail_Extract();
            paillier_plaintext_t* dec;
            char* cdd;
            dec = paillier_dec(NULL, ppk, _psk, RV[h]);
//            dec = paillier_dec(NULL, ppk, psk, paillier_ciphertext_from_bytes(byteVCtx[j],PAILLIER_BITS_TO_BYTES(ppk->bits) ) );
            cdd = (char*) paillier_plaintext_to_bytes(PAILLIER_BITS_TO_BYTES(ppk->bits), dec);
            unsigned int cddd;
//            cddd = cdd[0];
            cddd = mpz_get_ui (dec->m );
            int cdii = cddd - UINT_MAX - 1;
            assert(cdii == s[h]);
            char cii = (char) cdii;
            assert(cii == s[h]);

            /*subtract debug*/
            paillier_ciphertext_t* Sub;
            paillier_ciphertext_t* Sub1;
            Sub = paillier_create_enc_zero();
            Sub1 = paillier_create_enc_zero();
            mpz_invert(Sub1->c, RV[h]->c, ppk->n_squared);
            paillier_mul(ppk, Sub, SV[h], Sub1);
            paillier_plaintext_t* dec1;
            dec1 = paillier_dec(NULL, ppk, _psk, Sub);
            char* c_Sub;
            c_Sub = (char*) paillier_plaintext_to_bytes(PAILLIER_BITS_TO_BYTES(ppk->bits), dec1);
            unsigned int cd_Sub;
//            cddd = cdd[0];
            cd_Sub = mpz_get_ui (dec1->m );
            int cdii_Sub = cd_Sub - UINT_MAX - 1;
            assert(cdii_Sub == 0);
            char cii_Sub = (char) cdii_Sub;
            assert(cii_Sub == '\0');

            /*******/
        }




    }

}

//void PkCrypto::Paill_pk_decrypt(vector<paillier_ciphertext_t*> &ctx, const string &msg) const
//void PkCrypto::Paill_pk_decrypt(vector<paillier_ciphertext_t*> &vctx, const string& ctx, string &msg) const
void PkCrypto::Paill_pk_decrypt(const string& ctx, string &msg, int b) const
{
    if(!_can_decrypt_Pail) throw("Cannot decrypt using paillier");
    paillier_pubkey_t* ppk;
    ppk = pk_Pail_Extract();
    paillier_prvkey_t* psk;
    psk = sk_Pail_Extract();
    msg.clear();
    paillier_plaintext_t* dec;

    if (_trad_enc_Paill == true)
    {
        auto& str = ctx;
        std::string s(std::begin(str), std::end(str));
        char m_cpy[s.size()];
        for (int j = 0; j <= s.size() ; ++j) {
            m_cpy[j] = s[j];
        }
//        m_cpy[s.size()]= 'NULL';
        paillier_plaintext_t * dec;
        paillier_ciphertext_t * P_ctx;
        char* cp;
        P_ctx = paillier_ciphertext_from_bytes(m_cpy,s.size());
        dec = paillier_dec(NULL, _ppk, _psk,P_ctx);
        cp = (char*) paillier_plaintext_to_str(dec);
        msg = cp;
//        string dec_m = b64decode(cp);
//        msg =b64encode(cp);
    }
    else
    {
        auto& str = ctx;
        std::string s(std::begin(str), std::end(str));
//        unsigned size = s.size()/(ppk->bits) * 4;

        int size;
        string Ctxt_0;  //For non-conditional ciphertext we expect Ctxt_0 be zero
        vector<paillier_ciphertext_t*> vctx;
        vctx = Parse_Real_Pass_Ctx(_ppk, ctx,size, Ctxt_0, b);


        for (int i = 0; i < size ; i++)
//        for (int i = 0; i <=  ctx.size()/(ppk->bits) * 4  ; i++)
//    while (FINAL2.read(byteCtxt, PAILLIER_BITS_TO_BYTES(ppk->bits)*2))
        {
//            if(strlen(paillier_plaintext_to_str(dec)) > 1 && _can_decrypt_Pail )
            if(_can_decrypt_Pail )
//            if( strtoint(char)*dec->m->_mp_d > 256 && _can_decrypt_Pail )
            {
                dec = paillier_dec(NULL, _ppk, _psk, vctx[i]);
                unsigned int cddd;
//            cddd = cdd[0];
                cddd = mpz_get_ui (dec->m );
                int cdii = 0;
                cdii = cddd - UINT_MAX - 1;
                if (strlen(paillier_plaintext_to_str(dec)) >  1)
                {
                    cdii = cddd % 256;
                }
                char cii;
                cii = (char) cdii;
                msg = msg + cii;

//                assert(strlen(paillier_plaintext_to_str(dec)) == 1 || strlen(paillier_plaintext_to_str(dec)) == 0);

            }
            else
            {
                throw("Cannot decrypt using Paillier Secret Key");
            }


        }

    }


}











