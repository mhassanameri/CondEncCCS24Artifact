//
// Created by mameriek on 9/28/21.
//

#include "ConditionalEncryptionCAPSLOCK.h"


int CAPLOCKpredicate::Enc(const paillier_pubkey_t* ppk, const string &msg, char ctx_final[])
{
    constexpr size_t Ctxt_Vec_size = 1;
    const size_t Ctxt_Byte_size =  PAILLIER_BITS_TO_BYTES(ppk->bits)*2;
//    char* ctx_final =(char*) malloc (2 * sizeof(size_t) + Ctxt_Byte_size);
    memcpy(ctx_final, &Ctxt_Vec_size, sizeof(size_t));
    memcpy(ctx_final + sizeof(size_t), &Ctxt_Byte_size, sizeof(size_t));

    auto& M = msg;
    unsigned char a_z[msg.size()];
    for (int i = 0; i < msg.size(); i++)
    {
        a_z[i] = M[i];
    }
    mpz_t aux;
    mpz_init(aux);
    auto m = static_cast<paillier_plaintext_t*>(malloc(sizeof(paillier_plaintext_t)));

    mpz_import(aux, M.size(), -1, 1, 0, 0, &a_z[0]); //In fact plays the role of ToInt to encode msg to an Integer.
    mpz_init_set(m->m, aux);
    paillier_ciphertext_t* Ctxt_z = paillier_enc(nullptr, ppk, m, paillier_get_rand_devurandom);
    // paillier_ciphertext_t* Ctxt_z = paillier_enc(nullptr, ppk, m, nullptr);

    // auto byteCtxt1 = static_cast<char*>(paillier_ciphertext_to_bytes(static_cast<int>(Ctxt_Byte_size), Ctxt_z));
    const auto byteCtxt1 = paillier_ciphertext_to_bytes(static_cast<int>(Ctxt_Byte_size), Ctxt_z);

    memcpy(ctx_final + 2 * sizeof(size_t), byteCtxt1, Ctxt_Byte_size);
    paillier_freeciphertext(Ctxt_z);
//    mpz_clear(aux);
    paillier_freeplaintext(m);
    free(byteCtxt1);
    mpz_clear(aux);
    return 1;
//    ctx = mpz_get_str(NULL, 10, Ctxt_z->c);
//    ctx = ctx + "%VVV";
}



/*
 * This function basically decrypts the conditional encryption of the typos of the original msgm when the CAPSLOCK key
 * is On. If this predicate is holding then the result of decryption is convertOpposite(msg), when ctxt is a conditional
 * encrytpion of msg and payload. Otherwise, the output of the decryption is a non-sense message which is compeletely
 * independent to the payload, typo and the original message.
 * */


// string CAPLOCKpredicate::CondEnc(paillier_pubkey_t *ppk,
//                               char RlPwd_ctx_pull[],
//                               string& msg,
//                               string& payload,
//                               size_t _len,
//                               int threshold,
//                               char ctx_final[])
// {
//     vector<paillier_ciphertext_t *> Ctxt_z(1);
//     int VecSize;
//     string CtxAE; //We need this here as well, as we need to check if the resulting ciphertext is from a legitimate typo or is randomly created.
//
// //    Ctxt_z = PaillerWrapperFunctions::Pail_Parse_Real_Pass_Ctx(ppk, RlPwd_ctx_pull,VecSize, CtxAE, 0); //Potential TODO: make sure the the previous parsing scheme woorking still here (basically we just trasnfer the string to the PAillier CTX space)
//
//     // size_t AECtxSize = 24;
//     // size_t AECtxSize = 24 + KEYSIZE_BYTES;
//     // size_t AECtxSize = 32 + KEYSIZE_BYTES;
//     size_t AECtxSize = 38;
//
//     size_t Ctxt_Vec_size = 1;
//     size_t Ctxt_Byte_size =  PAILLIER_BITS_TO_BYTES(ppk->bits)*2;
// //    char* ctx_final =(char*) malloc (2 * sizeof(size_t) + Ctxt_Byte_size);
//     memcpy(ctx_final, &Ctxt_Vec_size, sizeof(size_t));
//     memcpy(ctx_final + sizeof(size_t), &AECtxSize, sizeof(size_t));
//     memcpy(ctx_final + 2 * sizeof(size_t), &Ctxt_Byte_size, sizeof(size_t));
//     Ctxt_z = PaillerWrapperFunctions::Pail_Parse_Ctx_size(ppk, RlPwd_ctx_pull);
//
// //    auto& M = msg;
//     string CAPSLKonTypo = msg;
//
//     string b(AES::DEFAULT_KEYLENGTH, 0);
//     PRNG.GenerateBlock((CryptoPP::byte*) b.data(), b.size());
//     int StringPointerSize = sizeof(string);
//
//     int mallocSizeEncKey =  AECtxSize * sizeof(string);
//     // string* EncrypteKey = (string*) malloc(sizeof(char) * AECtxSize );
//     string* EncrypteKey = (string*) malloc( mallocSizeEncKey );
//
//     // auto* EncrypteKey = static_cast<string*>(malloc(AECtxSize));
//
//     // string* EncrypteKey = (string*) malloc( AECtxSize );
//
// //    CryptoSymWrapperFunctions::Wrapper_AuthEncrypt(b, payload, EncrypteKey); //
//     bool WrapAuthEncResult =false;
//     WrapAuthEncResult = CryptoSymWrapperFunctions::Wrapper_AuthEncrypt(b, payload, EncrypteKey[0]);
//
//     size_t sizeEncKey = sizeof(EncrypteKey[0]);
//     size_t sizeEncKey1 = EncrypteKey[0].size();
//
//     // assert( sizeof(EncrypteKey[0]) == sizeof(char) * AECtxSize);
//     // assert( sizeof(EncrypteKey[0]) == sizeof(string*) * AECtxSize);
//     // assert( sizeof(EncrypteKey[0]) == sizeof(string*) * AECtxSize);
//
//
//     memcpy(ctx_final + 3 * sizeof(size_t), &EncrypteKey[0], sizeof(char) * AECtxSize);
//     paillier_ciphertext_t* Ctxt_CPSLCK;
//     free(EncrypteKey);
//
//
//
//
//
// //    string* CtxtAEStr = (string*) malloc(sizeof(char) * 24);
// //    memcpy(&CtxtAEStr[0], ctx_final + 3 * sizeof(size_t), sizeof(char) * 24); //Correct
// //
// //
// //    assert(AECtxSize == sizeof (EncrypteKey));
// //    paillier_plaintext_t* m;
//     paillier_plaintext_t* m_k;
//     m_k = (paillier_plaintext_t*)malloc(sizeof(paillier_plaintext_t));
//
//
//     unsigned char a_M[AES::DEFAULT_KEYLENGTH];
//     for (int i = 0; i < AES::DEFAULT_KEYLENGTH; i++)
//     {
//         a_M[i] = b[i];
//     }
//     // paillier_plaintext_t* m_k = paillier_plaintext_from_bytes( a_M, AES::DEFAULT_KEYLENGTH );
//
//
//     mpz_t aux;
//     mpz_init(aux);
//     // auto* m = static_cast<paillier_plaintext_t*>(malloc(sizeof(paillier_plaintext_t)));
//     // mpz_init(m->m);
//
//     paillier_ciphertext_t* Ctxt_k;
//     //The ciphertext of the key for the authenticated encryption
//
// //    m_Typo = (paillier_plaintext_t*) malloc(sizeof(paillier_plaintext_t));
//     mpz_import(aux, AES::DEFAULT_KEYLENGTH, -1, 1, 0, 0, &a_M[0]); //In fact plays the role of ToInt to encode msg to an Integer.
//     mpz_init_set(m_k->m, aux);
//     Ctxt_k = paillier_enc(NULL, ppk, m_k, paillier_get_rand_devrandom);
//
//
//     // paillier_ciphertext_t* Ctxt_k = paillier_enc(nullptr, ppk, m_k, nullptr);
//
//
//     int CpasLockTransRslt = 0;
//     CpasLockTransRslt = CAPLOCKpredicate::convertOpposite(CAPSLKonTypo);
//     auto& M_CAPSLK = CAPSLKonTypo;
//     unsigned char a_z[M_CAPSLK.size()];
//     int M_CPSLK_len = M_CAPSLK.size();
//     for (int i = 0; i < M_CAPSLK.size(); i++)
//     {
//         a_z[i] = M_CAPSLK[i];
//     }
//
//     // paillier_plaintext_t* m;
//     // m = (paillier_plaintext_t*)malloc(sizeof(paillier_plaintext_t));
//
//     mpz_import(aux, M_CAPSLK.size(), -1, 1, 0, 0, &a_z[0]); //In fact plays the role of ToInt to encode msg to an Integer.
//     mpz_init_set(m_k->m, aux);
//     Ctxt_CPSLCK = paillier_enc(NULL, ppk, m_k, paillier_get_rand_devrandom);
//
//     // paillier_ciphertext_t* Ctxt_CPSLCK = paillier_enc(nullptr, ppk, m, paillier_get_rand_devurandom);
//     // paillier_plaintext_t* m_CPSLCK = paillier_plaintext_from_bytes( a_z, M_CPSLK_len );
//     // paillier_ciphertext_t* Ctxt_CPSLCK = paillier_enc(NULL, ppk, m_CPSLCK, paillier_get_rand_devrandom);
//
//
//     //    vector<char*> byteVCtx_Insrt(1);
//
//
//
// //    Aux_Ctx = (paillier_ciphertext_t *) malloc(PAILLIER_BITS_TO_BYTES(ppk->bits)*2);
// //    mpz_init_set_ui(Aux_Ctx->c, 1);
// //    Aux_Ctx1 = (paillier_ciphertext_t *) malloc(PAILLIER_BITS_TO_BYTES(ppk->bits)*2);
// //    Aux_Ctx1 =paillier_create_enc_zero();
// //    mpz_init_set_ui(Aux_Ctx1->c, 1);
// //    Aux_Ctx2 = (paillier_ciphertext_t *) malloc(PAILLIER_BITS_TO_BYTES(ppk->bits)*2);
// //    mpz_init_set_ui(Aux_Ctx2->c, 1);
//     paillier_ciphertext_t* Aux_Ctx;
//     Aux_Ctx = PaillerWrapperFunctions::Pail_Subtct(ppk, Ctxt_z[0], Ctxt_CPSLCK);
//
//     //    R = (paillier_plaintext_t*) malloc(sizeof(paillier_plaintext_t));
//     paillier_plaintext_t* R;
//     R = PaillerWrapperFunctions::Rand_Plain_Pail(ppk); //TODO: <Ppotential task> I need to describe a function to generate random number in plaintext.
//     paillier_ciphertext_t* Aux_Ctx1;
//     Aux_Ctx1 = PaillerWrapperFunctions::Pail_Mult_PtxCtx(ppk, Aux_Ctx, R);
// //    mpz_powm(Aux_Ctx1->c, Aux_Ctx->c, R->m, ppk->n_squared);
//     paillier_ciphertext_t* Aux_Ctx2;
//     Aux_Ctx2 = PaillerWrapperFunctions::Pail_Add(ppk, Ctxt_k, Aux_Ctx1);
//
//     char* byteCtxt1;
//     byteCtxt1 = (char*)paillier_ciphertext_to_bytes(PAILLIER_BITS_TO_BYTES(ppk->bits)*2, Aux_Ctx2);
//     // byteCtxt1 = paillier_ciphertext_to_bytes(PAILLIER_BITS_TO_BYTES(ppk->bits) * 2, Aux_Ctx2);
//
//     memcpy(ctx_final + 3 * sizeof(size_t) + AECtxSize, byteCtxt1, PAILLIER_BITS_TO_BYTES(ppk->bits)*2);
//
//
//     paillier_freeciphertext(Aux_Ctx);
//     paillier_freeciphertext(Aux_Ctx1);
//     paillier_freeciphertext(Aux_Ctx2);
//     paillier_freeciphertext(Ctxt_CPSLCK);
//     paillier_freeciphertext(Ctxt_k);
//     paillier_freeciphertext(Ctxt_z[0]);
//     // paillier_freeplaintext(m);
//     // paillier_freeplaintext(m_k);
//     mpz_clear(m_k->m);
//     // free(m_k);
//     // paillier_freeplaintext(m_CPSLCK);
//     paillier_freeplaintext(R);
//     // mpz_clear(R->m);
// //    paillier_freeplaintext(m_Typo);
//     free(byteCtxt1);
//     mpz_clear(aux);
//
// //    mpz_clear(aux_Typo);
//
//     return "EncrypteKey[0]";
//     // return "1";
// //    byteVCtx_Insrt[0] = mpz_get_str(NULL, 10, Aux_Ctx2->c);
//
// //    output_ce_ctx = output_ce_ctx + byteVCtx_Insrt[0] + "%VVV";
// }

string CAPLOCKpredicate::CondEnc(paillier_pubkey_t *ppk,
                              char RlPwd_ctx_pull[],
                              string& msg,
                              string& payload,
                              char ctx_final[])
{
    vector<paillier_ciphertext_t *> Ctxt_z(1);
    int VecSize;
    string CtxAE; //We need this here as well, as we need to check if the resulting ciphertext is from a legitimate typo or is randomly created.

//    Ctxt_z = PaillerWrapperFunctions::Pail_Parse_Real_Pass_Ctx(ppk, RlPwd_ctx_pull,VecSize, CtxAE, 0); //Potential TODO: make sure the the previous parsing scheme woorking still here (basically we just trasnfer the string to the PAillier CTX space)

    // size_t AECtxSize = 24;
    // size_t AECtxSize = 24 + KEYSIZE_BYTES;
    // size_t AECtxSize = 32 + KEYSIZE_BYTES;
    // size_t AECtxSize = 38;
    size_t AECtxSize = 2 * KEYSIZE_BYTES + payload.size();

    size_t Ctxt_Vec_size = 1;
    size_t Ctxt_Byte_size =  PAILLIER_BITS_TO_BYTES(ppk->bits)*2;
//    char* ctx_final =(char*) malloc (2 * sizeof(size_t) + Ctxt_Byte_size);
    memcpy(ctx_final, &Ctxt_Vec_size, sizeof(size_t));
    memcpy(ctx_final + sizeof(size_t), &AECtxSize, sizeof(size_t));
    memcpy(ctx_final + 2 * sizeof(size_t), &Ctxt_Byte_size, sizeof(size_t));
    Ctxt_z = PaillerWrapperFunctions::Pail_Parse_Ctx_size(ppk, RlPwd_ctx_pull);

    string CAPSLKonTypo = msg;

    string b(AES::DEFAULT_KEYLENGTH, 0);
    PRNG.GenerateBlock((CryptoPP::byte*) b.data(), b.size());
    std::string* EncrypteKey = new std::string[1];


//    CryptoSymWrapperFunctions::Wrapper_AuthEncrypt(b, payload, EncrypteKey); //
    bool WrapAuthEncResult =false;
// cout << "Hassan1\n";
    WrapAuthEncResult = CryptoSymWrapperFunctions::Wrapper_AuthEncrypt(b, payload, EncrypteKey[0]);

    // size_t sizeEncKey = sizeof(EncrypteKey[0]);
    size_t sizeEncKey = EncrypteKey[0].size();
    assert(sizeEncKey == AECtxSize);


    // assert( sizeof(EncrypteKey[0]) == sizeof(char) * AECtxSize);
    // assert( sizeof(EncrypteKey[0]) == sizeof(string*) * AECtxSize);
    // assert( sizeof(EncrypteKey[0]) == sizeof(string*) * AECtxSize);


    memcpy(ctx_final + 3 * sizeof(size_t), EncrypteKey[0].c_str(), sizeof(char) * sizeEncKey);
    paillier_ciphertext_t* Ctxt_CPSLCK;
    // free(EncrypteKey);
    delete[] EncrypteKey;




//    string* CtxtAEStr = (string*) malloc(sizeof(char) * 24);
//    memcpy(&CtxtAEStr[0], ctx_final + 3 * sizeof(size_t), sizeof(char) * 24); //Correct
//
//
//    assert(AECtxSize == sizeof (EncrypteKey));
//    paillier_plaintext_t* m;
    paillier_plaintext_t* m_k;
    m_k = (paillier_plaintext_t*)malloc(sizeof(paillier_plaintext_t));


    unsigned char a_M[AES::DEFAULT_KEYLENGTH];
    for (int i = 0; i < AES::DEFAULT_KEYLENGTH; i++)
    {
        a_M[i] = b[i];
    }
    // paillier_plaintext_t* m_k = paillier_plaintext_from_bytes( a_M, AES::DEFAULT_KEYLENGTH );


    mpz_t aux;
    mpz_init(aux);
    // auto* m = static_cast<paillier_plaintext_t*>(malloc(sizeof(paillier_plaintext_t)));
    // mpz_init(m->m);

    paillier_ciphertext_t* Ctxt_k;
    //The ciphertext of the key for the authenticated encryption

//    m_Typo = (paillier_plaintext_t*) malloc(sizeof(paillier_plaintext_t));
    mpz_import(aux, AES::DEFAULT_KEYLENGTH, -1, 1, 0, 0, &a_M[0]); //In fact plays the role of ToInt to encode msg to an Integer.
    mpz_init_set(m_k->m, aux);
    Ctxt_k = paillier_enc(NULL, ppk, m_k, paillier_get_rand_devrandom);


    // paillier_ciphertext_t* Ctxt_k = paillier_enc(nullptr, ppk, m_k, nullptr);


    int CpasLockTransRslt = 0;
    CpasLockTransRslt = CAPLOCKpredicate::convertOpposite(CAPSLKonTypo);
    auto& M_CAPSLK = CAPSLKonTypo;
    unsigned char a_z[M_CAPSLK.size()];
    int M_CPSLK_len = M_CAPSLK.size();
    for (int i = 0; i < M_CAPSLK.size(); i++)
    {
        a_z[i] = M_CAPSLK[i];
    }

    // paillier_plaintext_t* m;
    // m = (paillier_plaintext_t*)malloc(sizeof(paillier_plaintext_t));

    mpz_import(aux, M_CAPSLK.size(), -1, 1, 0, 0, &a_z[0]); //In fact plays the role of ToInt to encode msg to an Integer.
    mpz_init_set(m_k->m, aux);
    Ctxt_CPSLCK = paillier_enc(NULL, ppk, m_k, paillier_get_rand_devrandom);

    // paillier_ciphertext_t* Ctxt_CPSLCK = paillier_enc(nullptr, ppk, m, paillier_get_rand_devurandom);
    // paillier_plaintext_t* m_CPSLCK = paillier_plaintext_from_bytes( a_z, M_CPSLK_len );
    // paillier_ciphertext_t* Ctxt_CPSLCK = paillier_enc(NULL, ppk, m_CPSLCK, paillier_get_rand_devrandom);


    //    vector<char*> byteVCtx_Insrt(1);



//    Aux_Ctx = (paillier_ciphertext_t *) malloc(PAILLIER_BITS_TO_BYTES(ppk->bits)*2);
//    mpz_init_set_ui(Aux_Ctx->c, 1);
//    Aux_Ctx1 = (paillier_ciphertext_t *) malloc(PAILLIER_BITS_TO_BYTES(ppk->bits)*2);
//    Aux_Ctx1 =paillier_create_enc_zero();
//    mpz_init_set_ui(Aux_Ctx1->c, 1);
//    Aux_Ctx2 = (paillier_ciphertext_t *) malloc(PAILLIER_BITS_TO_BYTES(ppk->bits)*2);
//    mpz_init_set_ui(Aux_Ctx2->c, 1);
    paillier_ciphertext_t* Aux_Ctx;
    Aux_Ctx = PaillerWrapperFunctions::Pail_Subtct(ppk, Ctxt_z[0], Ctxt_CPSLCK);

    //    R = (paillier_plaintext_t*) malloc(sizeof(paillier_plaintext_t));
    paillier_plaintext_t* R;
    R = PaillerWrapperFunctions::Rand_Plain_Pail(ppk); //TODO: <Ppotential task> I need to describe a function to generate random number in plaintext.
    paillier_ciphertext_t* Aux_Ctx1;
    Aux_Ctx1 = PaillerWrapperFunctions::Pail_Mult_PtxCtx(ppk, Aux_Ctx, R);
//    mpz_powm(Aux_Ctx1->c, Aux_Ctx->c, R->m, ppk->n_squared);
    paillier_ciphertext_t* Aux_Ctx2;
    Aux_Ctx2 = PaillerWrapperFunctions::Pail_Add(ppk, Ctxt_k, Aux_Ctx1);

    char* byteCtxt1;
    byteCtxt1 = (char*)paillier_ciphertext_to_bytes(PAILLIER_BITS_TO_BYTES(ppk->bits)*2, Aux_Ctx2);
    // byteCtxt1 = paillier_ciphertext_to_bytes(PAILLIER_BITS_TO_BYTES(ppk->bits) * 2, Aux_Ctx2);

    memcpy(ctx_final + 3 * sizeof(size_t) + AECtxSize, byteCtxt1, PAILLIER_BITS_TO_BYTES(ppk->bits)*2);


    paillier_freeciphertext(Aux_Ctx);
    paillier_freeciphertext(Aux_Ctx1);
    paillier_freeciphertext(Aux_Ctx2);
    paillier_freeciphertext(Ctxt_CPSLCK);
    paillier_freeciphertext(Ctxt_k);
    paillier_freeciphertext(Ctxt_z[0]);
    // paillier_freeplaintext(m);
    // paillier_freeplaintext(m_k);
    mpz_clear(m_k->m);
    // free(m_k);
    // paillier_freeplaintext(m_CPSLCK);
    paillier_freeplaintext(R);
    // mpz_clear(R->m);
//    paillier_freeplaintext(m_Typo);
    free(byteCtxt1);
    mpz_clear(aux);

//    mpz_clear(aux_Typo);

    return "1";
    // return "1";
//    byteVCtx_Insrt[0] = mpz_get_str(NULL, 10, Aux_Ctx2->c);

//    output_ce_ctx = output_ce_ctx + byteVCtx_Insrt[0] + "%VVV";
}
 int CAPLOCKpredicate::CondDec( paillier_pubkey_t* ppk,
                         char typo_ctx[],
                         paillier_prvkey_t* psk,
                         string &recovered)
{
    int ret = -1;
    vector<paillier_ciphertext_t*> V_ctx_typo(1);
//    int VecSize=0;
    void* ByteDec;
    string CtxAE; //Extracting the AE part.

//    string CtxAE; //This part may not be applicable here.
//    V_ctx_typo = PaillerWrapperFunctions::Pail_Parse_Ctx_size(ppk, typo_ctx);//The old version withou the AE, So need to use the modified version.
    int pars_rslt =0;
    pars_rslt = CAPLOCKpredicate::Pail_Parse_Ctx_size_AECtx_CPSALOcK(ppk, typo_ctx, CtxAE, V_ctx_typo);

     paillier_plaintext_t* dec;
    dec = paillier_dec(nullptr, ppk, psk, V_ctx_typo[0]);
//    ByteDec = paillier_plaintext_to_bytes_NegOrd(ShareSize, dec);TODO: previously we have this part. we may need to double dchek it:  main difference: using ShareSize instead of _len
    ByteDec = paillier_plaintext_to_bytes_NegOrd(AES::DEFAULT_KEYLENGTH, dec);

    vector<CryptoPP::byte> ab(AES::DEFAULT_KEYLENGTH);
    memcpy(&ab[0],ByteDec, AES::DEFAULT_KEYLENGTH);
//    ab = PaillerWrapperFunctions::mpz_to_vector(dec->m, _len); //
    std::string s(ab.begin(), ab.end());
    paillier_freeplaintext(dec);
    free(ByteDec);

     string plaintext_rcv;
     bool AEReslt;
     AEReslt = CryptoSymWrapperFunctions::Wrapper_AuthDecrypt(s, CtxAE, plaintext_rcv);
     if (AEReslt == true)
     {
         recovered = plaintext_rcv;
         ret = 1;
     }
     paillier_freeciphertext(V_ctx_typo[0]);
    return ret;
}

int CAPLOCKpredicate::RegDec(paillier_pubkey_t* ppk,
                        char typo_ctx[],
                         paillier_prvkey_t* psk,
                         string &recovered,
                         size_t _len)
{
    int ret = 0;
    int PailCtxtSize =  PAILLIER_BITS_TO_BYTES(ppk->bits)*2;
    void* c = malloc(PailCtxtSize);
    auto byteCtxt = static_cast<paillier_ciphertext_t*>(malloc(PailCtxtSize));
    size_t a;
    size_t b;
    memcpy(&a, typo_ctx, sizeof(size_t));
    memcpy(&b, typo_ctx + sizeof(size_t), sizeof(size_t));
    memcpy(c, typo_ctx + 2 * sizeof(size_t), PailCtxtSize);

    byteCtxt = paillier_ciphertext_from_bytes(c, PailCtxtSize);
    paillier_plaintext_t* dec;
    dec = paillier_dec(nullptr, ppk, psk, byteCtxt);
    // string ByteDec = paillier_plaintext_to_str(dec);
    recovered = paillier_plaintext_to_str_NegOrd(dec);

    // void* dec_Byte  = paillier_plaintext_to_bytes_NegOrd(static_cast<int>(_len),  dec);
    // char dec_CharVect  [_len];
    // memcpy(dec_CharVect, dec_Byte, _len);
    // recovered = dec_CharVect;
    ret =1;
    free(c);
    // free(dec_Byte);
    paillier_freeciphertext(byteCtxt);
    paillier_freeplaintext(dec);
    // paillier_plaintext_to_bytes_NegOrd
    return ret;
}

 int CAPLOCKpredicate::convertOpposite(string& str)
{
    int ln = str.length();

    // Conversion according to ASCII values
    for (int i = 0; i < ln; i++) {
        if (str[i] >= 'a' && str[i] <= 'z')
            // Convert lowercase to uppercase
            str[i] = str[i] - 32;
        else if (str[i] >= 'A' && str[i] <= 'Z')
            // Convert uppercase to lowercase
            str[i] = str[i] + 32;
    }
    return 1;
}


int CAPLOCKpredicate::Pail_Parse_Ctx_size_AECtx_CPSALOcK(const paillier_pubkey_t* ppk,
                                                         const char* ctx, string& CtxtAEStr,
                                                         vector<paillier_ciphertext_t*> &Vect_Ctx)
{
    int ret = 0;
    size_t size;
    memcpy(&size, ctx , sizeof(size_t));
    size_t AE_Ctx_size;
    memcpy(&AE_Ctx_size, ctx  + sizeof(size_t), sizeof(size_t));
    size_t Ctxt_Elemnt_Size;
    memcpy(&Ctxt_Elemnt_Size, ctx + 2 * sizeof(size_t), sizeof(size_t));


    // string* CtxtAEStrPre = (string*)malloc(AE_Ctx_size * sizeof(char));
    std::string* CtxtAEStrPre = new std::string[1];
    CtxtAEStrPre[0].resize(AE_Ctx_size);
    // auto* CtxtAEStrPre = malloc(AE_Ctx_size * sizeof(char));
    memcpy(&CtxtAEStrPre[0][0], ctx + 3 * sizeof(size_t), AE_Ctx_size * sizeof(char)); //Correct
    //    CtxtAEStr = CtxtAEStrPre[0];
    CryptoPP::StringSink ss(CtxtAEStr);
    cout << "\n";
    ss.Put((const CryptoPP::byte*)CtxtAEStrPre[0].data(),  CtxtAEStrPre[0].size(), false);

    delete[] CtxtAEStrPre;

    char* byteCtxt1 =(char*)malloc(PAILLIER_BITS_TO_BYTES(ppk->bits) * 2);

    for(int i = 0; i< size; i++ )
    {
        memcpy(byteCtxt1,  ctx + 3 * sizeof(size_t) + AE_Ctx_size + i * Ctxt_Elemnt_Size, Ctxt_Elemnt_Size);
        Vect_Ctx[i] = paillier_ciphertext_from_bytes((void*)byteCtxt1, PAILLIER_BITS_TO_BYTES(ppk->bits)*2);
    }

    free(byteCtxt1);
    ret = 1;
    return ret;
}