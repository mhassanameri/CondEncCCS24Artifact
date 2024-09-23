//
// Created by mameriek on 9/6/21.
//

#include "ConditionalEncryptionEditDistOne.h"



//PaillerWrapperFunctions, CryptoSymWrapperFunctions

//The follwoing may be considered
//typtop::WaitlistEntry wlent;
//wlent.ParseFromString(typo);
//string orig_typo = wlent.pw();

/*
     * API is similar to Enc, but the output ciphertext is pointer to byte array of unsigned char*
     * */
 int EditDistOne::Enc(paillier_pubkey_t* ppk, string &msg, char ctx_final[])
{
    string unpad_msg =  CryptoSymWrapperFunctions::Wrapper_unpad(msg);
    size_t unpad_msg_size =  unpad_msg.size();
    auto& str_msg = msg;
    auto& str_msg_ubpad = unpad_msg;
    std::string s(std::begin(str_msg_ubpad), std::end(str_msg_ubpad));
    std::string s_pad(std::begin(str_msg), std::end(str_msg));
    paillier_ciphertext_t* Ctxt_z;
    size_t Ctxt_Vec_size = msg.size() + 1;
    size_t msg_size = s_pad.size();
    size_t Ctxt_Byte_size =  PAILLIER_BITS_TO_BYTES(ppk->bits)*2;
//    char* ctx_final =(char*) malloc ((Ctxt_Vec_size + 1 ) * sizeof(size_t) + Ctxt_Vec_size  *  Ctxt_Byte_size);

    memcpy(ctx_final, &Ctxt_Vec_size, sizeof(size_t));
    memcpy(ctx_final + sizeof(size_t), &Ctxt_Byte_size, sizeof(size_t));
//    for(int k = 0; k < Ctxt_Vec_size; k++)
//    {
//        memcpy(ctx_final + (k+1) * sizeof(size_t), &Ctxt_Byte_size, sizeof(size_t));
//    }

//    vector<char*> byteVCtx(Ctxt_Vec_size);
    vector<paillier_ciphertext_t*> VCtxt_z(unpad_msg_size);

    unsigned char a_z[msg.size()];
    for (int i = 0; i < msg.size(); i++)
    {
        a_z[i] = str_msg[i];
    }
    mpz_t aux;
    mpz_init(aux);
    paillier_plaintext_t* m;
    m = (paillier_plaintext_t*) malloc(sizeof(paillier_plaintext_t));
    mpz_import(aux, msg_size, -1, 1, 0, 0, &a_z[0]);
    mpz_init_set(m->m, aux);
    Ctxt_z = paillier_enc(NULL, ppk, m, paillier_get_rand_devrandom);

    char* byteCtxt1 = (char*)paillier_ciphertext_to_bytes(Ctxt_Byte_size, Ctxt_z);

//    memcpy(ctx_final  + (Ctxt_Vec_size + 1) * sizeof(size_t), byteCtxt1,  Ctxt_Byte_size);
    memcpy(ctx_final  + 2 * sizeof(size_t), byteCtxt1,  Ctxt_Byte_size);

    paillier_ciphertext_t * CtxtGarbage;
    CtxtGarbage = (paillier_ciphertext_t *) malloc(sizeof(paillier_ciphertext_t));
    paillier_plaintext_t *R;
//    R = (paillier_plaintext_t*) malloc(sizeof(paillier_plaintext_t));
    char* byteCtxt;
    for (int i = 0; i < msg_size; i++)// msg_size = s.size()
    {
        if (i < unpad_msg_size)
        {
            string sub_i = str_msg_ubpad.substr (0,i) +  str_msg_ubpad.substr (i+1,unpad_msg_size);
            string sub_i_padd = CryptoSymWrapperFunctions::Wrapper_pad(sub_i, msg_size);
            unsigned char a[sub_i_padd.size() ];
            for (int j = 0; j <sub_i_padd.size(); ++j)
            {
                a[j] =  sub_i_padd[j];
            }
//            paillier_plaintext_t* m;
//            mpz_t aux;
//            mpz_init(aux);
//            m = (paillier_plaintext_t*) malloc(sizeof(paillier_plaintext_t));
            mpz_import(aux, sub_i_padd.size(), -1, 1, 0, 0, &a[0]);
            mpz_init_set(m->m, aux);
            VCtxt_z[i] = paillier_enc(NULL, ppk, m, paillier_get_rand_devrandom);
            byteCtxt = (char*)paillier_ciphertext_to_bytes(Ctxt_Byte_size, VCtxt_z[i]);
            memcpy(ctx_final  + 2 * sizeof(size_t) + (i+1) * Ctxt_Byte_size, byteCtxt,  Ctxt_Byte_size);
            free(byteCtxt);
//            mpz_clear(m->m);
//            free(m);
        }
        else
        {
            mpz_init_set_ui(CtxtGarbage->c, 1);
            R = PaillerWrapperFunctions::Rand_Plain_Pail(ppk); //I need to describe a function to generate random number in plaintext.
            mpz_powm(CtxtGarbage->c, VCtxt_z[0]->c, R->m, ppk->n_squared);
            byteCtxt = (char*)paillier_ciphertext_to_bytes(Ctxt_Byte_size, CtxtGarbage);
            memcpy(ctx_final  + 2 * sizeof(size_t) + (i+1) * Ctxt_Byte_size, byteCtxt,  Ctxt_Byte_size);
            free(byteCtxt);
            paillier_freeplaintext(R);
        }

//        byteVCtx[i] = mpz_get_str(NULL, 10, VCtxt_z[i]->c);
    }



    for(int i =0; i <unpad_msg_size ; i++)
        {
            paillier_freeciphertext(VCtxt_z[i]);
        }

    paillier_freeplaintext(m);
//    paillier_freeplaintext(R);
    paillier_freeciphertext(CtxtGarbage);
    paillier_freeciphertext(Ctxt_z);
    free(byteCtxt1);
//    free(byteCtxt);
    mpz_clear(aux);
    return 1;
}




/*
 * High level Description of this algorithm funtionality:
 *
   * What we are given:  The encryption of c_0 = Enc(ToInt(m)) ->  parse it to the vector of (c_0, c_1, ...,c_n),
     * s.t. c_i = Enc_pk(ToInt(m_{-i});
     * 1. For insertion: Given the typo m', Compute c'_i = Enc_{pk} (m'_{-i});
     *      1.a. commpute for all i, compute c_i^{ins} = Enc( (ToInt(m) -  ToInt(m'_{-i}) * R_i + K), in which K is the
     *      Key for checking the authentication encryption which is chosen uniformlt at random.
     * 2. For the deletion, for all i, compute c_i ^{del} = Enc((ToInt(m_{-i}) - ToInt(m'))* R  + K), K is the same as
     * previous step.
     * 3. Encrypt the typo m using Authentication Encryption AE using Key K: C'_0 =  AE.Enc_K (m');
     * 4. C_condiEnc = (c'_0, c_i^{ins}, ..., c_{i}^{del}
     *
     * For the decryption step:
     * 1. We parse C_condiEnc and look for
     *          c'_i \in {{Parse (C_condiEnc)} - c'_0 } s.t., (1, m') = AEDec(Dec_{sk}(c'_i),c'_0)
     *      1.a. if exists such c'_i, output m'.
 *
 * */



string EditDistOne::CondEnc(paillier_pubkey_t* ppk,
                          char RlPwd_ctx_pull[],
                          string& typo,
                          string& payload,
                          size_t len,
                          char ctx_final[])
{
    vector<paillier_ciphertext_t *> Ctxt_z(len + 1);//The len should be the actual length of padded typo.
//    vector<paillier_ciphertext_t *> Ctxt_CondEnc(2 * len);
    int VecSize;
    string CtxAE;

    string typo_unpad = CryptoSymWrapperFunctions::Wrapper_unpad(typo); //This part will extract the unpadded version of the typo for encryption.
    size_t typo_unpad_size =  typo_unpad.size(); //We need to track the size of the unpadded typo.
    size_t AECtxSize = 2 * KEYSIZE_BYTES + payload.size();
    // size_t AECtxSize = 24; // for 128  bit, the output is 192 bit as the size of the EncryptedKey.
    size_t Ctxt_Vec_size =  typo.size() + len + 1;//TODO: We can also set this value to 2* len + 1  //one C_0 ctx and 2 * _len Insertion ctxs and Delection ctxs: This variable says the number of paillier ctxts.
    size_t Ctxt_Byte_size =  PAILLIER_BITS_TO_BYTES(ppk->bits)*2;
//    char* ctx_final =(char*) malloc (  ((( 3 * sizeof(size_t) )+ AECtxSize * sizeof (char)) + (Ctxt_Vec_size *  Ctxt_Byte_size)));
    memcpy(ctx_final, &Ctxt_Vec_size, sizeof(size_t));
    memcpy(ctx_final + sizeof(size_t), &AECtxSize, sizeof(size_t));
    memcpy(ctx_final + 2 * sizeof(size_t), &Ctxt_Byte_size, sizeof(size_t));


    /*
     * We parse the conventional ctxt to extract the the ctxt we need for handling the deletion/insertion cases
     * */

    Ctxt_z = PaillerWrapperFunctions::Pail_Parse_Ctx_size(ppk, RlPwd_ctx_pull);


    string b(AES::DEFAULT_KEYLENGTH, 0);
    PRNG.GenerateBlock((CryptoPP::byte *) b.data(), b.size());
//    string message= CryptoSymWrapperFunctions::Wrapper_pad(typo, len);//TODO: check if we need to use the original typo or its padded version.
    // ==> It seems that this should be replaced with payload. Previously:  Wrapper_pad(typo, len)
//    string message_OrigTypo = typo; // "ghello_pass";//orig_typo

    // string* EncrypteKey = (string*) malloc(AECtxSize);
    std::string* EncrypteKey = new std::string[1];
     bool WrapAuthEncResult =false;
    WrapAuthEncResult= CryptoSymWrapperFunctions::Wrapper_AuthEncrypt(b, payload, EncrypteKey[0]); //perviously message or message_OrigTypo TODO: needs to be checked wihch one is the correct one


    memcpy(ctx_final + 3 * sizeof(size_t), EncrypteKey[0].c_str(), sizeof(char) * AECtxSize);
//    memcpy(ctx_final + 3 * sizeof(size_t), AECtxtKeyChar, AECtxSize);

     delete[] EncrypteKey;
    // free(EncrypteKey);

//    string* CtxtAEStr = (string*) malloc(sizeof(char) * 24);
//    memcpy(&CtxtAEStr[0], ctx_final + 3 * sizeof(size_t), sizeof(char) * 24); //Correct
//
//
//    assert(AECtxSize == sizeof (EncrypteKey));

/*For debugging*/
//    string CtxAETest;
//    string* CtxAE_Char = (string*)malloc(24);
//    free(CtxAE_Char);
//    memcpy(CtxAE_Char, ctx_final + 3 * sizeof(size_t), 24);
//    CtxAETest = CtxAE_Char[0];
//    assert(CtxAETest == EncrypteKey);

//    output_ce_ctx = EncodedCtxt + "%VVV";
    paillier_plaintext_t* m = (paillier_plaintext_t*) malloc (sizeof(paillier_plaintext_t));
//    void* a = (char*) malloc(AES::DEFAULT_KEYLENGTH);
//    memcpy(a, &b[0], AES::DEFAULT_KEYLENGTH * sizeof(char));
//    m = paillier_plaintext_from_bytes (a,AES::DEFAULT_KEYLENGTH * sizeof(char));
    unsigned char a_z[AES::DEFAULT_KEYLENGTH];
////    char* a_z_char =  (char*) malloc(AES::DEFAULT_KEYLENGTH);
    for (int i = 0; i < AES::DEFAULT_KEYLENGTH; i++)
    {
        a_z[i] = b[i];
    }
//    size_t key_size = AES::DEFAULT_KEYLENGTH;
//    memcpy(a_z_char, &b, key_size);
//    free(a_z_char);
    mpz_t aux;
    mpz_init(aux);

    paillier_ciphertext_t* Ctxt_k; //The ctxt of AE key under the Paillier publick key.
//    m = (paillier_plaintext_t*) malloc(sizeof(paillier_plaintext_t));
    mpz_import(aux, AES::DEFAULT_KEYLENGTH, -1, 1, 0, 0, &a_z[0]);
//    mpz_import(aux, AES::DEFAULT_KEYLENGTH, -1, 1, 0, 0, &a_z[0]);
    mpz_init_set(m->m, aux);
//    vector<byte> ab;
//    ab = PaillerWrapperFunctions::mpz_to_vector(m->m, AES::DEFAULT_KEYLENGTH);
//    ab.resize(AES::DEFAULT_KEYLENGTH);
//    std::string s(ab.begin(), ab.end());
//    assert(s ==  b);
    Ctxt_k = paillier_enc(NULL, ppk, m, paillier_get_rand_devrandom);


//    free(a);

    /*
     * Computing the the ctxt related to the Insertion
     * */

    auto& str_typo =  typo_unpad;   //message_OrigTypo;//TODO: Check to make sure if we need to use orig_typo [or pad (orig_typo)] instead of message.
    size_t size_typo_unpad = str_typo.size();
    vector<paillier_ciphertext_t*> VCtxt_typo(size_typo_unpad);

    for (int i = 0; i < size_typo_unpad; i++) //here the size_,esage is the size of the typo without padding
    {
        string sub_i = str_typo.substr (0,i) +  str_typo.substr (i+1,size_typo_unpad);
        string sub_i_padd = CryptoSymWrapperFunctions::Wrapper_pad(sub_i, len);
        unsigned char a[len];
        for (int j = 0; j <len  ; ++j)
        {
            a[j] =  sub_i_padd[j];
        }
//        paillier_plaintext_t* m;
//        m = (paillier_plaintext_t*) malloc(sizeof(paillier_plaintext_t));
        mpz_import(aux, len, -1, 1, 0, 0, &a[0]);
        mpz_init_set(m->m, aux);
        VCtxt_typo[i] = paillier_enc(NULL, ppk, m,
                                     paillier_get_rand_devrandom); //computing Enc(ToInt(m'_{-i}))

    }


    paillier_ciphertext_t* Aux_Ctx;
    paillier_ciphertext_t* Aux_Ctx1;
    paillier_ciphertext_t* Aux_Ctx2;

    /*
     * Computing the ctxt related to the deletion deletion.
     * */

//    vector<char*> byteVCtx_Del(Ctxt_z.size()-1);
    auto& str_typo_padded =  typo;
    unsigned char typo_ByteVector[len];
    for (int i = 0; i < len; i++)
    {
        typo_ByteVector[i] = str_typo_padded[i];
    }
    mpz_t aux_Del;
    mpz_init(aux_Del);
    paillier_plaintext_t* m_typo;
    paillier_ciphertext_t* Ctxt_typo; //The ctxt of padded whole padded ToinT(pad(typo)) using the Paillier pk.
    m_typo = (paillier_plaintext_t*) malloc(sizeof(paillier_plaintext_t));

    mpz_import(aux_Del, len, -1, 1, 0, 0, &typo_ByteVector[0]);
    mpz_init_set(m_typo->m, aux_Del);
    Ctxt_typo = paillier_enc(NULL, ppk, m_typo, paillier_get_rand_devrandom);
/*
 * Here the size of vector of the otiginal mesasge, So here, in the case also the typo is equal to the original message also will be captured.
 * */
//    char* TESTCharCTx = (char*) malloc (  Ctxt_Byte_size);
//    memcpy(TESTCharCTx, Ctxt_k,  Ctxt_Byte_size);
//free(TESTCharCTx);
//    Aux_Ctx = (paillier_ciphertext_t *) malloc(Ctxt_Byte_size);
//    Aux_Ctx1 = (paillier_ciphertext_t *) malloc(Ctxt_Byte_size);
//    Aux_Ctx2 = (paillier_ciphertext_t *) malloc(Ctxt_Byte_size);
    paillier_plaintext_t *R;
//    R = (paillier_plaintext_t*) malloc(sizeof(paillier_plaintext_t));
//    char* byteCtxt1 = (char*)malloc(PAILLIER_BITS_TO_BYTES(ppk->bits)*2);
//    char* byteCtxt = (char*)malloc(PAILLIER_BITS_TO_BYTES(ppk->bits)*2);
    char* byteCtxt1;
    char* byteCtxt;

    for (int j = 0; j <Ctxt_z.size(); j++) {
//        mpz_init_set_ui(Aux_Ctx->c, 1);
//        mpz_init_set_ui(Aux_Ctx1->c, 1);
//        mpz_init_set_ui(Aux_Ctx2->c, 1);
        Aux_Ctx = PaillerWrapperFunctions::Pail_Subtct(ppk, Ctxt_z[j], Ctxt_typo);
        R = PaillerWrapperFunctions::Rand_Plain_Pail(ppk); //I need to describe a function to generate random number in plaintext.
//        mpz_powm(Aux_Ctx1->c, Aux_Ctx->c, R->m, ppk->n_squared);
        Aux_Ctx1 = PaillerWrapperFunctions::Pail_Mult_PtxCtx(ppk,Aux_Ctx, R);
        Aux_Ctx2 = PaillerWrapperFunctions::Pail_Add(ppk, Ctxt_k, Aux_Ctx1);
        byteCtxt1 = (char*)paillier_ciphertext_to_bytes(Ctxt_Byte_size, Aux_Ctx2);
        memcpy(ctx_final + 3 * sizeof(size_t) + AECtxSize + j * Ctxt_Byte_size, byteCtxt1,  Ctxt_Byte_size);
        free(byteCtxt1);
        paillier_freeplaintext(R);
        paillier_freeciphertext(Aux_Ctx);
        paillier_freeciphertext(Aux_Ctx1);
        paillier_freeciphertext(Aux_Ctx2);
//        memcpy(ctx_final +(((3 * sizeof(size_t)) + AECtxSize) + (j * Ctxt_Byte_size)), Ctxt_k,  Ctxt_Byte_size);
    }





//    output_ce_ctx = EncodedCtxt + "%VVV"; // Adding the symmetric encryotion of the secret as the first element of the ctxt



//for (int i=0; i< Ctxt_z.size() - 1; ++i)
//    {
//        output_ce_ctx = output_ce_ctx + byteVCtx_Del[i];
//        output_ce_ctx = output_ce_ctx + "%VVV";
//    }


//    vector<char*> byteVCtx_Insrt(size_msg);

    paillier_ciphertext_t* CtxtGarbage;
//    CtxtGarbage = (paillier_ciphertext_t *) malloc(Ctxt_Byte_size);
    for (int j = 0; j <len ; j++) {

        if (j < size_typo_unpad )
        {
//            mpz_init_set_ui(Aux_Ctx->c, 1);
//            mpz_init_set_ui(Aux_Ctx1->c, 1);
//            mpz_init_set_ui(Aux_Ctx2->c, 1);
            Aux_Ctx = PaillerWrapperFunctions::Pail_Subtct(ppk, Ctxt_z[0], VCtxt_typo[j]);
            R = PaillerWrapperFunctions::Rand_Plain_Pail(ppk);
            Aux_Ctx1 = PaillerWrapperFunctions::Pail_Mult_PtxCtx(ppk,Aux_Ctx, R );
//            mpz_powm(Aux_Ctx1->c, Aux_Ctx->c, R->m, ppk->n_squared);
            Aux_Ctx2 = PaillerWrapperFunctions::Pail_Add(ppk, Ctxt_k, Aux_Ctx1);
            byteCtxt1 = (char*)paillier_ciphertext_to_bytes(Ctxt_Byte_size, Aux_Ctx2);
            memcpy(ctx_final +  (((3 * sizeof(size_t)) + AECtxSize) + (( Ctxt_z.size() + j ) * Ctxt_Byte_size)), byteCtxt1,  Ctxt_Byte_size);
            free(byteCtxt1);
            paillier_freeplaintext(R);
            paillier_freeciphertext(Aux_Ctx);
            paillier_freeciphertext(Aux_Ctx1);
            paillier_freeciphertext(Aux_Ctx2);
//        memcpy(ctx_final + (((3 * sizeof(size_t)) + AECtxSize) + (( Ctxt_z.size() + j ) * Ctxt_Byte_size)), Ctxt_k,  Ctxt_Byte_size);
//        byteVCtx_Insrt[j] = mpz_get_str(NULL, 10, Aux_Ctx2->c);
        }
        else
        {
//            CtxtGarbage = paillier_create_enc_zero();
//            mpz_init_set_ui(CtxtGarbage->c, 1);
//            paillier_plaintext_t *R;
//            R = (paillier_plaintext_t*) malloc(sizeof(paillier_plaintext_t));
            R = PaillerWrapperFunctions::Rand_Plain_Pail(ppk); //I need to describe a function to generate random number in plaintext.
            CtxtGarbage = paillier_enc(NULL, ppk, R, paillier_get_rand_devrandom);
//            mpz_powm(CtxtGarbage->c, Aux_Ctx2->c, R->m, ppk->n_squared);
            byteCtxt = (char*)paillier_ciphertext_to_bytes(Ctxt_Byte_size, CtxtGarbage);
            memcpy(ctx_final +  (((3 * sizeof(size_t)) + AECtxSize) + (( Ctxt_z.size() + j ) * Ctxt_Byte_size)), byteCtxt,  Ctxt_Byte_size);
            free(byteCtxt);
            paillier_freeplaintext(R);
            paillier_freeciphertext(CtxtGarbage);

        }

    }

//    char* byteCtxtTEST = (char*)malloc(PAILLIER_BITS_TO_BYTES(ppk->bits)*2);
//    memcpy(byteCtxtTEST,  ctx_final + (3 * sizeof(size_t)) + AECtxSize + 39 * Ctxt_Byte_size,  Ctxt_Byte_size);
//
//
//    paillier_ciphertext_t* CTEST;
//    CTEST = paillier_ciphertext_from_bytes((void*)byteCtxtTEST, PAILLIER_BITS_TO_BYTES(ppk->bits)*2);
//
//    /*For debugging to make sure the ctx is ok*/
//    std::fstream secKeyFile("seckey.txt", std::fstream::in);
//    assert(secKeyFile.is_open());
//    std::string hexSecKey;
//    std::getline(secKeyFile, hexSecKey);
//    secKeyFile.close();
//    paillier_prvkey_t*  Pail_Sk;
//    Pail_Sk = paillier_prvkey_from_hex(&hexSecKey[0], ppk);
//    paillier_plaintext_t* dec;
//    dec = paillier_dec(NULL, ppk, Pail_Sk, CTEST);
//    vector<byte> abTEST;
//    abTEST = PaillerWrapperFunctions::mpz_to_vector(dec->m, AES::DEFAULT_KEYLENGTH);
//    abTEST.resize(AES::DEFAULT_KEYLENGTH);
//    std::string sTEST(abTEST.begin(), abTEST.end());

    for(int i=0; i < len + 1; i++)
    {
        paillier_freeciphertext(Ctxt_z[i]);
    }

    paillier_freeplaintext(m);
    paillier_freeplaintext(m_typo);
//    paillier_freeplaintext(R);

    paillier_freeciphertext(Ctxt_k);
    paillier_freeciphertext(Ctxt_typo);
//    paillier_freeciphertext(CtxtGarbage);
//    paillier_freeciphertext(Aux_Ctx);
//    paillier_freeciphertext(Aux_Ctx1);
//    paillier_freeciphertext(Aux_Ctx2);


    for (int i = 0; i < size_typo_unpad; i++)
    {
        paillier_freeciphertext(VCtxt_typo[i]);
    }

//    free(byteCtxt1);
//    free(byteCtxt);
    mpz_clear(aux);
    mpz_clear(aux_Del);
    return "1";
//    return EncrypteKey;

}


int EditDistOne::RegDec(paillier_pubkey_t* ppk,
                        char typo_ctx[],
                         paillier_prvkey_t* psk,
                         string &recovered,
                         size_t _len)
 {
     int ret = 0;
     int PailCtxtSize =  PAILLIER_BITS_TO_BYTES(ppk->bits)*2;
     void* c = malloc(PailCtxtSize);
     auto byteCtxt = static_cast<paillier_ciphertext_t*>(malloc(PailCtxtSize));

     memcpy(c, typo_ctx + 2 * sizeof(size_t), PailCtxtSize);

     byteCtxt = paillier_ciphertext_from_bytes(c, PailCtxtSize);
     paillier_plaintext_t* dec;
     dec = paillier_dec(nullptr, ppk, psk, byteCtxt);
     recovered = paillier_plaintext_to_str_NegOrd(dec);

     ret =1;
     free(c);
     paillier_freeciphertext(byteCtxt);
     paillier_freeplaintext(dec);
     return ret;
 }



vector<paillier_ciphertext_t*> EditDistOne::Pail_Parse_Ctx_size_AECtx(paillier_pubkey_t* ppk,
                                                                      char* ctx, string &CtxAE)
{
    size_t size;
//    free(msg_size);
    memcpy(&size, ctx , sizeof(size_t));


    size_t Ctxt_Elemnt_Size;
//    free(Elements_Size);
    memcpy(&Ctxt_Elemnt_Size, ctx + 2 * sizeof(size_t), sizeof(size_t));


    size_t AE_Ctx_size;
//    free(AECtxtSize);
    memcpy(&AE_Ctx_size, ctx  + sizeof(size_t), sizeof(size_t));


//    string* CtxAE_Char = (string*) malloc(AE_Ctx_size);
//    char* CtxAE_Char = (char*) malloc(AE_Ctx_size);
    string* CtxAE_Char = (string*)malloc(AE_Ctx_size);
//    free(CtxAE_Char);
    memcpy(&CtxAE_Char[0], ctx + 3 * sizeof(size_t), AE_Ctx_size);

//    vector<byte> ab(24);
//    for (int i =0; i< 24; i++)
//    {
//        ab[i] = CtxAE_Char[0][i];
//    }
//
//    ab.resize(24);
//    string s(ab.begin(), ab.end());

    CtxAE = CtxAE_Char[0];
//    CtxAE = CtxAE_Char;


//    Accum_ptr =  Accum_ptr + AE_Ctx_size;

    vector<paillier_ciphertext_t*> Vect_Ctx(size);

    for(int i = 0; i< size; i++ )
    {
        char* byteCtxt1 = (char*)malloc(PAILLIER_BITS_TO_BYTES(ppk->bits)*2);
        memcpy(byteCtxt1,  ctx + 3 * sizeof(size_t) + AE_Ctx_size + i * Ctxt_Elemnt_Size, Ctxt_Elemnt_Size);
//        Accum_ptr = Accum_ptr + Ctxt_Elemnt_Size;

        paillier_ciphertext_t* ctxt1 = paillier_ciphertext_from_bytes((void*)byteCtxt1, PAILLIER_BITS_TO_BYTES(ppk->bits)*2);
//        Vect_Ctx[i] = paillier_ciphertext_from_bytes((void*)byteCtxt1, PAILLIER_BITS_TO_BYTES(ppk->bits)*2);
//        free(byteCtxt1);
        Vect_Ctx[i]  = ctxt1;
    }

    //TODO Free the variables



    free(CtxAE_Char);
//    free((string*)CtxAE_Char);
//    free((char*)byteCtxt1);
    return Vect_Ctx;
}


int EditDistOne::CondDec(paillier_pubkey_t* ppk,
                              char* typo_ctx,
                              paillier_prvkey_t* psk,
                              string &recovered,
                              size_t _len)
{
    int ret = -1;
    vector<paillier_ciphertext_t*> V_ctx_typo( 2 * _len + 1);
//    int VecSize;
    string CtxAE; //Extracting the AE part.

//    V_ctx_typo = EditDistOne::Pail_Parse_Ctx_size_AECtx(ppk, typo_ctx, CtxAE);
//    tuple<vector<paillier_ciphertext_t*>, string> ParsedCtxt;
//    vector<paillier_ciphertext_t*>, string>  ParsedCtxt;
    int pars_rslt =0;
    pars_rslt = EditDistOne::Pail_Parse_Ctx_size_AECtx_V3(ppk, typo_ctx, CtxAE, V_ctx_typo);

//    V_ctx_typo = std::get<0>(ParsedCtxt);
//    V_ctx_typo = ParsedCtxt;

//    CtxAE = std::get<1>(ParsedCtxt);
    size_t Num_of_Psil_Sampl_Ctx = 2 * _len + 1;
    size_t  size_of_AECtxt = sizeof(CtxAE);
//    const string  CTxtAE_const = std::get<1>(ParsedCtxt);;
//    string DecoddCtxAE;
//    DecoddCtxAE = CryptoSymWrapperFunctions::Wrapper_b64decode(CtxAE);
//        if (VecSize != 2 * _len) return -1;

    bool AEReslt;
    paillier_plaintext_t * dec;
//    vector<paillier_plaintext_t *>decVec(Num_of_Psil_Sampl_Ctx);
//    dec = (paillier_plaintext_t*) malloc(sizeof(paillier_plaintext_t));

//    for (int i= 0; i <Num_of_Psil_Sampl_Ctx; i++)
//    {
//        decVec[i] = (paillier_plaintext_t*) malloc(sizeof(paillier_plaintext_t));
//        mpz_init(decVec[i]->m);
//        paillier_dec(decVec[i], ppk, psk, V_ctx_typo[i]);
////        paillier_plaintext_to_bytes(AES::DEFAULT_KEYLENGTH, decVec[i]);
//    }
    void* ByteDec;
//    ByteDec = malloc(AES::DEFAULT_KEYLENGTH);
//    dec = (paillier_plaintext_t*) malloc(sizeof(paillier_plaintext_t));
    for(int i= 0; i<Num_of_Psil_Sampl_Ctx; i++)
    {
        dec = paillier_dec(NULL, ppk, psk, V_ctx_typo[i]);
        vector<CryptoPP::byte> ab(AES::DEFAULT_KEYLENGTH);

//        ByteDec = paillier_plaintext_to_bytes(AES::DEFAULT_KEYLENGTH, dec);
        ByteDec = paillier_plaintext_to_bytes_NegOrd(AES::DEFAULT_KEYLENGTH, dec);
        memcpy(&ab[0],ByteDec, AES::DEFAULT_KEYLENGTH);

//        ab = PaillerWrapperFunctions::mpz_to_vector(decVec[i]->m, AES::DEFAULT_KEYLENGTH); //Problem: I realized that this function causes the segmentation error.
        ab.resize(AES::DEFAULT_KEYLENGTH);
        string s(ab.begin(), ab.end());
        free(ByteDec);
        paillier_freeplaintext(dec);

        string plaintext_rcv;
        AEReslt = CryptoSymWrapperFunctions::Wrapper_AuthDecrypt(s, CtxAE, plaintext_rcv);
//        paillier_freeplaintext(dec);
        if (AEReslt == true)
        {
            recovered = plaintext_rcv;
            ret = 1;
            break;
        }
    }


    for(int i =0; i < Num_of_Psil_Sampl_Ctx;  i++)
    {
//        paillier_freeciphertext(std::get<0>(ParsedCtxt)[i]);
        paillier_freeciphertext(V_ctx_typo[i]);
//        paillier_freeplaintext(decVec[i]);

//        paillier_freeciphertext(ParsedCtxt[i]);
    }

//

    return ret;

}



vector<paillier_ciphertext_t*> EditDistOne::Pail_Parse_Ctx_size_AECtx_V2(paillier_pubkey_t* ppk,
                                                                      char* ctx, string& CTXAE )
{
//    size_t* msg_size =(size_t*) malloc(sizeof(size_t));
    size_t size;
//    free(msg_size);
    memcpy(&size, ctx , sizeof(size_t));
//    const size_t size = msg_size;
//    size_t size = 35;

    size_t AE_Ctx_size;
    memcpy(&AE_Ctx_size, ctx  + sizeof(size_t), sizeof(size_t));
//    const size_t AE_Ctx_size = (size_t) AECtxtSize;
//    size_t AE_Ctx_size =24;

    size_t Ctxt_Elemnt_Size;
    memcpy(&Ctxt_Elemnt_Size, ctx + 2 * sizeof(size_t), sizeof(size_t));
//    const size_t Ctxt_Elemnt_Size = (size_t) Elements_Size;
//    size_t Ctxt_Elemnt_Size = 256;

    string* CtxtAEStr = (string*) malloc(sizeof(char) * AE_Ctx_size);

//    char* CtxtAEStr = (char*) malloc(AE_Ctx_size);

//    string CtxAE_String;
    memcpy(&CtxtAEStr[0], ctx + 3 * sizeof(size_t), AE_Ctx_size); //Correct

//    const string CTXAE = CtxtAEStr[0];
    CTXAE = CtxtAEStr[0];

//    string* CtxAE_Char = (string*) malloc(AE_Ctx_size);
//    char* CtxAE_Char = (char*) malloc(AE_Ctx_size);
//    string* CtxAE_Char = (string*) malloc(AE_Ctx_size);
//    string CtxAE_Char[0];
//    free(&CtxAE_Char[0]);
//    memcpy(CtxAE_Char, ctx + 3 * sizeof(size_t), AE_Ctx_size);
//    string CtxAE;
//    CtxAE = CtxAE_String;
//    CtxAE = CtxAE_Char[0];

//    free(CtxAE_Char);
//    CtxAE = CtxAE_Char;


//    Accum_ptr =  Accum_ptr + AE_Ctx_size;
    vector<paillier_ciphertext_t*> Vect_Ctx(size);
    char* byteCtxt1 = (char*)malloc(PAILLIER_BITS_TO_BYTES(ppk->bits)*2);
//    free((char*)byteCtxt1);
    for(int i = 0; i< size; i++ )
    {
//        char* byteCtxt1 = (char*)malloc(PAILLIER_BITS_TO_BYTES(ppk->bits)*2);
        memcpy(byteCtxt1,  ctx + 3 * sizeof(size_t) + AE_Ctx_size + i * Ctxt_Elemnt_Size, Ctxt_Elemnt_Size);
//        Accum_ptr = Accum_ptr + Ctxt_Elemnt_Size;
        Vect_Ctx[i] = paillier_ciphertext_from_bytes((void*)byteCtxt1, PAILLIER_BITS_TO_BYTES(ppk->bits)*2);
    }

//    tuple<vector<paillier_ciphertext_t*>, string> Output;
//    Output = make_tuple(Vect_Ctx, CTXAE);

//    for(int i = 0; i < size; i++)
//    {
//        paillier_freeciphertext(Vect_Ctx[i]);
//    }

    free(byteCtxt1);
    free(&CtxtAEStr[0]);
//    free(CtxtAEStr);
//    return make_tuple(Vect_Ctx, CTXAE);
    return Vect_Ctx;

//    return Output;

}


int EditDistOne::Pail_Parse_Ctx_size_AECtx_V3(paillier_pubkey_t* ppk,
                                              char* ctx, string& CtxtAEStr,
                                              vector<paillier_ciphertext_t*> &Vect_Ctx)
{
    size_t size;
    memcpy(&size, ctx , sizeof(size_t));
    size_t AE_Ctx_size;
    memcpy(&AE_Ctx_size, ctx  + sizeof(size_t), sizeof(size_t));
    size_t Ctxt_Elemnt_Size;
    memcpy(&Ctxt_Elemnt_Size, ctx + 2 * sizeof(size_t), sizeof(size_t));

    // string* CtxtAEStrPre = (string*) malloc (AE_Ctx_size);
    std::string* CtxtAEStrPre = new std::string[1];
     CtxtAEStrPre[0].resize(AE_Ctx_size);
    memcpy(&CtxtAEStrPre[0][0], ctx + 3 * sizeof(size_t),  AE_Ctx_size * sizeof(char)); //Correct
//    CtxtAEStr = CtxtAEStrPre[0];

    CryptoPP::StringSink ss(CtxtAEStr);
    cout << "\n";
    ss.Put((const CryptoPP::byte*)CtxtAEStrPre[0].data(),  CtxtAEStrPre[0].size(), false);

//    assert(CtxtAEStr = CtxtAEStrPre);

    // free(CtxtAEStrPre);
     delete[] CtxtAEStrPre;

//    byte* a = new byte[AE_Ctx_size];
//    memcpy(a, ctx + 3 * sizeof(size_t),  AE_Ctx_size); //Correct
//
////    CryptoPP::StringSource ss(CtxtAEStrPre[0], true /*pumpAll*/,new StringSink(CtxtAEStr)); // StringSink
//    CryptoPP::StringSource ss(a,AE_Ctx_size, true /*pumpAll*/,new StringSink(CtxtAEStr)); // StringSink
//    delete []a;

//    vector<paillier_ciphertext_t*> Vect_Ctx(size);
    char* byteCtxt1 = (char*)malloc(PAILLIER_BITS_TO_BYTES(ppk->bits)*2);

    for(int i = 0; i< size; i++ )
    {
//        char* byteCtxt1 = (char*)malloc(PAILLIER_BITS_TO_BYTES(ppk->bits)*2);
        memcpy(byteCtxt1,  ctx + 3 * sizeof(size_t) + AE_Ctx_size + i * Ctxt_Elemnt_Size, Ctxt_Elemnt_Size);
//        Accum_ptr = Accum_ptr + Ctxt_Elemnt_Size;
        Vect_Ctx[i] = paillier_ciphertext_from_bytes((void*)byteCtxt1, PAILLIER_BITS_TO_BYTES(ppk->bits)*2);
    }

//    tuple<vector<paillier_ciphertext_t*>, string> Output;
//    Output = make_tuple(Vect_Ctx, CTXAE);

//    for(int i = 0; i < size; i++)
//    {
//        paillier_freeciphertext(Vect_Ctx[i]);
//    }


//    free(CtxtAEStrPre);
    free(byteCtxt1);

//    free(&CtxtAEStr[0]);
//    free(CtxtAEStr);
    return 1;
//    return Vect_Ctx;

//    return Output;

}