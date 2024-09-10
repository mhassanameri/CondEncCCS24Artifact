//
// Created by mameriek on 9/6/21.
//

/*
 * In this document we introduce the concept of conditional encryption under the predicate
 * Edit distance one.
 * */



#ifndef CONDENCCPP_CONDITIONALENCRYPTIONEDITDISTONE_H
#define CONDENCCPP_CONDITIONALENCRYPTIONEDITDISTONE_H

#include "PaillierWrapperFunctions.h"
#include "CryptoSymWrapperFunctions.h"
//#include "conditionalcrypto.h"

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


//PaillerWrapperFunctions, CryptoSymWrapperFunctions
class EditDistOne {
public:

    /* API Documentation
      * Algorithm description:  Simple Encryption scheme which uses the traditional encryption schemes (here we use Partially
      * homomorphic encryption scheme, i.e., Paillier.
      * Inputs:
      *    paillier_pubkey_t* ppk                - the public key for our conditional encryption scheme
      *                                              (a pallier public key)
      *    const string &msg                     - the input message msg of arbitrary length
      *  Output:
      *    string &tx                            - the output ciphertext will be written here.
      * */



    /*
     * API is similar to Enc, but the output ciphertext is pointer to byte array of unsigned char*
     * */

    static int Enc(paillier_pubkey_t* ppk, string &msg, char ctx_final[]);




    /* API Documenation should specify
	 * Conditional Encryption for Edit Distance One Predicate
	 * Inputs:
	 *    paillier_pubkey_t* ppk         - the public key for our conditional encryption scheme (a pallier public key)
	 *    const string& RlPwd_ctx_pull   - the input ciphertext of some (unknown) original message x
	 *    const string typo              - input string which may or may not have ED(typo,x)<= 1
	 *    const string payload           - the input message to be conditionally encypted based on the predicate ED(typo,x)<= 1
	 *    string &output_ce_ctx          - the output ciphertext will be written here. If ED(typo,x) > 1 the ciphertext reveals nothing about inputs typo or payload or x
	 *                                     otherwise if ED(typo,x)<=1 then the ciphertext can be decrypted to recover the string payload
     *    size_t _len                    - Determines the size of padded message
	 *    TODO: extra input should be public key for conditional encryption scheme (a Pallier Key). We do not want to rely on global variables!
	 *    Question: where are the encryption keys as inputs?
	 *
     * This following conditional encryption fucntion, supports the  prediciate of edit distance 1.
     *

     * */


    /*
     * The functionality is similar to the CondEnc while the output is pointer to byte string of unsined char*
     * TODO: Here the variabel _len is the lenght of the original message. We need to decide what length is important to be considered. padded/ or not padded.
     * */
    static string CondEnc(paillier_pubkey_t* ppk,
                              char RlPwd_ctx_pull[],
                              string& typo,
                              string& payload,
                              size_t _len,
                               char ctx_final[]);


    static vector<paillier_ciphertext_t*> Pail_Parse_Ctx_size_AECtx(paillier_pubkey_t* ppk,
                                                                    char* ctx, string &CtxAE);

//    static tuple<vector<paillier_ciphertext_t*>, const string>  Pail_Parse_Ctx_size_AECtx_V2(paillier_pubkey_t* ppk,
//                                                                    char* ctx);
    static vector<paillier_ciphertext_t*> Pail_Parse_Ctx_size_AECtx_V2(paillier_pubkey_t* ppk,
                                                                                             char* ctx, string& CTXAE);
    static int Pail_Parse_Ctx_size_AECtx_V3(paillier_pubkey_t* ppk,
                                                                                      char* ctx, string& CtxtAEStr,
                                                                                      vector<paillier_ciphertext_t*> &Vect_Ctx);

    /*
	*  TODO: Document API here.
	* Inputs:
	*  const string &typo_ctx           - the ciphertext to decrypt
	*  paillier_pubkey_t* ppk           - the public key for our conditional encryption scheme (is this needed here?)
	*  paillier_prvkey_t* psk           - the secrtet  key for our conditional encryption scheme (a pallier secret key)
	*  string &recovered                - the decrypted message will be written here (might be garbage )
    *
	* Returns 1 if the message was successfully recovered; -1 if recovery failed
	*/

    static int CondDec(paillier_pubkey_t* ppk,
                             char* typo_ctx,
                             paillier_prvkey_t* psk,
                             string &recovered,
                             size_t _len);

};
#endif //CONDENCCPP_CONDITIONALENCRYPTIONEDITDISTONE_H
