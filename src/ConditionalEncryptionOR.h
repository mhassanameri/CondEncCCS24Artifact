//
// Created by mameriek on 9/17/21.
//

#ifndef CONDENCCPP_CONDITIONALENCRYPTIONOR_H
#define CONDENCCPP_CONDITIONALENCRYPTIONOR_H


//#include "conditionalcrypto.h"
#include "ConditionalEncryptionCAPSLOCK.h"
#include "ConditionalEncryptionEditDistOne.h"
#include "ConditionalEncryptionHamDistAtmostT.h"

//

class OrPredicate {

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

    static int Enc(paillier_pubkey_t* ppk, string &msg, char* ctx_final, size_t _len);



    /* API Documenation should specify
	 * Conditional Encryption for OR of Hamming Distance Two and Edit Distance One predicates
	 * Inputs:
	 *    paillier_pubkey_t* ppk         - the public key for our conditional encryption scheme (a pallier public key)
	 *    const string& RlPwd_ctx_pull   - the input ciphertext of some (unknown) original message x
	 *    const string typo              - input string which may or may not have ED(typo,x)<= 1 OR HD(typo, x) <= 2
	 *    const string payload           - the input message to be conditionally encypted based on the predicate ED(typo,x)<= 1 OR HD(typo, x) <= 2
	 *    string &output_ce_ctx          - the output ciphertext will be written here. If ED(typo,x) > 1 the ciphertext reveals nothing about inputs typo or payload or x
	 *                                     otherwise if ED(typo,x)<=1 then the ciphertext can be decrypted to recover the string payload
     *    size_t _len                    - Determines the size of padded message
	 *    Question: where are the encryption keys as inputs?
	 *
     * This following conditional encryption fucntion, supports the  prediciate of edit distance 1.
     *

     * */


    static string CondEnc(paillier_pubkey_t *ppk,
                          char* RlPwd_ctx_pull,
                          string& typo,
                          string& payload,
                          size_t _len,
                          int threshold,
                          char* ctx_final);


    static int CondDec( paillier_pubkey_t *ppk,
                        char* typo_ctx,
                        paillier_prvkey_t* psk,
                        int threshold,
                        string &recovered,
                        size_t _len);



    /*
     * Main goal: The following function is the opitmized version of the conditional decryption whene we know what is
     * the size of the original message m. Let the size of message be l_m. Consider the case of HD at most 2. In our
     * implementation we used secret sharing scheme and we need to search over the shares to find the valod shares to
     * extract the original secret and extract the secret key to extract the legitimate payload m'. So for the aim of
     * optimizing the decryption, we can just consider the shares after the l_m-th shares as the valid share and then
     *
     *
     * Main difference: The followin optimized decryption function is deesigned for the case that we know the size of
     * original message m. As we know what is the size of the message, for the case of hamming Distance at most 2, when
     * we use the secret sharing scheme, we know the shares related to the padding part are the valid shares and we just
     * need to find the valid remaining shares among the
     *
     * In this function, ppk is the public key, typo_ctx is the input ctx, psk is the associated secret key, threshold
     * is the number of minimum required valid share to recover the typo (or payload), recovered is the resulting payload
     * in the case that the payload and the original message are satisfying the OR predicate, _len is the maximum size
     * of the input messages and l_m is the size of original message m.
     * */



    static int CondDec_Optimized_for_HD2( paillier_pubkey_t *ppk,
                        char* typo_ctx,
                        paillier_prvkey_t* psk,
                        int threshold,
                        string &recovered,
                        size_t _len);


    /*
     * This function takes as input the size of the a single Partially Homomorphic Encryption ciphertext size
     * (Paillier in our implementation) PailCtxtSize and the padding length len and computes the size of
     * traditional ciphertext. (The tranditional ctxt can be used to conditionally encrypt the payload.
     * */

    static size_t Trad_Ctxt_Size_Calculator (size_t len, size_t PailCtxtSize);



    /*
     * This function takes the padding size len, the PHE ciphertexct size (Paillier scheme) and the size of
     *  authenticated encryption ciphertext AE_Ctxt_Size and computes the size of conditional encryption ciphertext of
     *  the OR of HD at most 2, ED at most one, CAPSLOCK_ON predicates.
     * encryption c
     * */


    static size_t CondEnc_Ctxt_Size_Calculator (size_t len, size_t PailCtxtSize, size_t AE_Ctxt_Size);





private:

    static vector<string> OR_Predicate_Parsing(string& ctx, int& VecSize);


};


#endif //CONDENCCPP_CONDITIONALENCRYPTIONOR_H
