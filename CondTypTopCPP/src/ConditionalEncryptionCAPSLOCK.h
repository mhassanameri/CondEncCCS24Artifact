//
// Created by mameriek on 9/28/21.
//

#ifndef CONDENCCPP_CONDITIONALENCRYPTIONCAPSLOCK_H
#define CONDENCCPP_CONDITIONALENCRYPTIONCAPSLOCK_H

#include "PaillierWrapperFunctions.h"
#include "CryptoSymWrapperFunctions.h"
//#include "conditionalcrypto.h"



//class CAPLOCKpredicate: public ConditionalEncryption {
class CAPLOCKpredicate {
public:
    /* API Documentation
      * Algorithm description:  Regular encryption for CAPLOCK Conditional Encryption scheme
      * Uses pallier partially homomorphic encryption scheme, i.e., Paillier.
      * Inputs:
      *    paillier_pubkey_t* ppk                - the public key for our conditional encryption scheme
      *                                              (a pallier public key)
      *    const string &msg                     - the input message msg of arbitrary length
      *  Output:
      *    string &tx                            - the output ciphertext will be written here.
      * */

    /*
     * The simple Encryption algorithm, Outputs the Byte vectro as ctxt.
     * */
    static int Enc(const paillier_pubkey_t* ppk, const string &msg, char ctx_final[]);


    /* API Documenation should specify
	 * Conditional Encryption for CAPSLOCK predicate
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



    /*
     * The CondEnc with ciphertext in char*;
     * */

    static string CondEnc(paillier_pubkey_t *ppk,
                       char RlPwd_ctx_pull[],
                       string& m1,
                       string& m2,
                       char ctx_final[]);

    /* API Documenation should specify
	 * Conditional decryption for CAPSLOCK predicate
	 * TODO: ADD inputs/outputs
	 */

    /*
     * The conditional decryption when the input ciphertext is char*
     * */

    static int CondDec( paillier_pubkey_t* ppk,
                         char* typo_ctx,
                         paillier_prvkey_t* psk,
                         string &recovered);

	static int RegDec(paillier_pubkey_t* ppk,
						 char typo_ctx[],
						 paillier_prvkey_t* psk,
						 string &recovered,
						 size_t _len);

    /*
 * Function to convert characters of a string to opposite case. For example, the word
 * pwd = "Password" will be tranferred to pwd = "pASSWORD" by running convertOpposite(pwd).
 */
    static int convertOpposite(string& str);

private:

    /*
     * This function takes as input the paillier public key ppk, the pointer to the coniditonal CTXt and
     * outputs the vector of the pailier ciphertexts (Vect_Ctx) and the cihphertext of the
     * Authenticated encryption (CtxAEStr). We note that the size of the vector is one as we just consider
     * the capslock predicate which is extracted by encrypting the input message when converted the their
     * corresponding chars when the capslock key is on.
     * */

    static int Pail_Parse_Ctx_size_AECtx_CPSALOcK(const paillier_pubkey_t* ppk,
                                                  const char* ctx, string& CtxtAEStr,
                                                  vector<paillier_ciphertext_t*> &Vect_Ctx);

};







// Function to convert characters
// of a string to opposite case




#endif //CONDENCCPP_CONDITIONALENCRYPTIONCAPSLOCK_H
