//
// Created by mameriek on 9/17/21.
//

#include "ConditionalEncryptionOR.h"
#include <chrono>
using namespace std::chrono;

/*
 * High level functionality: The algorithm calls the tradtitional encryption schemes of two classes HamDistAtmostT and
 * EditDistOne and concatenate the ciphertext with each other and generates the final ctxt.
 *
 *
 * */

  int OrPredicate::Enc(paillier_pubkey_t* ppk, string &msg, char* ctx_final, size_t _len)
{
     size_t CapsLockCtxSize = 2 * sizeof(size_t) +  PAILLIER_BITS_TO_BYTES(ppk->bits)*2;
     size_t EDOneCtxSize    = 2 * sizeof(size_t) + (_len + 1)  *  PAILLIER_BITS_TO_BYTES(ppk->bits)*2;
     size_t HDTwoCtxSize    = 2 * sizeof(size_t) + _len *  PAILLIER_BITS_TO_BYTES(ppk->bits)*2;


//     char Aux_ctx_EDOne [EDOneCtxSize];
//     char Aux_ctx_HDTwo [HDTwoCtxSize];
//     char Aux_ctx_CAPS [CapsLockCtxSize];

     string msg_pad = CryptoSymWrapperFunctions::Wrapper_pad(msg, _len);//assuming the the imput message is given in unpadded version.

     // std::unique_ptr<EditDistOne> EDOneClass(new EditDistOne());
     // std::unique_ptr<HamDistAtmostT>  HamDisTwoClass(new HamDistAtmostT());
     // std::unique_ptr<CAPLOCKpredicate>  CAPLOCKClass(new CAPLOCKpredicate());


//     int EditOneOrigCtxtRslt = EditDistOne::Enc(ppk,msg_pad, Aux_ctx_EDOne);
//     int HamDisTwoOrigCtxtRslt = HamDistAtmostT::Enc(ppk,msg_pad, Aux_ctx_HDTwo);
//     int CApsOrigCtxtRslt  = CAPLOCKpredicate::Enc(ppk, msg, Aux_ctx_CAPS);

//     int CApsOrigCtxtRslt  = CAPLOCKpredicate::Enc(ppk, msg, ctx_final);
//     int EditOneOrigCtxtRslt = EditDistOne::Enc(ppk,msg_pad, ctx_final + CapsLockCtxSize);
//     int HamDisTwoOrigCtxtRslt = HamDistAtmostT::Enc(ppk,msg_pad, ctx_final + CapsLockCtxSize + EDOneCtxSize);

    int CApsOrigCtxtRslt    = CAPLOCKpredicate::Enc(ppk, msg, ctx_final);
    int EditOneOrigCtxtRslt = EditDistOne::Enc(ppk,msg_pad, ctx_final + CapsLockCtxSize);
    int HamDisTwoOrigCtxtRslt = HamDistAtmostT::Enc(ppk,msg_pad, ctx_final + CapsLockCtxSize + EDOneCtxSize);
     /*Using the smart pointer to avoid memory leakage*/


    // CAPLOCKClass.reset();
    // HamDisTwoClass.reset();
    // EDOneClass.reset();

     //

//     size_t CumPtr = 0;

//     memcpy(ctx_final, Aux_ctx_CAPS, CapsLockCtxSize);
//     CumPtr = CumPtr + CapsLockCtxSize;
//
//     memcpy(ctx_final + CumPtr, Aux_ctx_EDOne, EDOneCtxSize);
//     CumPtr = CumPtr +EDOneCtxSize;
//
//     memcpy(ctx_final + CumPtr, Aux_ctx_HDTwo,HDTwoCtxSize );

     return 1;

}


  string OrPredicate::CondEnc(paillier_pubkey_t* ppk,
                       char* Orig_ctx_pull,
                       string& typo,
                       string& payload,
                       size_t _len,
                       int threshold,
                       char* ctx_final)
{

      size_t PailCtxtSize = PAILLIER_BITS_TO_BYTES(ppk->bits)*2;
      size_t AE_CtxtSize = 2 * KEYSIZE_BYTES + _len;


      size_t EDOneOrigCtxSize   = 2 * sizeof(size_t) + (_len + 1)  *  PailCtxtSize;
      size_t HDTwoOrigCtxSize   = 2 * sizeof(size_t) + _len *  PailCtxtSize;
      size_t CAPSLocOrigCtxSize = 2 * sizeof(size_t) +  PailCtxtSize;

      size_t CondEncEDOneCtxSize = 3 * sizeof(size_t) + (sizeof(char) * AE_CtxtSize) + (2 * _len + 1) *  PailCtxtSize;
      size_t CondEncHDTwoCtxSize = 3 * sizeof(size_t) + (sizeof(char) * AE_CtxtSize) + (_len *  PailCtxtSize);
      size_t CondEncCPSLKCtxSize = 3 * sizeof(size_t) + (sizeof(char) * AE_CtxtSize) +  PailCtxtSize;

      std::string pad_typo = CryptoSymWrapperFunctions::Wrapper_pad(typo, _len);

      string ctx_CPSLKRslt;
      ctx_CPSLKRslt = CAPLOCKpredicate::CondEnc(ppk, Orig_ctx_pull, typo, payload,  ctx_final);
      // cout << "The CapsLOCK Encrypt is Done\n";
      std::string ctx_EDOneRlst;
      ctx_EDOneRlst= EditDistOne::CondEnc(ppk, Orig_ctx_pull + CAPSLocOrigCtxSize, pad_typo, payload,_len, ctx_final + CondEncCPSLKCtxSize ); //TODO: make sure that the typo is padded [Impprtant], AND remember: Thershold should be 30,

      // cout << "The EDOne Encrypt is Done\n";
      std::string ctx_HDTowRslt;
      ctx_HDTowRslt = HamDistAtmostT::CondEnc(ppk, Orig_ctx_pull + CAPSLocOrigCtxSize + EDOneOrigCtxSize, typo, payload,_len, threshold, ctx_final + CondEncCPSLKCtxSize + CondEncEDOneCtxSize); //the threshold is 30 here as well
      // cout << "The OR Encrypt is Done\n";
      return "1";

}

 int OrPredicate::CondDec(paillier_pubkey_t* ppk,
                          char* typo_ctx,
                          paillier_prvkey_t* psk,
                          int threshold,
                          string &recovered,
                          size_t _len)
{

//    int VecSize;

    size_t CumSize =0;

    // size_t AE_CtxtSize = 2 * KEYSIZE_BYTES + 38;
      size_t AE_CtxtSize = 2 * KEYSIZE_BYTES + _len;



    size_t PailCtxtSize = PAILLIER_BITS_TO_BYTES(ppk->bits)*2; //computing the size of Paillier CTXs.
    size_t CondEncCPSLKCtxSize = 3 * sizeof(size_t) + sizeof(char) *  AE_CtxtSize  +  PailCtxtSize;
    size_t CondEncEDOneCtxSize = 3 * sizeof(size_t) + sizeof (char) * AE_CtxtSize  + ((2 * _len + 1) *  PailCtxtSize);
    size_t CondEncHDTwoCtxSize = 3 * sizeof(size_t) + (sizeof(char) * AE_CtxtSize) + (_len *  PailCtxtSize);

    string AE_ctx_CAPS;
    string AE_ctx_EDOne;
    string AE_ctx_HDTwo;


     // std::unique_ptr<EditDistOne> EDOneClass(new EditDistOne());
     // std::unique_ptr<HamDistAtmostT>  HamDisTwoClass(new HamDistAtmostT());
     // std::unique_ptr<CAPLOCKpredicate>  CAPLOCKClass(new CAPLOCKpredicate());

//    memcpy(Aux_Cond_ctx_CAPS, typo_ctx, CondEncCPSLKCtxSize );
//    CumSize = CumSize + CondEncCPSLKCtxSize;
//
//    memcpy(Aux_Cond_ctx_EDOne, typo_ctx + CumSize, CondEncEDOneCtxSize);
//    CumSize = CumSize + CondEncEDOneCtxSize;
//
//    memcpy(Aux_Cond_ctx_HDTwo, typo_ctx + CumSize, CondEncHDTwoCtxSize);


    int RsltCAPS  = 0;
    int RsltHDTwo = 0;
    int RsltEDOne = 0;


    string RecoverCAPS;
    string RecoverHDTwo;
    string RecoverEDOne;



      // cout << "start to decrypt CAPSLOACK\n";
     RsltCAPS  = CAPLOCKpredicate::CondDec(ppk, typo_ctx, psk, RecoverCAPS);

     if (RsltCAPS == 1)
     {
        recovered = RecoverCAPS;
         return RsltCAPS;
     }

      // cout << "start to decrypt EDOne\n";
    RsltEDOne = EditDistOne::CondDec(ppk, typo_ctx + CondEncCPSLKCtxSize, psk, RecoverEDOne, _len);

    if (RsltEDOne == 1)
    {
        recovered = RecoverEDOne;
        return RsltEDOne;
    }


    // cout << "start to decrypt HmaDis\n";
    // RsltHDTwo = HamDistAtmostT::CondDec(ppk, typo_ctx + CondEncCPSLKCtxSize + CondEncEDOneCtxSize, psk,threshold, RecoverHDTwo, _len, ShareSize);
    RsltHDTwo = HamDistAtmostT::CondDec(ppk, typo_ctx + CondEncCPSLKCtxSize + CondEncEDOneCtxSize, psk,threshold, RecoverHDTwo, _len);


    if (RsltHDTwo == 1)
    {
        recovered = RecoverHDTwo;
        return RsltHDTwo;
    }



     // CAPLOCKClass.reset();
     // HamDisTwoClass.reset();
     // EDOneClass.reset();

    return -1;
}


 int OrPredicate::CondDec_Optimized_for_HD2( paillier_pubkey_t *ppk,
                                      char* typo_ctx,
                                      paillier_prvkey_t* psk,
                                      int threshold,
                                      string &recovered,
                                      size_t _len)
 {

      size_t AE_CtxtSize = 2 * KEYSIZE_BYTES + _len;
      size_t CumSize =0;
     size_t PailCtxtSize = PAILLIER_BITS_TO_BYTES(ppk->bits)*2; //computing the size of Paillier CTXs.
     size_t CondEncCPSLKCtxSize = 3 * sizeof(size_t) + sizeof(char) *  AE_CtxtSize  +  PailCtxtSize;
     size_t CondEncEDOneCtxSize = 3 * sizeof(size_t) + sizeof (char) * AE_CtxtSize  + ((2 * _len + 1) *  PailCtxtSize);

     std::unique_ptr<EditDistOne> EDOneClass(new EditDistOne());
     std::unique_ptr<HamDistAtmostT>  HamDisTwoClass(new HamDistAtmostT());
     std::unique_ptr<CAPLOCKpredicate>  CAPLOCKClass(new CAPLOCKpredicate());


     int RsltCAPS  = 0;
     int RsltHDTwo = 0;
     int RsltEDOne = 0;


     string RecoverCAPS;
     string RecoverHDTwo;
     string RecoverEDOne;




     RsltCAPS  = CAPLOCKClass->CondDec(ppk, typo_ctx, psk, RecoverCAPS);

     if (RsltCAPS == 1)
     {
         recovered = RecoverCAPS;
         return RsltCAPS;
     }


     RsltEDOne = EDOneClass->CondDec(ppk, typo_ctx + CondEncCPSLKCtxSize, psk, RecoverEDOne, _len);

     if (RsltEDOne == 1)
     {
         recovered = RecoverEDOne;
         return RsltEDOne;
     }


     // RsltHDTwo = HamDisTwoClass->CondDec_2dif(ppk, typo_ctx + CondEncCPSLKCtxSize + CondEncEDOneCtxSize, psk,threshold, RecoverHDTwo, _len);
      RsltHDTwo = HamDisTwoClass->CondDec_NewOPT(ppk, typo_ctx + CondEncCPSLKCtxSize + CondEncEDOneCtxSize, psk,threshold, RecoverHDTwo, _len);


     if (RsltHDTwo == 1)
     {
         recovered = RecoverHDTwo;
         return RsltHDTwo;
     }



     CAPLOCKClass.reset();
     HamDisTwoClass.reset();
     EDOneClass.reset();

     return -1;


 }


 size_t OrPredicate::Trad_Ctxt_Size_Calculator (size_t len, size_t PailCtxtSize)
 {

     size_t threshold = len-2;


     size_t EDOneOrigCtxSize   = 2 * sizeof(size_t) + (len + 1)  *  PailCtxtSize;
     size_t HDTwoOrigCtxSize   = 2 * sizeof(size_t) + len *  PailCtxtSize;
     size_t CAPSLocOrigCtxSize = 2 * sizeof(size_t) +  PailCtxtSize;

     size_t ORPrdrigCtxSize = CAPSLocOrigCtxSize + EDOneOrigCtxSize + HDTwoOrigCtxSize;
     return ORPrdrigCtxSize;

 }

 size_t OrPredicate::CondEnc_Ctxt_Size_Calculator (size_t len, size_t PailCtxtSize, size_t AE_Ctxt_Size)
 {
     size_t CondEncEDOneCtxSize = 3 * sizeof(size_t) + (sizeof(char) * AE_Ctxt_Size) + ((2 * len) + 1) *  PailCtxtSize;
     size_t CondEncHDTwoCtxSize = 3 * sizeof(size_t) + (sizeof(char) * AE_Ctxt_Size) + (len *  PailCtxtSize);
     size_t CondEncCPSLKCtxSize = 3 * sizeof(size_t) + (sizeof(char) * AE_Ctxt_Size) +  PailCtxtSize;

     size_t CondEncOR_CtxSize = CondEncCPSLKCtxSize + CondEncEDOneCtxSize + CondEncHDTwoCtxSize;

     return CondEncOR_CtxSize;

 }



// TODO: Update to include parsing for CAPS lock as third component
 vector<string> OrPredicate::OR_Predicate_Parsing(string& ctx, int& VecSize)
{

    vector<string> vctx;
    //    = (char*)malloc(PAILLIER_BITS_TO_BYTES(ppk->bits)*2 );

    std::string delimiter = "Prdct.OR";
    string s =  ctx;
    int counter = 0;
    int AECtxContr = 0;
    size_t pos = 0;
    std::string token;
    while ((pos = s.find(delimiter)) != std::string::npos) {
        token = s.substr(0, pos);
        vctx.push_back(token);
        s.erase(0, pos + delimiter.length());
        counter++;
    }
    VecSize = counter;
    return  vctx;
}



