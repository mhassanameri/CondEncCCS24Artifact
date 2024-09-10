//
// Created by rahul on 3/28/17.
//
#include  "pkcspad.h"
#include "pw_crypto.h"
#include "catch.hpp"
#include "db.pb.h"
#include "PaillierWrapperFunctions.h"
#include "CryptoSymWrapperFunctions.h"

#include "ConditionalEncryptionHamDistTwo.h"
#include "ConditionalEncryptionOR.h"
#include "ConditionalEncryptionCAPSLOCK.h"
#include "ConditionalEncryptionEditDistOne.h"
#include <iostream>
#include <fstream>
#include <chrono>
using namespace std::chrono;
using std::vector;

string random_msg() {
    SecByteBlock s(32);
    PRNG.GenerateBlock(s.data(), s.size());
    return string(s.begin(), s.end());
}

void get_random_ench(typtop::EncHeaderData& ench) {
    string pw(20, 0);
    PRNG.GenerateBlock((byte*)pw.data(), 20);  // might throw segfault
    ench.set_pw(pw);
    ench.set_pw_ent((float)-93.346);
    for (int i = 0; i < 10; i++) {
        ench.add_freq(3);
        ench.add_last_used(13123);
    }
    ench.set_freq(2, 24);
}


TEST_CASE("Generating Raw data files for storing the extracted data after testing")
{

    std::ofstream HDdataL("HDdataL.dat", std::ios_base::app | std::ios_base::out);
    std::ofstream HDdataT("HDdataT.dat", std::ios_base::app | std::ios_base::out);
    std::ofstream EDOnedataL("EDOnedataL.dat", std::ios_base::app | std::ios_base::out);
    std::ofstream CAPSLKdataL("CAPSLKdataL.dat", std::ios_base::app | std::ios_base::out);
    std::ofstream ORdataL("ORdataL.dat", std::ios_base::app | std::ios_base::out);
    std::ofstream SSdataL("SecretSharing.dat", std::ios_base::app | std::ios_base::out);


    HDdataL << "L" << "\t" << "Enc" << "\t" << "CondEnc"<< "\t" << "CondDec" << "\t" << "CtxtSize" << "\t" << "CondCtxtSize\n";
    HDdataT << "T" << "\t" << "Enc" << "\t" << "CondEnc"<< "\t" << "CondDec" << "\t" << "CtxtSize" << "\t" << "CondCtxtSize\n";
    EDOnedataL << "L" << "\t" << "Enc" << "\t" << "CondEnc"<< "\t" << "CondDec" << "\t" << "CtxtSize" << "\t" << "CondCtxtSize\n";
    CAPSLKdataL << "L" << "\t" << "Enc" << "\t" << "CondEnc"<< "\t" << "CondDec" << "\t" << "CtxtSize" << "\t" << "CondCtxtSize\n";
    ORdataL << "L" << "\t" << "Enc" << "\t" << "CondEnc"<< "\t" << "CondDec" << "\t" << "CtxtSize" << "\t" << "CondCtxtSize\n";
    SSdataL << "T" << "\t" << "Recover\n";
}

//TEST_CASE("Secret Sharing execition time, threshold  = 7")
//{
//
//    string b(AES::DEFAULT_KEYLENGTH, 0);
//    PRNG.GenerateBlock((byte *) b.data(), b.size());
//    string Zero_secret = "0000";
//    int threshold = 7;
//    string test  = "TESTTEST";
//    string EncrypteKey;
//    int shares = 8; //the value of _len = 8
//
//
//    string seed = CryptoPP::IntToString(time(NULL));
//    seed.resize(16, ' ');
//    CryptoPP::RandomPool rng;
//    rng.IncorporateEntropy((byte *)seed.data(), strlen(seed.data()));
//
//    CryptoPP::ChannelSwitch *channelSwitch;
//    channelSwitch = NULLPTR;
//    CryptoPP::ChannelSwitch *channelSwitch_Zero;
//    channelSwitch_Zero = NULLPTR;
//
//    PRNG.GenerateBlock((byte *) b.data(), b.size());
//    CryptoSymWrapperFunctions::Wrapper_AuthEncrypt(b, test, EncrypteKey);
//
//    string plain_text;
//    CryptoSymWrapperFunctions::Wrapper_AuthDecrypt(b, EncrypteKey, plain_text);
//
//    assert (plain_text == test);
//
//
//    CryptoPP::StringSource source(b, false,
//                                  new CryptoPP::SecretSharing(rng, threshold, shares,
//                                                              channelSwitch = new CryptoPP::ChannelSwitch, false));
//
//    CryptoPP::StringSource source_Zero(Zero_secret, false, new CryptoPP::SecretSharing(rng, threshold, shares,
//                                                                                       channelSwitch_Zero = new CryptoPP::ChannelSwitch,false)); //Genreating the shares for Zero: "0"
//
//    vector<string> strShares(shares);
//    vector<string> Plain_strShares(shares);
//    vector<string> strShares_for_recover(shares);
//    CryptoPP::vector_member_ptrs<CryptoPP::StringSink> strSinks(shares);
//    string channel;
//
//
//    vector<string> strShares_Zero(shares);
//    vector<string> Plain_strShares_Zero(shares);
//    vector<string> strShares_for_recover_zero(shares);
//    CryptoPP::vector_member_ptrs<CryptoPP::StringSink> strSinks_Zero(shares);
//    string channel_Zero;
//
//    const unsigned int CHID_LENGTH = 4;
//
//    // ********** Create Shares for the AES secret information "b".
//    for (unsigned int i = 0; i < shares; i++) {
//        strSinks[i].reset(new CryptoPP::StringSink(strShares[i]));
//        channel = CryptoPP::WordToString<word32>(i);
//        strSinks[i]->Put((byte *) channel.data(), CHID_LENGTH);
//        channelSwitch->AddRoute(channel, *strSinks[i],DEFAULT_CHANNEL  ); //CryptoPP::BufferedTransformation::NULL_CHANNEL
//    }
//    source.PumpAll();
//
//
//    // ********** Create and assigns the Shares for the zero part
//    for (unsigned int i = 0; i < shares; i++) {
//        strSinks_Zero[i].reset(new CryptoPP::StringSink(strShares_Zero[i]));
//        channel_Zero = CryptoPP::WordToString<word32>(i);
//        strSinks_Zero[i]->Put((byte *) channel_Zero.data(), CHID_LENGTH);
//        channelSwitch_Zero->AddRoute(channel_Zero, *strSinks_Zero[i], DEFAULT_CHANNEL); //CryptoPP::BufferedTransformation::NULL_CHANNEL
//    }
//    source_Zero.PumpAll();
//
//    /*Transferring the shares to another aux array for feeding it to the encryption fuacntion*/
//
//    for(unsigned int j=0; j<shares; j++ )
//    {
//        string aux = strShares[j];
//        auto& str = aux;
//        string s(begin(str), end(str));
//        if(j == 4 ||j == 5 || j == 6 || j == 7 )
//        {
//            strShares_for_recover[j] = s;
//            strShares_for_recover[j][4] = '$';
//        }
//        else
//        {
//            strShares_for_recover[j] = s;
//        }
//    }
//
//    for(unsigned int j=0; j<shares; j++ )
//    {
//        string aux = strShares_Zero[j];
//        auto& str = aux;
//        string s(begin(str), end(str));
//        if(j == 4 ||j == 5 || j == 6 || j == 7 )
//        {
//            strShares_for_recover_zero[j] = s;
//            strShares_for_recover_zero[j][4] = '$';
//        }
//        else
//        {
//            strShares_for_recover_zero[j] = s;
//        }
//    }
//
//    int rsltRcVr;
//    vector<int> Valid_selected;
//    string plaintext_rcv;
//    string MainRecoverShare;
//    vector<int> v{0, 1, 2, 3, 4, 5, 6, 7};
//
//    double duration_cum = 0;
//
//
//    for (int j=0;j < 20; j++)
//    {
//
//        auto start = high_resolution_clock::now();
//        rsltRcVr = HamDistTwo::generatesubsets(strShares_for_recover, strShares_for_recover_zero,  EncrypteKey, MainRecoverShare,
//                                               plaintext_rcv, v,0,threshold, Valid_selected);
//        auto stop = high_resolution_clock::now();
//        assert(rsltRcVr !=1 );
//        auto duration = duration_cast<milliseconds>(stop - start);
//
//        duration_cum = duration_cum +  duration.count();
//    }
//
//
//
//    double ave_time  = duration_cum/20;
//    cout << ave_time << "\t";
//
//    std::ofstream SSdataL("SecretSharing.dat", std::ios_base::app | std::ios_base::out);
//    SSdataL << "1" << "\t" <<ave_time << "\n";
//
////    assert(rsltRcVr == 1);
//    cout << "end of the test\n";
//
//}
//
//TEST_CASE("Secret Sharing execition time, threshold  = 6")
//{
//
//    string b(AES::DEFAULT_KEYLENGTH, 0);
//    PRNG.GenerateBlock((byte *) b.data(), b.size());
//    string Zero_secret = "0000";
//    int threshold = 6;
//    string test  = "TESTTEST";
//    string EncrypteKey;
//    int shares = 8; //the value of _len = 8
//
//
//    string seed = CryptoPP::IntToString(time(NULL));
//    seed.resize(16, ' ');
//    CryptoPP::RandomPool rng;
//    rng.IncorporateEntropy((byte *)seed.data(), strlen(seed.data()));
//
//    CryptoPP::ChannelSwitch *channelSwitch;
//    channelSwitch = NULLPTR;
//    CryptoPP::ChannelSwitch *channelSwitch_Zero;
//    channelSwitch_Zero = NULLPTR;
//
//    PRNG.GenerateBlock((byte *) b.data(), b.size());
//    CryptoSymWrapperFunctions::Wrapper_AuthEncrypt(b, test, EncrypteKey);
//
//
//    CryptoPP::StringSource source(b, false,
//                                  new CryptoPP::SecretSharing(rng, threshold, shares,
//                                                              channelSwitch = new CryptoPP::ChannelSwitch, false));
//
//    CryptoPP::StringSource source_Zero(Zero_secret, false, new CryptoPP::SecretSharing(rng, threshold, shares,
//                                                                                       channelSwitch_Zero = new CryptoPP::ChannelSwitch,false)); //Genreating the shares for Zero: "0"
//
//    vector<string> strShares(shares);
//    vector<string> Plain_strShares(shares);
//    vector<string> strShares_for_recover(shares);
//    CryptoPP::vector_member_ptrs<CryptoPP::StringSink> strSinks(shares);
//    string channel;
//
//
//    vector<string> strShares_Zero(shares);
//    vector<string> Plain_strShares_Zero(shares);
//    vector<string> strShares_for_recover_zero(shares);
//    CryptoPP::vector_member_ptrs<CryptoPP::StringSink> strSinks_Zero(shares);
//    string channel_Zero;
//
//    const unsigned int CHID_LENGTH = 4;
//
//    // ********** Create Shares for the AES secret information "b".
//    for (unsigned int i = 0; i < shares; i++) {
//        strSinks[i].reset(new CryptoPP::StringSink(strShares[i]));
//        channel = CryptoPP::WordToString<word32>(i);
//        strSinks[i]->Put((byte *) channel.data(), CHID_LENGTH);
//        channelSwitch->AddRoute(channel, *strSinks[i],DEFAULT_CHANNEL  ); //CryptoPP::BufferedTransformation::NULL_CHANNEL
//    }
//    source.PumpAll();
//
//
//    // ********** Create and assigns the Shares for the zero part
//    for (unsigned int i = 0; i < shares; i++) {
//        strSinks_Zero[i].reset(new CryptoPP::StringSink(strShares_Zero[i]));
//        channel_Zero = CryptoPP::WordToString<word32>(i);
//        strSinks_Zero[i]->Put((byte *) channel_Zero.data(), CHID_LENGTH);
//        channelSwitch_Zero->AddRoute(channel_Zero, *strSinks_Zero[i], DEFAULT_CHANNEL); //CryptoPP::BufferedTransformation::NULL_CHANNEL
//    }
//    source_Zero.PumpAll();
//
//    /*Transferring the shares to another aux array for feeding it to the encryption fuacntion*/
//
//    for(unsigned int j=0; j<shares; j++ )
//    {
//        string aux = strShares[j];
//        auto& str = aux;
//        string s(begin(str), end(str));
//        if(j == 4 ||j == 5 || j == 6 || j == 7 )
//        {
//            strShares_for_recover[j] = s;
//            strShares_for_recover[j][4] = '$';
//        }
//        else
//        {
//            strShares_for_recover[j] = s;
//        }
//    }
//
//    for(unsigned int j=0; j<shares; j++ )
//    {
//        string aux = strShares_Zero[j];
//        auto& str = aux;
//        string s(begin(str), end(str));
//        if(j == 4 ||j == 5 || j == 6 || j == 7 )
//        {
//            strShares_for_recover_zero[j] = s;
//            strShares_for_recover_zero[j][4] = '$';
//        }
//        else
//        {
//            strShares_for_recover_zero[j] = s;
//        }
//    }
//
//    int rsltRcVr;
//    vector<int> Valid_selected;
//    string plaintext_rcv;
//    string MainRecoverShare;
//    vector<int> v{0, 1, 2, 3, 4, 5, 6, 7};
//
//    double duration_cum = 0;
//
//
//    for (int i=0;i < 20; i++)
//    {
//
//        auto start = high_resolution_clock::now();
//        rsltRcVr = HamDistTwo::generatesubsets(strShares_for_recover, strShares_for_recover_zero,  EncrypteKey, MainRecoverShare,
//                                               plaintext_rcv, v,0,threshold, Valid_selected);
//        auto stop = high_resolution_clock::now();
//        assert(rsltRcVr != 1);
//        auto duration = duration_cast<milliseconds>(stop - start);
//        duration_cum = duration_cum +  duration.count();
//    }
//    double ave_time  = duration_cum/20;
//    cout << ave_time << "\t";
//
//    std::ofstream SSdataL("SecretSharing.dat", std::ios_base::app | std::ios_base::out);
//    SSdataL << "2" << "\t" <<ave_time << "\n";
//
////    assert(rsltRcVr == 1);
//    cout << "end of the test\n";
//
//}
//
//TEST_CASE("Secret Sharing execition time, threshold  = 5")
//{
//
//    string b(AES::DEFAULT_KEYLENGTH, 0);
//    PRNG.GenerateBlock((byte *) b.data(), b.size());
//    string Zero_secret = "0000";
//    int threshold = 5;
//    string test  = "TESTTEST";
//    string EncrypteKey;
//    int shares = 8; //the value of _len = 8
//
//
//    string seed = CryptoPP::IntToString(time(NULL));
//    seed.resize(16, ' ');
//    CryptoPP::RandomPool rng;
//    rng.IncorporateEntropy((byte *)seed.data(), strlen(seed.data()));
//
//    CryptoPP::ChannelSwitch *channelSwitch;
//    channelSwitch = NULLPTR;
//    CryptoPP::ChannelSwitch *channelSwitch_Zero;
//    channelSwitch_Zero = NULLPTR;
//
//    PRNG.GenerateBlock((byte *) b.data(), b.size());
//    CryptoSymWrapperFunctions::Wrapper_AuthEncrypt(b, test, EncrypteKey);
//
//
//    CryptoPP::StringSource source(b, false,
//                                  new CryptoPP::SecretSharing(rng, threshold, shares,
//                                                              channelSwitch = new CryptoPP::ChannelSwitch, false));
//
//    CryptoPP::StringSource source_Zero(Zero_secret, false, new CryptoPP::SecretSharing(rng, threshold, shares,
//                                                                                       channelSwitch_Zero = new CryptoPP::ChannelSwitch,false)); //Genreating the shares for Zero: "0"
//
//    vector<string> strShares(shares);
//    vector<string> Plain_strShares(shares);
//    vector<string> strShares_for_recover(shares);
//    CryptoPP::vector_member_ptrs<CryptoPP::StringSink> strSinks(shares);
//    string channel;
//
//
//    vector<string> strShares_Zero(shares);
//    vector<string> Plain_strShares_Zero(shares);
//    vector<string> strShares_for_recover_zero(shares);
//    CryptoPP::vector_member_ptrs<CryptoPP::StringSink> strSinks_Zero(shares);
//    string channel_Zero;
//
//    const unsigned int CHID_LENGTH = 4;
//
//    // ********** Create Shares for the AES secret information "b".
//    for (unsigned int i = 0; i < shares; i++) {
//        strSinks[i].reset(new CryptoPP::StringSink(strShares[i]));
//        channel = CryptoPP::WordToString<word32>(i);
//        strSinks[i]->Put((byte *) channel.data(), CHID_LENGTH);
//        channelSwitch->AddRoute(channel, *strSinks[i],DEFAULT_CHANNEL  ); //CryptoPP::BufferedTransformation::NULL_CHANNEL
//    }
//    source.PumpAll();
//
//
//    // ********** Create and assigns the Shares for the zero part
//    for (unsigned int i = 0; i < shares; i++) {
//        strSinks_Zero[i].reset(new CryptoPP::StringSink(strShares_Zero[i]));
//        channel_Zero = CryptoPP::WordToString<word32>(i);
//        strSinks_Zero[i]->Put((byte *) channel_Zero.data(), CHID_LENGTH);
//        channelSwitch_Zero->AddRoute(channel_Zero, *strSinks_Zero[i], DEFAULT_CHANNEL); //CryptoPP::BufferedTransformation::NULL_CHANNEL
//    }
//    source_Zero.PumpAll();
//
//    /*Transferring the shares to another aux array for feeding it to the encryption fuacntion*/
//
//    for(unsigned int j=0; j<shares; j++ )
//    {
//        string aux = strShares[j];
//        auto& str = aux;
//        string s(begin(str), end(str));
//        if(j == 4 ||j == 5 || j == 6 || j == 7 )
//        {
//            strShares_for_recover[j] = s;
//            strShares_for_recover[j][4] = '$';
//        }
//        else
//        {
//            strShares_for_recover[j] = s;
//        }
//    }
//
//    for(unsigned int j=0; j<shares; j++ )
//    {
//        string aux = strShares_Zero[j];
//        auto& str = aux;
//        string s(begin(str), end(str));
//        if(j == 4 ||j == 5 || j == 6 || j == 7 )
//        {
//            strShares_for_recover_zero[j] = s;
//            strShares_for_recover_zero[j][4] = '$';
//        }
//        else
//        {
//            strShares_for_recover_zero[j] = s;
//        }
//    }
//
//    int rsltRcVr;
//    vector<int> Valid_selected;
//    string plaintext_rcv;
//    string MainRecoverShare;
//    vector<int> v{0, 1, 2, 3, 4, 5, 6, 7};
//
//    double duration_cum = 0;
//
//
//    for (int i=0; i < 20; i++)
//    {
//
//        auto start = high_resolution_clock::now();
//        rsltRcVr = HamDistTwo::generatesubsets(strShares_for_recover, strShares_for_recover_zero,  EncrypteKey, MainRecoverShare,
//                                               plaintext_rcv, v,0,threshold, Valid_selected);
//        auto stop = high_resolution_clock::now();
//        assert(rsltRcVr != 1);
//        auto duration = duration_cast<milliseconds>(stop - start);
//        duration_cum = duration_cum +  duration.count();
//    }
//    double ave_time  = duration_cum/20;
//    cout << ave_time << "\t";
//
//    std::ofstream SSdataL("SecretSharing.dat", std::ios_base::app | std::ios_base::out);
//    SSdataL << "3" << "\t" <<ave_time << "\n";
//
////    assert(rsltRcVr == 1);
//    cout << "end of the test\n";
//
//}
//
//TEST_CASE("Secret Sharing execition time, threshold  = 4")
//{
//
//    string b(AES::DEFAULT_KEYLENGTH, 0);
//    PRNG.GenerateBlock((byte *) b.data(), b.size());
//    string Zero_secret = "0000";
//    int threshold = 4;
//    string test  = "TESTTEST";
//    string EncrypteKey;
//    int shares = 8; //the value of _len = 8
//
//
//    string seed = CryptoPP::IntToString(time(NULL));
//    seed.resize(16, ' ');
//    CryptoPP::RandomPool rng;
//    rng.IncorporateEntropy((byte *)seed.data(), strlen(seed.data()));
//
//    CryptoPP::ChannelSwitch *channelSwitch;
//    channelSwitch = NULLPTR;
//    CryptoPP::ChannelSwitch *channelSwitch_Zero;
//    channelSwitch_Zero = NULLPTR;
//
//    PRNG.GenerateBlock((byte *) b.data(), b.size());
//    CryptoSymWrapperFunctions::Wrapper_AuthEncrypt(b, test, EncrypteKey);
//
//
//    CryptoPP::StringSource source(b, false,
//                                  new CryptoPP::SecretSharing(rng, threshold, shares,
//                                                              channelSwitch = new CryptoPP::ChannelSwitch, false));
//
//    CryptoPP::StringSource source_Zero(Zero_secret, false, new CryptoPP::SecretSharing(rng, threshold, shares,
//                                                                                       channelSwitch_Zero = new CryptoPP::ChannelSwitch,false)); //Genreating the shares for Zero: "0"
//
//    vector<string> strShares(shares);
//    vector<string> Plain_strShares(shares);
//    vector<string> strShares_for_recover(shares);
//    CryptoPP::vector_member_ptrs<CryptoPP::StringSink> strSinks(shares);
//    string channel;
//
//
//    vector<string> strShares_Zero(shares);
//    vector<string> Plain_strShares_Zero(shares);
//    vector<string> strShares_for_recover_zero(shares);
//    CryptoPP::vector_member_ptrs<CryptoPP::StringSink> strSinks_Zero(shares);
//    string channel_Zero;
//
//    const unsigned int CHID_LENGTH = 4;
//
//    // ********** Create Shares for the AES secret information "b".
//    for (unsigned int i = 0; i < shares; i++) {
//        strSinks[i].reset(new CryptoPP::StringSink(strShares[i]));
//        channel = CryptoPP::WordToString<word32>(i);
//        strSinks[i]->Put((byte *) channel.data(), CHID_LENGTH);
//        channelSwitch->AddRoute(channel, *strSinks[i],DEFAULT_CHANNEL  ); //CryptoPP::BufferedTransformation::NULL_CHANNEL
//    }
//    source.PumpAll();
//
//
//    // ********** Create and assigns the Shares for the zero part
//    for (unsigned int i = 0; i < shares; i++) {
//        strSinks_Zero[i].reset(new CryptoPP::StringSink(strShares_Zero[i]));
//        channel_Zero = CryptoPP::WordToString<word32>(i);
//        strSinks_Zero[i]->Put((byte *) channel_Zero.data(), CHID_LENGTH);
//        channelSwitch_Zero->AddRoute(channel_Zero, *strSinks_Zero[i], DEFAULT_CHANNEL); //CryptoPP::BufferedTransformation::NULL_CHANNEL
//    }
//    source_Zero.PumpAll();
//
//    /*Transferring the shares to another aux array for feeding it to the encryption fuacntion*/
//
//    for(unsigned int j=0; j<shares; j++ )
//    {
//        string aux = strShares[j];
//        auto& str = aux;
//        string s(begin(str), end(str));
//        if(j == 4 ||j == 5 || j == 6 || j == 7 || j == 3)
//        {
//            strShares_for_recover[j] = s;
//            strShares_for_recover[j][4] = '$';
//        }
//        else
//        {
//            strShares_for_recover[j] = s;
//        }
//    }
//
//    for(unsigned int j=0; j<shares; j++ )
//    {
//        string aux = strShares_Zero[j];
//        auto& str = aux;
//        string s(begin(str), end(str));
//        if(j == 4 ||j == 5 || j == 6 || j == 7 || j == 3 )
//        {
//            strShares_for_recover_zero[j] = s;
//            strShares_for_recover_zero[j][4] = '$';
//        }
//        else
//        {
//            strShares_for_recover_zero[j] = s;
//        }
//    }
//
//    int rsltRcVr;
//    vector<int> Valid_selected;
//    string plaintext_rcv;
//    string MainRecoverShare;
//    vector<int> v{0, 1, 2, 3, 4, 5, 6, 7};
//
//    double duration_cum = 0;
//
//
//    for (int i=0;  i < 20; i++)
//    {
//
//        auto start = high_resolution_clock::now();
//        rsltRcVr = HamDistTwo::generatesubsets(strShares_for_recover, strShares_for_recover_zero,  EncrypteKey, MainRecoverShare,
//                                               plaintext_rcv, v,0,threshold, Valid_selected);
//        auto stop = high_resolution_clock::now();
//        assert(rsltRcVr != 1);
//        auto duration = duration_cast<milliseconds>(stop - start);
//        duration_cum = duration_cum +  duration.count();
//    }
//    double ave_time  = duration_cum/20;
//    cout << ave_time <<"\t";
//
//    std::ofstream SSdataL("SecretSharing.dat", std::ios_base::app | std::ios_base::out);
//    SSdataL << "4" << "\t" <<ave_time << "\n";
//
////    assert(rsltRcVr == 1);
//    cout << "end of the test\n";
//
//}
//



//TEST_CASE("Paillier Wrapper funcitions")
//{
//
////    PwPkCrypto pkobj;
////    pkobj.Paill_pk_init(1024);
////
////    string msg = "Sal klsdsgdffdg";
////
////    vector<paillier_ciphertext_t*> Vctx(3);
////    char*  Bctx_Char = (char*) malloc (sizeof(size_t) +  PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2);//TODO: I may need to change the allocated size for this part.
////
////    Bctx_Char = PaillerWrapperFunctions::Enc_Byte_By_Byte(msg, pkobj._ppk);
////
////    Vctx = PaillerWrapperFunctions::Pail_Parse_Ctx_size(pkobj._ppk, Bctx_Char );
////    cout << "the resulting message is: ";
////    string resutl;
////    char res_char [msg.size()];
////    char *ss;
////    for (int i= 0; i< msg.size(); i++) {
////        paillier_plaintext_t *dec;
////        dec = paillier_dec(NULL, pkobj._ppk, pkobj._psk, Vctx[i]);
////
////        ss = (char *) paillier_plaintext_to_bytes(1, dec);
////        resutl +=  ss;
////    }
////    cout << resutl << "\n";
////    free(Bctx_Char);
//}
//



TEST_CASE("Conditional Encryption: Hamming Distance at most One [Threshold len-1, len =8] predicate")                                                                       
{
    PwPkCrypto pkobj;
    pkobj.Paill_pk_init(1024);
    int Num_tests = 10;
    size_t _len = 8;

    int Threshold = _len - 1;

    string msg = "Test";


    string msg_pad = CryptoSymWrapperFunctions::Wrapper_pad(msg, _len);
    int sizechar = sizeof(size_t);

    size_t TradCtxSize = 2 * sizeof(size_t) + _len *  PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2;
    size_t CondCtxSize = 3 * sizeof(size_t) + (sizeof(char) * 24) + (_len *  256);

    double duration_CondEnc_HD2_Sum = 0;
    double duration_Enc_HD2_Sum = 0;
    double duration_CondDec_HD2_Sum = 0;

    ofstream CondEncHD2;
    CondEncHD2.open("CondEnc_HD_T1_L8.txt");
    CondEncHD2 << "The predicate is Hamming distance at most One [2 errors as wors case]******************\n \n ";

    for(int T = 0; T< Num_tests; T++) {
        char HD2_Char_ORigCTx [2 * sizeof(size_t) + _len *  PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2];
        char HD2_ctx_typo_Bytes[3 * sizeof(size_t) + (sizeof(char) * 24) + (_len *  256)];
        string typo =msg;
        string payload;

        /*Randomly making typo and the payload*/
        unsigned seed= time(0);
        int NumOfErrs = 0;
        char err1, err2, err3;
        srand(seed);
        NumOfErrs = 2;
//        NumOfErrs =rand() % 4;
        if (NumOfErrs == 1)
        {
            err1 = 32 + (rand() % 95);
            int ErrLction;
            ErrLction = rand() % (msg.size());
            typo[ErrLction] = err1;
        } else if (NumOfErrs == 2)
        {
            err1 = 32 + (rand() % 95);
            err2 = 32 + (rand() % 95);
            int ErrLction1, ErrLction2;
            ErrLction1 = rand() % msg.size();
            ErrLction2 = rand() % msg.size();
            typo[ErrLction1] = err1;
            typo[ErrLction2] = err2;
        } else if (NumOfErrs == 3)
        {
            err1 = 32 + (rand() % 95);
            err2 = 32 + (rand() % 95);
            err3 = 32 + (rand() % 95);
            int ErrLction1, ErrLction2, ErrLction3;
            ErrLction1 = rand() % msg.size();
            ErrLction2 = rand() % msg.size();
            ErrLction3 = rand() % msg.size();
            typo[ErrLction1] = err1;
            typo[ErrLction2] = err2;
            typo[ErrLction3] = err3;
        }
        payload = typo;
        string pad_typo = CryptoSymWrapperFunctions::Wrapper_pad(typo, _len);

        /* ============ */

        auto start_Enc_HD2 = high_resolution_clock::now();
        int tradEncRslt =0;
        tradEncRslt = HamDistTwo::Enc(pkobj._ppk, msg_pad, HD2_Char_ORigCTx);
        auto stop_Enc_HD2 = high_resolution_clock::now();
        auto duration_Enc_HD2 = duration_cast<milliseconds>(stop_Enc_HD2 - start_Enc_HD2);

        auto start_CondEnc_HD2 = high_resolution_clock::now();
        auto ctx_final = HamDistTwo::CondEnc(pkobj._ppk, HD2_Char_ORigCTx, typo, payload,_len, Threshold, HD2_ctx_typo_Bytes);

        auto stop_CondEnc_HD2 = high_resolution_clock::now();
        auto duration_CondEnc_HD2 = duration_cast<milliseconds>(stop_CondEnc_HD2 - start_CondEnc_HD2);

        auto start_CondDec_HD2 = high_resolution_clock::now();
        string recovered_hd2Bytes;
        int CondDecOut  = 0;

        CondDecOut = HamDistTwo::CondDec(pkobj._ppk, HD2_ctx_typo_Bytes, pkobj._psk, Threshold, recovered_hd2Bytes, _len, 28);
        auto stop_CondDec_HD2 = high_resolution_clock::now();
        auto duration_CondDec_HD2 = duration_cast<milliseconds>(stop_CondDec_HD2 - start_CondDec_HD2);


        CondEncHD2 << "Enc.Time, CondEnc.Time, Cond.Dec.Time, Ctx.Size, CondCtx.Size, CondDecRslt: (" <<
                   duration_Enc_HD2.count()
                   << ", " << duration_CondEnc_HD2.count()
                   << ", " << duration_CondDec_HD2.count()
                   << ", " << TradCtxSize
                   << ", " << CondCtxSize
                   << ", " << CondDecOut << " )\n";

        duration_Enc_HD2_Sum =  duration_Enc_HD2_Sum + duration_Enc_HD2.count();
        duration_CondEnc_HD2_Sum =  duration_CondEnc_HD2_Sum + duration_CondEnc_HD2.count();
        duration_CondDec_HD2_Sum =  duration_CondDec_HD2_Sum + duration_CondDec_HD2.count();

    }

    std::ofstream HDdataL("HDdataL_T1.dat", std::ios_base::app | std::ios_base::out);
    std::ofstream HDdataT("HDdataL8_T.dat", std::ios_base::app | std::ios_base::out);

    HDdataL << "T\tL\t" << "Enc\tCondEnc\tCondDec\tCtxtSize\tCondCtxtSize\n";
    HDdataT << "T\tL\t" << "Enc\tCondEnc\tCondDec\tCtxtSize\tCondCtxtSize\n";
    int MaxDist  = _len - Threshold;

    HDdataT << MaxDist << "\t"<< _len << "\t" << duration_Enc_HD2_Sum / Num_tests << "\t"
            << duration_CondEnc_HD2_Sum / Num_tests << "\t"
            << duration_CondDec_HD2_Sum / Num_tests << "\t"
            << CondCtxSize << "\t"
            << TradCtxSize << "\n";



    HDdataL << MaxDist << "\t"<< _len << "\t" << duration_Enc_HD2_Sum / Num_tests << "\t"
            << duration_CondEnc_HD2_Sum / Num_tests << "\t"
            << duration_CondDec_HD2_Sum / Num_tests << "\t"
            << CondCtxSize << "\t"
            << TradCtxSize << "\n";


    CondEncHD2 << "Average Enc, CondEnc, CondDec, CtxtSize: " <<
               duration_Enc_HD2_Sum / Num_tests
               << ", " <<  duration_CondEnc_HD2_Sum / Num_tests
               << ", " <<  duration_CondDec_HD2_Sum / Num_tests << " \n";


    CondEncHD2.close();
    paillier_freepubkey(pkobj._ppk);
    paillier_freeprvkey(pkobj._psk);
    cout << "Hamming Distant  at most one [Threshold =_len -1, _len = 8] is finished \n";
}

TEST_CASE("Conditional Encryption: Hamming Distance at most One [Threshold len-1, len =16] predicate")
{
    PwPkCrypto pkobj;
    pkobj.Paill_pk_init(1024);
    int Num_tests = 5;
    size_t _len = 16;
    int Threshold = _len - 1;

    string msg = "Test";


    string msg_pad = CryptoSymWrapperFunctions::Wrapper_pad(msg, _len);
    int sizechar = sizeof(size_t);
    size_t TradCtxSize = 2 * sizeof(size_t) + _len *  PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2;
    size_t CondCtxSize = 3 * sizeof(size_t) + (sizeof(char) * 24) + (_len *  256);

    double duration_CondEnc_HD2_Sum = 0;
    double duration_Enc_HD2_Sum = 0;
    double duration_CondDec_HD2_Sum = 0;

    ofstream CondEncHD2;
    CondEncHD2.open("CondEncHDAtmostOneLen16.txt");
    CondEncHD2 << "The predicate is Hamming distance at most two [3 errors as wors case]******************\n \n ";

    for(int T = 0; T< Num_tests; T++) {
        char HD2_Char_ORigCTx [2 * sizeof(size_t) + _len *  PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2];
        char HD2_ctx_typo_Bytes[3 * sizeof(size_t) + (sizeof(char) * 24) + (_len *  256)];
        string typo =msg;
        string payload;

        /*Randomly making typo and the payload*/
        unsigned seed= time(0);
        int NumOfErrs = 0;
        char err1, err2, err3;
        srand(seed);
        NumOfErrs = 2;
//        NumOfErrs =rand() % 4;
        if (NumOfErrs == 1)
        {
            err1 = 32 + (rand() % 95);
            int ErrLction;
            ErrLction = rand() % (msg.size());
            typo[ErrLction] = err1;
        } else if (NumOfErrs == 2)
        {
            err1 = 32 + (rand() % 95);
            err2 = 32 + (rand() % 95);
            int ErrLction1, ErrLction2;
            ErrLction1 = rand() % msg.size();
            ErrLction2 = rand() % msg.size();
            typo[ErrLction1] = err1;
            typo[ErrLction2] = err2;
        } else if (NumOfErrs == 3)
        {
            err1 = 32 + (rand() % 95);
            err2 = 32 + (rand() % 95);
            err3 = 32 + (rand() % 95);
            int ErrLction1, ErrLction2, ErrLction3;
            ErrLction1 = rand() % msg.size();
            ErrLction2 = rand() % msg.size();
            ErrLction3 = rand() % msg.size();
            typo[ErrLction1] = err1;
            typo[ErrLction2] = err2;
            typo[ErrLction3] = err3;
        }
        payload = typo;
        string pad_typo = CryptoSymWrapperFunctions::Wrapper_pad(typo, _len);


        /* ============ */

        auto start_Enc_HD2 = high_resolution_clock::now();
        int tradEncRslt =0;
        tradEncRslt = HamDistTwo::Enc(pkobj._ppk, msg_pad, HD2_Char_ORigCTx);
        auto stop_Enc_HD2 = high_resolution_clock::now();
        auto duration_Enc_HD2 = duration_cast<milliseconds>(stop_Enc_HD2 - start_Enc_HD2);

        auto start_CondEnc_HD2 = high_resolution_clock::now();
//        char* CondEncRst = new char[3 * sizeof(size_t) + (sizeof(char) * 24) + (32 *  256) + 1];
//        memset(HD2_ctx_typo_Bytes, '\0', CondCtxSize);
        auto ctx_final = HamDistTwo::CondEnc(pkobj._ppk, HD2_Char_ORigCTx, typo, payload,_len, Threshold, HD2_ctx_typo_Bytes);

        auto stop_CondEnc_HD2 = high_resolution_clock::now();
        auto duration_CondEnc_HD2 = duration_cast<milliseconds>(stop_CondEnc_HD2 - start_CondEnc_HD2);

        auto start_CondDec_HD2 = high_resolution_clock::now();
        string recovered_hd2Bytes;
        int CondDecOut  = 0;
        CondDecOut = HamDistTwo::CondDec(pkobj._ppk, HD2_ctx_typo_Bytes, pkobj._psk, Threshold, recovered_hd2Bytes, _len, 28);

        auto stop_CondDec_HD2 = high_resolution_clock::now();
        auto duration_CondDec_HD2 = duration_cast<milliseconds>(stop_CondDec_HD2 - start_CondDec_HD2);

        CondEncHD2 << "Enc.Time, CondEnc.Time, Cond.Dec.Time, Ctx.Size, CondCtx.Size, CondDecRslt: (" <<
                   duration_Enc_HD2.count()
                   << ", " << duration_CondEnc_HD2.count()
                   << ", " << duration_CondDec_HD2.count()
                   << ", " << TradCtxSize
                   << ", " << CondCtxSize
                   << ", " << CondDecOut << " )\n";

        duration_Enc_HD2_Sum =  duration_Enc_HD2_Sum + duration_Enc_HD2.count();
        duration_CondEnc_HD2_Sum =  duration_CondEnc_HD2_Sum + duration_CondEnc_HD2.count();
        duration_CondDec_HD2_Sum =  duration_CondDec_HD2_Sum + duration_CondDec_HD2.count();

    }

    std::ofstream HDdataL("HDdataL_T1.dat", std::ios_base::app | std::ios_base::out);
    std::ofstream HDdataT("HDdataL16_T.dat", std::ios_base::app | std::ios_base::out);

    HDdataT << "T\tL\t" << "Enc\tCondEnc\tCondDec\tCondCtxtSize\tCondCtxtSize\n";
    int MaxDist  = _len - Threshold;

    HDdataT << MaxDist << "\t"<< _len << "\t" << duration_Enc_HD2_Sum / Num_tests << "\t"
            << duration_CondEnc_HD2_Sum / Num_tests << "\t"
            << duration_CondDec_HD2_Sum / Num_tests << "\t"
            << CondCtxSize << "\t"
            << TradCtxSize << "\n";



    HDdataL << MaxDist << "\t"<< _len << "\t" << duration_Enc_HD2_Sum / Num_tests << "\t"
            << duration_CondEnc_HD2_Sum / Num_tests << "\t"
            << duration_CondDec_HD2_Sum / Num_tests << "\t"
            << CondCtxSize << "\t"
            << TradCtxSize << "\n";

    CondEncHD2 << "Average Enc, CondEnc, CondDec, CtxtSize: " <<
               duration_Enc_HD2_Sum / Num_tests
               << ", " <<  duration_CondEnc_HD2_Sum / Num_tests
               << ", " <<  duration_CondDec_HD2_Sum / Num_tests << ") \n";

    CondEncHD2.close();
    paillier_freepubkey(pkobj._ppk);
    paillier_freeprvkey(pkobj._psk);
    cout << "Hamming Distant  at most one [Threshold =_len -1, _len = 16] is finished \n";
}

TEST_CASE("Conditional Encryption: Hamming Distance at most One [Threshold len-1, len =32 (effect of _len)] predicate")
{
    PwPkCrypto pkobj;
    pkobj.Paill_pk_init(1024);
    int Num_tests = 5;
    size_t _len = 32;
    int Threshold = _len - 1;

    string msg = "Test";


    string msg_pad = CryptoSymWrapperFunctions::Wrapper_pad(msg, _len);
    int sizechar = sizeof(size_t);

    size_t TradCtxSize = 2 * sizeof(size_t) + _len *  PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2;
    size_t CondCtxSize = 3 * sizeof(size_t) + (sizeof(char) * 24) + (_len *  256);

    double duration_CondEnc_HD2_Sum = 0;
    double duration_Enc_HD2_Sum = 0;
    double duration_CondDec_HD2_Sum = 0;

    ofstream CondEncHD2;
    CondEncHD2.open("CondEncHDAtmostOneLen32.txt");
    CondEncHD2 << "The predicate is Hamming distance at most two [3 errors as wors case]******************\n \n ";

    for(int T = 0; T< Num_tests; T++) {
        char HD2_Char_ORigCTx [2 * sizeof(size_t) + _len *  PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2];
        char HD2_ctx_typo_Bytes[3 * sizeof(size_t) + (sizeof(char) * 24) + (_len *  256)];
        string typo =msg;
        string payload;

        /*Randomly making typo and the payload*/
        unsigned seed= time(0);
        int NumOfErrs = 0;
        char err1, err2, err3;
        srand(seed);
        NumOfErrs = 2;
//        NumOfErrs =rand() % 4;
        if (NumOfErrs == 1)
        {
            err1 = 32 + (rand() % 95);
            int ErrLction;
            ErrLction = rand() % (msg.size());
            typo[ErrLction] = err1;
        } else if (NumOfErrs == 2)
        {
            err1 = 32 + (rand() % 95);
            err2 = 32 + (rand() % 95);
            int ErrLction1, ErrLction2;
            ErrLction1 = rand() % msg.size();
            ErrLction2 = rand() % msg.size();
            typo[ErrLction1] = err1;
            typo[ErrLction2] = err2;
        } else if (NumOfErrs == 3)
        {
            err1 = 32 + (rand() % 95);
            err2 = 32 + (rand() % 95);
            err3 = 32 + (rand() % 95);
            int ErrLction1, ErrLction2, ErrLction3;
            ErrLction1 = rand() % msg.size();
            ErrLction2 = rand() % msg.size();
            ErrLction3 = rand() % msg.size();
            typo[ErrLction1] = err1;
            typo[ErrLction2] = err2;
            typo[ErrLction3] = err3;
        }
        payload = typo;
        string pad_typo = CryptoSymWrapperFunctions::Wrapper_pad(typo, _len);


        /* ============ */

        auto start_Enc_HD2 = high_resolution_clock::now();
        int tradEncRslt =0;
        tradEncRslt = HamDistTwo::Enc(pkobj._ppk, msg_pad, HD2_Char_ORigCTx);
        auto stop_Enc_HD2 = high_resolution_clock::now();
        auto duration_Enc_HD2 = duration_cast<milliseconds>(stop_Enc_HD2 - start_Enc_HD2);

        auto start_CondEnc_HD2 = high_resolution_clock::now();

        auto ctx_final = HamDistTwo::CondEnc(pkobj._ppk, HD2_Char_ORigCTx, typo, payload,_len, Threshold, HD2_ctx_typo_Bytes);

        auto stop_CondEnc_HD2 = high_resolution_clock::now();
        auto duration_CondEnc_HD2 = duration_cast<milliseconds>(stop_CondEnc_HD2 - start_CondEnc_HD2);

        auto start_CondDec_HD2 = high_resolution_clock::now();
        string recovered_hd2Bytes;
        int CondDecOut  = 0;

        CondDecOut = HamDistTwo::CondDec(pkobj._ppk, HD2_ctx_typo_Bytes, pkobj._psk, Threshold, recovered_hd2Bytes, _len, 28);
        auto stop_CondDec_HD2 = high_resolution_clock::now();
        auto duration_CondDec_HD2 = duration_cast<milliseconds>(stop_CondDec_HD2 - start_CondDec_HD2);

        CondEncHD2 << "Enc.Time, CondEnc.Time, Cond.Dec.Time, Ctx.Size, CondCtx.Size, CondDecRslt: (" <<
                   duration_Enc_HD2.count()
                   << ", " << duration_CondEnc_HD2.count()
                   << ", " << duration_CondDec_HD2.count()
                   << ", " << TradCtxSize
                   << ", " << CondCtxSize
                   << ", " << CondDecOut << " )\n";

        duration_Enc_HD2_Sum =  duration_Enc_HD2_Sum + duration_Enc_HD2.count();
        duration_CondEnc_HD2_Sum =  duration_CondEnc_HD2_Sum + duration_CondEnc_HD2.count();
        duration_CondDec_HD2_Sum =  duration_CondDec_HD2_Sum + duration_CondDec_HD2.count();

    }

    std::ofstream HDdataL("HDdataL_T1.dat", std::ios_base::app | std::ios_base::out);
    std::ofstream HDdataT("HDdataL32_T.dat", std::ios_base::app | std::ios_base::out);

    HDdataT << "T\tL\t" << "Enc\tCondEnc\tCondDec\tCondCtxtSize\tCondCtxtSize\n";
    int MaxDist  = _len - Threshold;

    HDdataT << MaxDist << "\t"<< _len << "\t" << duration_Enc_HD2_Sum / Num_tests << "\t"
            << duration_CondEnc_HD2_Sum / Num_tests << "\t"
            << duration_CondDec_HD2_Sum / Num_tests << "\t"
            << CondCtxSize << "\t"
            << TradCtxSize << "\n";



    HDdataL << MaxDist << "\t"<< _len << "\t" << duration_Enc_HD2_Sum / Num_tests << "\t"
            << duration_CondEnc_HD2_Sum / Num_tests << "\t"
            << duration_CondDec_HD2_Sum / Num_tests << "\t"
            << CondCtxSize << "\t"
            << TradCtxSize << "\n";

    CondEncHD2 << "Average Enc, CondEnc, CondDec, CtxtSize: " <<
               duration_Enc_HD2_Sum / Num_tests
               << ", " <<  duration_CondEnc_HD2_Sum / Num_tests
               << ", " <<  duration_CondDec_HD2_Sum / Num_tests << ") \n";

    CondEncHD2.close();
    paillier_freepubkey(pkobj._ppk);
    paillier_freeprvkey(pkobj._psk);
    cout << "Hamming Distant  at most two [Threshold =_len -1, _len = 32] is finished \n";
}

TEST_CASE("Conditional Encryption: Hamming Distance at most One [Threshold len-1, len =64] predicate")
{
    PwPkCrypto pkobj;
    pkobj.Paill_pk_init(1024);
    int Num_tests = 5;
    size_t _len = 64;
    int Threshold = _len - 1;

    string msg = "Test";


    string msg_pad = CryptoSymWrapperFunctions::Wrapper_pad(msg, _len);
    int sizechar = sizeof(size_t);

    size_t TradCtxSize = 2 * sizeof(size_t) + _len *  PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2;
    size_t CondCtxSize = 3 * sizeof(size_t) + (sizeof(char) * 24) + (_len *  256);

    double duration_CondEnc_HD2_Sum = 0;
    double duration_Enc_HD2_Sum = 0;
    double duration_CondDec_HD2_Sum = 0;

    ofstream CondEncHD2;
    CondEncHD2.open("CondEncHDAtmostOneLen64.txt");
    CondEncHD2 << "The predicate is Hamming distance at most two [3 errors as wors case]******************\n \n ";

    for(int T = 0; T< Num_tests; T++) {
        char HD2_Char_ORigCTx [2 * sizeof(size_t) + _len *  PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2];
        char HD2_ctx_typo_Bytes[3 * sizeof(size_t) + (sizeof(char) * 24) + (_len *  256)];
        string typo =msg;
        string payload;

        /*Randomly making typo and the payload*/
        unsigned seed= time(0);
        int NumOfErrs = 0;
        char err1, err2, err3;
        srand(seed);
        NumOfErrs = 2;
//        NumOfErrs =rand() % 4;
        if (NumOfErrs == 1)
        {
            err1 = 32 + (rand() % 95);
            int ErrLction;
            ErrLction = rand() % (msg.size());
            typo[ErrLction] = err1;
        } else if (NumOfErrs == 2)
        {
            err1 = 32 + (rand() % 95);
            err2 = 32 + (rand() % 95);
            int ErrLction1, ErrLction2;
            ErrLction1 = rand() % msg.size();
            ErrLction2 = rand() % msg.size();
            typo[ErrLction1] = err1;
            typo[ErrLction2] = err2;
        } else if (NumOfErrs == 3)
        {
            err1 = 32 + (rand() % 95);
            err2 = 32 + (rand() % 95);
            err3 = 32 + (rand() % 95);
            int ErrLction1, ErrLction2, ErrLction3;
            ErrLction1 = rand() % msg.size();
            ErrLction2 = rand() % msg.size();
            ErrLction3 = rand() % msg.size();
            typo[ErrLction1] = err1;
            typo[ErrLction2] = err2;
            typo[ErrLction3] = err3;
        }
        payload = typo;
        string pad_typo = CryptoSymWrapperFunctions::Wrapper_pad(typo, _len);


        /* ============ */

        auto start_Enc_HD2 = high_resolution_clock::now();
        int tradEncRslt =0;
        tradEncRslt = HamDistTwo::Enc(pkobj._ppk, msg_pad, HD2_Char_ORigCTx);
        auto stop_Enc_HD2 = high_resolution_clock::now();
        auto duration_Enc_HD2 = duration_cast<milliseconds>(stop_Enc_HD2 - start_Enc_HD2);

        auto start_CondEnc_HD2 = high_resolution_clock::now();

        auto ctx_final = HamDistTwo::CondEnc(pkobj._ppk, HD2_Char_ORigCTx, typo, payload,_len, Threshold, HD2_ctx_typo_Bytes);

        auto stop_CondEnc_HD2 = high_resolution_clock::now();
        auto duration_CondEnc_HD2 = duration_cast<milliseconds>(stop_CondEnc_HD2 - start_CondEnc_HD2);

        auto start_CondDec_HD2 = high_resolution_clock::now();
        string recovered_hd2Bytes;
        int CondDecOut  = 0;
//        while (CondDecOut != 1)
//        {
        CondDecOut = HamDistTwo::CondDec(pkobj._ppk, HD2_ctx_typo_Bytes, pkobj._psk, Threshold, recovered_hd2Bytes, _len, 28);
//        }
        auto stop_CondDec_HD2 = high_resolution_clock::now();
        auto duration_CondDec_HD2 = duration_cast<milliseconds>(stop_CondDec_HD2 - start_CondDec_HD2);

        CondEncHD2 << "Enc.Time, CondEnc.Time, Cond.Dec.Time, Ctx.Size, CondCtx.Size, CondDecRslt: (" <<
                   duration_Enc_HD2.count()
                   << ", " << duration_CondEnc_HD2.count()
                   << ", " << duration_CondDec_HD2.count()
                   << ", " << TradCtxSize
                   << ", " << CondCtxSize
                   << ", " << CondDecOut << " )\n";

        duration_Enc_HD2_Sum =  duration_Enc_HD2_Sum + duration_Enc_HD2.count();
        duration_CondEnc_HD2_Sum =  duration_CondEnc_HD2_Sum + duration_CondEnc_HD2.count();
        duration_CondDec_HD2_Sum =  duration_CondDec_HD2_Sum + duration_CondDec_HD2.count();

    }

    std::ofstream HDdataL("HDdataL_T1.dat", std::ios_base::app | std::ios_base::out);
    std::ofstream HDdataT("HDdataL64_T.dat", std::ios_base::app | std::ios_base::out);

    HDdataT << "T\tL\t" << "Enc\tCondEnc\tCondDec\tCondCtxtSize\tCondCtxtSize\n";
    int MaxDist  = _len - Threshold;

    HDdataT << MaxDist << "\t"<< _len << "\t" << duration_Enc_HD2_Sum / Num_tests << "\t"
            << duration_CondEnc_HD2_Sum / Num_tests << "\t"
            << duration_CondDec_HD2_Sum / Num_tests << "\t"
            << CondCtxSize << "\t"
            << TradCtxSize << "\n";



    HDdataL << MaxDist << "\t"<< _len << "\t" << duration_Enc_HD2_Sum / Num_tests << "\t"
            << duration_CondEnc_HD2_Sum / Num_tests << "\t"
            << duration_CondDec_HD2_Sum / Num_tests << "\t"
            << CondCtxSize << "\t"
            << TradCtxSize << "\n";

    CondEncHD2 << "Average Enc, CondEnc, CondDec, CtxtSize: " <<
               duration_Enc_HD2_Sum / Num_tests
               << ", " <<  duration_CondEnc_HD2_Sum / Num_tests
               << ", " <<  duration_CondDec_HD2_Sum / Num_tests << ") \n";

    CondEncHD2.close();
    paillier_freepubkey(pkobj._ppk);
    paillier_freeprvkey(pkobj._psk);
    cout << "Hamming Distant  at most One [Threshold =_len -1, _len = 64] is finished \n";
}

TEST_CASE("Conditional Encryption: Hamming Distance at most One [Threshold len-1, len =128] predicate")
{
    PwPkCrypto pkobj;
    pkobj.Paill_pk_init(1024);
    int Num_tests = 5;
    size_t _len = 128;
    int Threshold = _len - 1;

    string msg = "TheTestingPlainText";


    string msg_pad = CryptoSymWrapperFunctions::Wrapper_pad(msg, _len);
    int sizechar = sizeof(size_t);

    size_t TradCtxSize = 2 * sizeof(size_t) + _len *  PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2;
    size_t CondCtxSize = 3 * sizeof(size_t) + (sizeof(char) * 24) + (_len *  256);

    double duration_CondEnc_HD2_Sum = 0;
    double duration_Enc_HD2_Sum = 0;
    double duration_CondDec_HD2_Sum = 0;

    ofstream CondEncHD2;
    CondEncHD2.open("CondEncHDAtmostTwoLen128.txt");
    CondEncHD2 << "The predicate is Hamming distance at most two [3 errors as wors case]******************\n \n ";

    for(int T = 0; T< Num_tests; T++) {
        char HD2_Char_ORigCTx [2 * sizeof(size_t) + _len *  PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2];
        char HD2_ctx_typo_Bytes[3 * sizeof(size_t) + (sizeof(char) * 24) + (_len *  256)];
        string typo =msg;
        string payload;

        /*Randomly making typo and the payload*/
        unsigned seed= time(0);
        int NumOfErrs = 0;
        char err1, err2, err3;
        srand(seed);
        NumOfErrs = 2;
//        NumOfErrs =rand() % 4;
        if (NumOfErrs == 1)
        {
            err1 = 32 + (rand() % 95);
            int ErrLction;
            ErrLction = rand() % (msg.size());
            typo[ErrLction] = err1;
        } else if (NumOfErrs == 2)
        {
            err1 = 32 + (rand() % 95);
            err2 = 32 + (rand() % 95);
            int ErrLction1, ErrLction2;
            ErrLction1 = rand() % msg.size();
            ErrLction2 = rand() % msg.size();
            typo[ErrLction1] = err1;
            typo[ErrLction2] = err2;
        } else if (NumOfErrs == 3)
        {
            err1 = 32 + (rand() % 95);
            err2 = 32 + (rand() % 95);
            err3 = 32 + (rand() % 95);
            int ErrLction1, ErrLction2, ErrLction3;
            ErrLction1 = rand() % msg.size();
            ErrLction2 = rand() % msg.size();
            ErrLction3 = rand() % msg.size();
            typo[ErrLction1] = err1;
            typo[ErrLction2] = err2;
            typo[ErrLction3] = err3;
        }
        payload = typo;
        string pad_typo = CryptoSymWrapperFunctions::Wrapper_pad(typo, _len);


        /* ============ */

        auto start_Enc_HD2 = high_resolution_clock::now();
        int tradEncRslt =0;
        tradEncRslt = HamDistTwo::Enc(pkobj._ppk, msg_pad, HD2_Char_ORigCTx);
        auto stop_Enc_HD2 = high_resolution_clock::now();
        auto duration_Enc_HD2 = duration_cast<milliseconds>(stop_Enc_HD2 - start_Enc_HD2);

        auto start_CondEnc_HD2 = high_resolution_clock::now();

        auto ctx_final = HamDistTwo::CondEnc(pkobj._ppk, HD2_Char_ORigCTx, typo, payload,_len, Threshold, HD2_ctx_typo_Bytes);

        auto stop_CondEnc_HD2 = high_resolution_clock::now();
        auto duration_CondEnc_HD2 = duration_cast<milliseconds>(stop_CondEnc_HD2 - start_CondEnc_HD2);

        auto start_CondDec_HD2 = high_resolution_clock::now();
        string recovered_hd2Bytes;
        int CondDecOut  = 0;

        CondDecOut = HamDistTwo::CondDec(pkobj._ppk, HD2_ctx_typo_Bytes, pkobj._psk, Threshold, recovered_hd2Bytes, _len, 28);

        auto stop_CondDec_HD2 = high_resolution_clock::now();
        auto duration_CondDec_HD2 = duration_cast<milliseconds>(stop_CondDec_HD2 - start_CondDec_HD2);

        CondEncHD2 << "Enc.Time, CondEnc.Time, Cond.Dec.Time, Ctx.Size, CondCtx.Size, CondDecRslt: (" <<
                   duration_Enc_HD2.count()
                   << ", " << duration_CondEnc_HD2.count()
                   << ", " << duration_CondDec_HD2.count()
                   << ", " << TradCtxSize
                   << ", " << CondCtxSize
                   << ", " << CondDecOut << " )\n";

        duration_Enc_HD2_Sum =  duration_Enc_HD2_Sum + duration_Enc_HD2.count();
        duration_CondEnc_HD2_Sum =  duration_CondEnc_HD2_Sum + duration_CondEnc_HD2.count();
        duration_CondDec_HD2_Sum =  duration_CondDec_HD2_Sum + duration_CondDec_HD2.count();

    }

    std::ofstream HDdataL("HDdataL_T1.dat", std::ios_base::app | std::ios_base::out);
    std::ofstream HDdataT("HDdataL128_T.dat", std::ios_base::app | std::ios_base::out);

    HDdataT << "T\tL\t" << "Enc\tCondEnc\tCondDec\tCondCtxtSize\tCondCtxtSize\n";
    int MaxDist  = _len - Threshold;

    HDdataT << MaxDist << "\t"<< _len << "\t" << duration_Enc_HD2_Sum / Num_tests << "\t"
            << duration_CondEnc_HD2_Sum / Num_tests << "\t"
            << duration_CondDec_HD2_Sum / Num_tests << "\t"
            << CondCtxSize << "\t"
            << TradCtxSize << "\n";



    HDdataL << MaxDist << "\t"<< _len << "\t" << duration_Enc_HD2_Sum / Num_tests << "\t"
            << duration_CondEnc_HD2_Sum / Num_tests << "\t"
            << duration_CondDec_HD2_Sum / Num_tests << "\t"
            << CondCtxSize << "\t"
            << TradCtxSize << "\n";

    CondEncHD2 << "Average Enc, CondEnc, CondDec, CtxtSize: " <<
               duration_Enc_HD2_Sum / Num_tests
               << ", " <<  duration_CondEnc_HD2_Sum / Num_tests
               << ", " <<  duration_CondDec_HD2_Sum / Num_tests << ") \n";

    CondEncHD2.close();
    paillier_freepubkey(pkobj._ppk);
    paillier_freeprvkey(pkobj._psk);
    cout << "Hamming Distant  at most two [Threshold =_len -1, _len = 128] is finished \n";
}

TEST_CASE("Conditional Encryption: Hamming Distance at most two [Threshold len-2, len =8] predicate")
{
    PwPkCrypto pkobj;
    pkobj.Paill_pk_init(1024);
    int Num_tests = 5;
    size_t _len = 8;
    int Threshold = _len - 2;

    string msg = "Test";


    string msg_pad = CryptoSymWrapperFunctions::Wrapper_pad(msg, _len);
    int sizechar = sizeof(size_t);

    size_t TradCtxSize = 2 * sizeof(size_t) + _len *  PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2;
    size_t CondCtxSize = 3 * sizeof(size_t) + (sizeof(char) * 24) + (_len *  256);

    double duration_CondEnc_HD2_Sum = 0;
    double duration_Enc_HD2_Sum = 0;
    double duration_CondDec_HD2_Sum = 0;

    ofstream CondEncHD2;
    CondEncHD2.open("CondEncHDAtmostTwoLen8.txt");
    CondEncHD2 << "The predicate is Hamming distance at most two [3 errors as wors case]******************\n \n ";

    for(int T = 0; T< Num_tests; T++) {
        char HD2_Char_ORigCTx [2 * sizeof(size_t) + _len *  PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2];
        char HD2_ctx_typo_Bytes[3 * sizeof(size_t) + (sizeof(char) * 24) + (_len *  256)];
        string typo =msg;
        string payload;

        /*Randomly making typo and the payload*/
        unsigned seed= time(0);
        int NumOfErrs = 0;
        char err1, err2, err3;
        srand(seed);
        NumOfErrs = 3;
//        NumOfErrs =rand() % 4;
        if (NumOfErrs == 1)
        {
            err1 = 32 + (rand() % 95);
            int ErrLction;
            ErrLction = rand() % (msg.size());
            typo[ErrLction] = err1;
        } else if (NumOfErrs == 2)
        {
            err1 = 32 + (rand() % 95);
            err2 = 32 + (rand() % 95);
            int ErrLction1, ErrLction2;
            ErrLction1 = rand() % msg.size();
            ErrLction2 = rand() % msg.size();
            typo[ErrLction1] = err1;
            typo[ErrLction2] = err2;
        } else if (NumOfErrs == 3)
        {
            err1 = 32 + (rand() % 95);
            err2 = 32 + (rand() % 95);
            err3 = 32 + (rand() % 95);
            int ErrLction1, ErrLction2, ErrLction3;
            ErrLction1 = rand() % msg.size();
            ErrLction2 = rand() % msg.size();
            ErrLction3 = rand() % msg.size();
            typo[ErrLction1] = err1;
            typo[ErrLction2] = err2;
            typo[ErrLction3] = err3;
        }
        payload = typo;
        string pad_typo = CryptoSymWrapperFunctions::Wrapper_pad(typo, _len);


        /* ============ */

        auto start_Enc_HD2 = high_resolution_clock::now();
        int tradEncRslt =0;
        tradEncRslt = HamDistTwo::Enc(pkobj._ppk, msg_pad, HD2_Char_ORigCTx);
        auto stop_Enc_HD2 = high_resolution_clock::now();
        auto duration_Enc_HD2 = duration_cast<milliseconds>(stop_Enc_HD2 - start_Enc_HD2);

        auto start_CondEnc_HD2 = high_resolution_clock::now();
//        char* CondEncRst = new char[3 * sizeof(size_t) + (sizeof(char) * 24) + (32 *  256) + 1];
//        memset(HD2_ctx_typo_Bytes, '\0', CondCtxSize);
        auto ctx_final = HamDistTwo::CondEnc(pkobj._ppk, HD2_Char_ORigCTx, typo, payload,_len, Threshold, HD2_ctx_typo_Bytes);

        auto stop_CondEnc_HD2 = high_resolution_clock::now();
        auto duration_CondEnc_HD2 = duration_cast<milliseconds>(stop_CondEnc_HD2 - start_CondEnc_HD2);

        auto start_CondDec_HD2 = high_resolution_clock::now();
        string recovered_hd2Bytes;
        int CondDecOut  = 0;
//        while (CondDecOut != 1)
//        {
        CondDecOut = HamDistTwo::CondDec(pkobj._ppk, HD2_ctx_typo_Bytes, pkobj._psk, Threshold, recovered_hd2Bytes, _len, 28);
//        }
        auto stop_CondDec_HD2 = high_resolution_clock::now();
        auto duration_CondDec_HD2 = duration_cast<milliseconds>(stop_CondDec_HD2 - start_CondDec_HD2);

        CondEncHD2 << "Enc.Time, CondEnc.Time, Cond.Dec.Time, Ctx.Size, CondCtx.Size, CondDecRslt: (" <<
                   duration_Enc_HD2.count()
                   << ", " << duration_CondEnc_HD2.count()
                   << ", " << duration_CondDec_HD2.count()
                   << ", " << TradCtxSize
                   << ", " << CondCtxSize
                   << ", " << CondDecOut << " )\n";

        duration_Enc_HD2_Sum =  duration_Enc_HD2_Sum + duration_Enc_HD2.count();
        duration_CondEnc_HD2_Sum =  duration_CondEnc_HD2_Sum + duration_CondEnc_HD2.count();
        duration_CondDec_HD2_Sum =  duration_CondDec_HD2_Sum + duration_CondDec_HD2.count();

    }



    std::ofstream HDdataL("HDdataL_T2.dat", std::ios_base::app | std::ios_base::out);
    std::ofstream HDdataT("HDdataL8_T.dat", std::ios_base::app | std::ios_base::out);

    HDdataL << "T\tL\t" << "Enc\tCondEnc\tCondDec\tCondCtxtSize\tCondCtxtSize\n";

    int MaxDist  = _len - Threshold;

    HDdataT << MaxDist << "\t"<< _len << "\t" << duration_Enc_HD2_Sum / Num_tests << "\t"
            << duration_CondEnc_HD2_Sum / Num_tests << "\t"
            << duration_CondDec_HD2_Sum / Num_tests << "\t"
            << CondCtxSize << "\t"
            << TradCtxSize << "\n";



    HDdataL << MaxDist << "\t"<< _len << "\t" << duration_Enc_HD2_Sum / Num_tests << "\t"
            << duration_CondEnc_HD2_Sum / Num_tests << "\t"
            << duration_CondDec_HD2_Sum / Num_tests << "\t"
            << CondCtxSize << "\t"
            << TradCtxSize << "\n";

    CondEncHD2 << "Average Enc, CondEnc, CondDec, CtxtSize: " <<
               duration_Enc_HD2_Sum / Num_tests
               << ", " <<  duration_CondEnc_HD2_Sum / Num_tests
               << ", " <<  duration_CondDec_HD2_Sum / Num_tests << ") \n";

    CondEncHD2.close();
    paillier_freepubkey(pkobj._ppk);
    paillier_freeprvkey(pkobj._psk);
    cout << "Hamming Distant  at most two [Threshold =_len -2, _len = 8] is finished \n";
}

TEST_CASE("Conditional Encryption: Hamming Distance at most two [Threshold len-2, len =16] predicate")
{
    PwPkCrypto pkobj;
    pkobj.Paill_pk_init(1024);
    int Num_tests = 5;
    size_t _len = 16;
    int Threshold = _len - 2;

    string msg = "Test";


    string msg_pad = CryptoSymWrapperFunctions::Wrapper_pad(msg, _len);
    int sizechar = sizeof(size_t);

    size_t TradCtxSize = 2 * sizeof(size_t) + _len *  PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2;
    size_t CondCtxSize = 3 * sizeof(size_t) + (sizeof(char) * 24) + (_len *  256);

    double duration_CondEnc_HD2_Sum = 0;
    double duration_Enc_HD2_Sum = 0;
    double duration_CondDec_HD2_Sum = 0;

    ofstream CondEncHD2;
    CondEncHD2.open("CondEncHDAtmostTwoLen16.txt");
    CondEncHD2 << "The predicate is Hamming distance at most two [3 errors as wors case]******************\n \n ";

    for(int T = 0; T< Num_tests; T++) {
        char HD2_Char_ORigCTx [2 * sizeof(size_t) + _len *  PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2];
        char HD2_ctx_typo_Bytes[3 * sizeof(size_t) + (sizeof(char) * 24) + (_len *  256)];
        string typo =msg;
        string payload;

        /*Randomly making typo and the payload*/
        unsigned seed= time(0);
        int NumOfErrs = 0;
        char err1, err2, err3;
        srand(seed);
        NumOfErrs = 3;
//        NumOfErrs =rand() % 4;
        if (NumOfErrs == 1)
        {
            err1 = 32 + (rand() % 95);
            int ErrLction;
            ErrLction = rand() % (msg.size());
            typo[ErrLction] = err1;
        } else if (NumOfErrs == 2)
        {
            err1 = 32 + (rand() % 95);
            err2 = 32 + (rand() % 95);
            int ErrLction1, ErrLction2;
            ErrLction1 = rand() % msg.size();
            ErrLction2 = rand() % msg.size();
            typo[ErrLction1] = err1;
            typo[ErrLction2] = err2;
        } else if (NumOfErrs == 3)
        {
            err1 = 32 + (rand() % 95);
            err2 = 32 + (rand() % 95);
            err3 = 32 + (rand() % 95);
            int ErrLction1, ErrLction2, ErrLction3;
            ErrLction1 = rand() % msg.size();
            ErrLction2 = rand() % msg.size();
            ErrLction3 = rand() % msg.size();
            typo[ErrLction1] = err1;
            typo[ErrLction2] = err2;
            typo[ErrLction3] = err3;
        }
        payload = typo;
        string pad_typo = CryptoSymWrapperFunctions::Wrapper_pad(typo, _len);


        /* ============ */

        auto start_Enc_HD2 = high_resolution_clock::now();
        int tradEncRslt =0;
        tradEncRslt = HamDistTwo::Enc(pkobj._ppk, msg_pad, HD2_Char_ORigCTx);
        auto stop_Enc_HD2 = high_resolution_clock::now();
        auto duration_Enc_HD2 = duration_cast<milliseconds>(stop_Enc_HD2 - start_Enc_HD2);

        auto start_CondEnc_HD2 = high_resolution_clock::now();

        auto ctx_final = HamDistTwo::CondEnc(pkobj._ppk, HD2_Char_ORigCTx, typo, payload,_len, Threshold, HD2_ctx_typo_Bytes);

        auto stop_CondEnc_HD2 = high_resolution_clock::now();
        auto duration_CondEnc_HD2 = duration_cast<milliseconds>(stop_CondEnc_HD2 - start_CondEnc_HD2);

        auto start_CondDec_HD2 = high_resolution_clock::now();
        string recovered_hd2Bytes;
        int CondDecOut  = 0;

        CondDecOut = HamDistTwo::CondDec(pkobj._ppk, HD2_ctx_typo_Bytes, pkobj._psk, Threshold, recovered_hd2Bytes, _len, 28);

        auto stop_CondDec_HD2 = high_resolution_clock::now();
        auto duration_CondDec_HD2 = duration_cast<milliseconds>(stop_CondDec_HD2 - start_CondDec_HD2);


        CondEncHD2 << "Enc.Time, CondEnc.Time, Cond.Dec.Time, Ctx.Size, CondCtx.Size, CondDecRslt: (" <<
                   duration_Enc_HD2.count()
                   << ", " << duration_CondEnc_HD2.count()
                   << ", " << duration_CondDec_HD2.count()
                   << ", " << TradCtxSize
                   << ", " << CondCtxSize
                   << ", " << CondDecOut << " )\n";

        duration_Enc_HD2_Sum =  duration_Enc_HD2_Sum + duration_Enc_HD2.count();
        duration_CondEnc_HD2_Sum =  duration_CondEnc_HD2_Sum + duration_CondEnc_HD2.count();
        duration_CondDec_HD2_Sum =  duration_CondDec_HD2_Sum + duration_CondDec_HD2.count();

    }

    std::ofstream HDdataL("HDdataL_T2.dat", std::ios_base::app | std::ios_base::out);
    std::ofstream HDdataT("HDdataL16_T.dat", std::ios_base::app | std::ios_base::out);


    int MaxDist  = _len - Threshold;

    HDdataT << MaxDist << "\t"<< _len << "\t" << duration_Enc_HD2_Sum / Num_tests << "\t"
            << duration_CondEnc_HD2_Sum / Num_tests << "\t"
            << duration_CondDec_HD2_Sum / Num_tests << "\t"
            << CondCtxSize << "\t"
            << TradCtxSize << "\n";


    HDdataL << MaxDist << "\t"<< _len << "\t" << duration_Enc_HD2_Sum / Num_tests << "\t"
            << duration_CondEnc_HD2_Sum / Num_tests << "\t"
            << duration_CondDec_HD2_Sum / Num_tests << "\t"
            << CondCtxSize << "\t"
            << TradCtxSize << "\n";

    CondEncHD2 << "Average Enc, CondEnc, CondDec, CtxtSize: " <<
               duration_Enc_HD2_Sum / Num_tests
               << ", " <<  duration_CondEnc_HD2_Sum / Num_tests
               << ", " <<  duration_CondDec_HD2_Sum / Num_tests << ") \n";

    CondEncHD2.close();
    paillier_freepubkey(pkobj._ppk);
    paillier_freeprvkey(pkobj._psk);
    cout << "Hamming Distant  at most two [Threshold =_len -2, _len = 16] is finished \n";
}

TEST_CASE("Conditional Encryption: Hamming Distance at most two [Threshold len-2, len =32 (effect of _len)] predicate")
{
    PwPkCrypto pkobj;
    pkobj.Paill_pk_init(1024);
    int Num_tests = 5;
    size_t _len = 32;
    int Threshold = _len - 2;

    string msg = "TheTestingPlainText";


    string msg_pad = CryptoSymWrapperFunctions::Wrapper_pad(msg, _len);
    int sizechar = sizeof(size_t);

    size_t TradCtxSize = 2 * sizeof(size_t) + _len *  PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2;
    size_t CondCtxSize = 3 * sizeof(size_t) + (sizeof(char) * 24) + (_len *  256);

    double duration_CondEnc_HD2_Sum = 0;
    double duration_Enc_HD2_Sum = 0;
    double duration_CondDec_HD2_Sum = 0;

    ofstream CondEncHD2;
    CondEncHD2.open("CondEncHDAtmostTwoLen32.txt");
    CondEncHD2 << "The predicate is Hamming distance at most two [3 errors as wors case]******************\n \n ";

    for(int T = 0; T< Num_tests; T++) {
        char HD2_Char_ORigCTx [2 * sizeof(size_t) + _len *  PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2];
        char HD2_ctx_typo_Bytes[3 * sizeof(size_t) + (sizeof(char) * 24) + (_len *  256)];
        string typo =msg;
        string payload;

        /*Randomly making typo and the payload*/
        unsigned seed= time(0);
        int NumOfErrs = 0;
        char err1, err2, err3;
        srand(seed);
        NumOfErrs = 3;
//        NumOfErrs =rand() % 4;
        if (NumOfErrs == 1)
        {
            err1 = 32 + (rand() % 95);
            int ErrLction;
            ErrLction = rand() % (msg.size());
            typo[ErrLction] = err1;
        } else if (NumOfErrs == 2)
        {
            err1 = 32 + (rand() % 95);
            err2 = 32 + (rand() % 95);
            int ErrLction1, ErrLction2;
            ErrLction1 = rand() % msg.size();
            ErrLction2 = rand() % msg.size();
            typo[ErrLction1] = err1;
            typo[ErrLction2] = err2;
        } else if (NumOfErrs == 3)
        {
            err1 = 32 + (rand() % 95);
            err2 = 32 + (rand() % 95);
            err3 = 32 + (rand() % 95);
            int ErrLction1, ErrLction2, ErrLction3;
            ErrLction1 = rand() % msg.size();
            ErrLction2 = rand() % msg.size();
            ErrLction3 = rand() % msg.size();
            typo[ErrLction1] = err1;
            typo[ErrLction2] = err2;
            typo[ErrLction3] = err3;
        }
        payload = typo;
        string pad_typo = CryptoSymWrapperFunctions::Wrapper_pad(typo, _len);


        /* ============ */

        auto start_Enc_HD2 = high_resolution_clock::now();
        int tradEncRslt =0;
        tradEncRslt = HamDistTwo::Enc(pkobj._ppk, msg_pad, HD2_Char_ORigCTx);
        auto stop_Enc_HD2 = high_resolution_clock::now();
        auto duration_Enc_HD2 = duration_cast<milliseconds>(stop_Enc_HD2 - start_Enc_HD2);

        auto start_CondEnc_HD2 = high_resolution_clock::now();
        auto ctx_final = HamDistTwo::CondEnc(pkobj._ppk, HD2_Char_ORigCTx, typo, payload,_len, Threshold, HD2_ctx_typo_Bytes);

        auto stop_CondEnc_HD2 = high_resolution_clock::now();
        auto duration_CondEnc_HD2 = duration_cast<milliseconds>(stop_CondEnc_HD2 - start_CondEnc_HD2);

        auto start_CondDec_HD2 = high_resolution_clock::now();
        string recovered_hd2Bytes;
        int CondDecOut  = 0;
        CondDecOut = HamDistTwo::CondDec(pkobj._ppk, HD2_ctx_typo_Bytes, pkobj._psk, Threshold, recovered_hd2Bytes, _len, 28);
        auto stop_CondDec_HD2 = high_resolution_clock::now();
        auto duration_CondDec_HD2 = duration_cast<milliseconds>(stop_CondDec_HD2 - start_CondDec_HD2);
        CondEncHD2 << "Enc.Time, CondEnc.Time, Cond.Dec.Time, Ctx.Size, CondCtx.Size, CondDecRslt: (" <<
                   duration_Enc_HD2.count()
                   << ", " << duration_CondEnc_HD2.count()
                   << ", " << duration_CondDec_HD2.count()
                   << ", " << TradCtxSize
                   << ", " << CondCtxSize
                   << ", " << CondDecOut << " )\n";

        duration_Enc_HD2_Sum =  duration_Enc_HD2_Sum + duration_Enc_HD2.count();
        duration_CondEnc_HD2_Sum =  duration_CondEnc_HD2_Sum + duration_CondEnc_HD2.count();
        duration_CondDec_HD2_Sum =  duration_CondDec_HD2_Sum + duration_CondDec_HD2.count();

    }

    std::ofstream HDdataL("HDdataL_T2.dat", std::ios_base::app | std::ios_base::out);
    std::ofstream HDdataT("HDdataL32_T.dat", std::ios_base::app | std::ios_base::out);

    int MaxDist  = _len - Threshold;

    HDdataT << MaxDist << "\t"<< _len << "\t" << duration_Enc_HD2_Sum / Num_tests << "\t"
            << duration_CondEnc_HD2_Sum / Num_tests << "\t"
            << duration_CondDec_HD2_Sum / Num_tests << "\t"
            << CondCtxSize << "\t"
            << TradCtxSize << "\n";



    HDdataL << MaxDist << "\t"<< _len << "\t" << duration_Enc_HD2_Sum / Num_tests << "\t"
            << duration_CondEnc_HD2_Sum / Num_tests << "\t"
            << duration_CondDec_HD2_Sum / Num_tests << "\t"
            << CondCtxSize << "\t"
            << TradCtxSize << "\n";

    CondEncHD2 << "Average Enc, CondEnc, CondDec, CtxtSize: " <<
               duration_Enc_HD2_Sum / Num_tests
               << ", " <<  duration_CondEnc_HD2_Sum / Num_tests
               << ", " <<  duration_CondDec_HD2_Sum / Num_tests << ") \n";

    CondEncHD2.close();
    paillier_freepubkey(pkobj._ppk);
    paillier_freeprvkey(pkobj._psk);
    cout << "Hamming Distant  at most two [Threshold =_len -2, _len = 32] is finished \n";
}

TEST_CASE("Conditional Encryption: Hamming Distance at most two [Threshold len-2, len =64] predicate")
{
    PwPkCrypto pkobj;
    pkobj.Paill_pk_init(1024);
    int Num_tests = 5;
    size_t _len = 64;
    int Threshold = _len - 2;

    string msg = "TheTestingPlainText";


    string msg_pad = CryptoSymWrapperFunctions::Wrapper_pad(msg, _len);
    int sizechar = sizeof(size_t);

    size_t TradCtxSize = 2 * sizeof(size_t) + _len *  PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2;
    size_t CondCtxSize = 3 * sizeof(size_t) + (sizeof(char) * 24) + (_len *  256);
    double duration_CondEnc_HD2_Sum = 0;
    double duration_Enc_HD2_Sum = 0;
    double duration_CondDec_HD2_Sum = 0;

    ofstream CondEncHD2;
    CondEncHD2.open("CondEncHDAtmostTwoLen64.txt");
    CondEncHD2 << "The predicate is Hamming distance at most two [3 errors as wors case]******************\n \n ";

    for(int T = 0; T< Num_tests; T++) {
        char HD2_Char_ORigCTx [2 * sizeof(size_t) + _len *  PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2];
        char HD2_ctx_typo_Bytes[3 * sizeof(size_t) + (sizeof(char) * 24) + (_len *  256)];
        string typo =msg;
        string payload;

        /*Randomly making typo and the payload*/
        unsigned seed= time(0);
        int NumOfErrs = 0;
        char err1, err2, err3;
        srand(seed);
        NumOfErrs = 3;
//        NumOfErrs =rand() % 4;
        if (NumOfErrs == 1)
        {
            err1 = 32 + (rand() % 95);
            int ErrLction;
            ErrLction = rand() % (msg.size());
            typo[ErrLction] = err1;
        } else if (NumOfErrs == 2)
        {
            err1 = 32 + (rand() % 95);
            err2 = 32 + (rand() % 95);
            int ErrLction1, ErrLction2;
            ErrLction1 = rand() % msg.size();
            ErrLction2 = rand() % msg.size();
            typo[ErrLction1] = err1;
            typo[ErrLction2] = err2;
        } else if (NumOfErrs == 3)
        {
            err1 = 32 + (rand() % 95);
            err2 = 32 + (rand() % 95);
            err3 = 32 + (rand() % 95);
            int ErrLction1, ErrLction2, ErrLction3;
            ErrLction1 = rand() % msg.size();
            ErrLction2 = rand() % msg.size();
            ErrLction3 = rand() % msg.size();
            typo[ErrLction1] = err1;
            typo[ErrLction2] = err2;
            typo[ErrLction3] = err3;
        }
        payload = typo;
        string pad_typo = CryptoSymWrapperFunctions::Wrapper_pad(typo, _len);


        /* ============ */

        auto start_Enc_HD2 = high_resolution_clock::now();
        int tradEncRslt =0;
        tradEncRslt = HamDistTwo::Enc(pkobj._ppk, msg_pad, HD2_Char_ORigCTx);
        auto stop_Enc_HD2 = high_resolution_clock::now();
        auto duration_Enc_HD2 = duration_cast<milliseconds>(stop_Enc_HD2 - start_Enc_HD2);

        auto start_CondEnc_HD2 = high_resolution_clock::now();

        auto ctx_final = HamDistTwo::CondEnc(pkobj._ppk, HD2_Char_ORigCTx, typo, payload,_len, Threshold, HD2_ctx_typo_Bytes);

        auto stop_CondEnc_HD2 = high_resolution_clock::now();
        auto duration_CondEnc_HD2 = duration_cast<milliseconds>(stop_CondEnc_HD2 - start_CondEnc_HD2);

        auto start_CondDec_HD2 = high_resolution_clock::now();
        string recovered_hd2Bytes;
        int CondDecOut  = 0;
//        while (CondDecOut != 1)
//        {
        CondDecOut = HamDistTwo::CondDec(pkobj._ppk, HD2_ctx_typo_Bytes, pkobj._psk, Threshold, recovered_hd2Bytes, _len, 28);
//        }
        auto stop_CondDec_HD2 = high_resolution_clock::now();
        auto duration_CondDec_HD2 = duration_cast<milliseconds>(stop_CondDec_HD2 - start_CondDec_HD2);

        CondEncHD2 << "Enc.Time, CondEnc.Time, Cond.Dec.Time, Ctx.Size, CondCtx.Size, CondDecRslt: (" <<
                   duration_Enc_HD2.count()
                   << ", " << duration_CondEnc_HD2.count()
                   << ", " << duration_CondDec_HD2.count()
                   << ", " << TradCtxSize
                   << ", " << CondCtxSize
                   << ", " << CondDecOut << " )\n";

        duration_Enc_HD2_Sum =  duration_Enc_HD2_Sum + duration_Enc_HD2.count();
        duration_CondEnc_HD2_Sum =  duration_CondEnc_HD2_Sum + duration_CondEnc_HD2.count();
        duration_CondDec_HD2_Sum =  duration_CondDec_HD2_Sum + duration_CondDec_HD2.count();

    }

    std::ofstream HDdataL("HDdataL_T2.dat", std::ios_base::app | std::ios_base::out);
    std::ofstream HDdataT("HDdataL64_T.dat", std::ios_base::app | std::ios_base::out);

    int MaxDist  = _len - Threshold;

    HDdataT << MaxDist << "\t"<< _len << "\t" << duration_Enc_HD2_Sum / Num_tests << "\t"
            << duration_CondEnc_HD2_Sum / Num_tests << "\t"
            << duration_CondDec_HD2_Sum / Num_tests << "\t"
            << CondCtxSize << "\t"
            << TradCtxSize << "\n";



    HDdataL << MaxDist << "\t"<< _len << "\t" << duration_Enc_HD2_Sum / Num_tests << "\t"
            << duration_CondEnc_HD2_Sum / Num_tests << "\t"
            << duration_CondDec_HD2_Sum / Num_tests << "\t"
            << CondCtxSize << "\t"
            << TradCtxSize << "\n";

    CondEncHD2 << "Average Enc, CondEnc, CondDec, CtxtSize: " <<
               duration_Enc_HD2_Sum / Num_tests
               << ", " <<  duration_CondEnc_HD2_Sum / Num_tests
               << ", " <<  duration_CondDec_HD2_Sum / Num_tests << ") \n";

    CondEncHD2.close();
    paillier_freepubkey(pkobj._ppk);
    paillier_freeprvkey(pkobj._psk);
    cout << "Hamming Distant  at most two [Threshold =_len -2, _len = 64] is finished \n";
}

TEST_CASE("Conditional Encryption: Hamming Distance at most two [Threshold len-2, len =128] predicate")
{
    PwPkCrypto pkobj;
    pkobj.Paill_pk_init(1024);
    int Num_tests = 5;
    size_t _len = 128;
    int Threshold = _len - 2;

    string msg = "TheTestingPlainText";


    string msg_pad = CryptoSymWrapperFunctions::Wrapper_pad(msg, _len);
    int sizechar = sizeof(size_t);

    size_t TradCtxSize = 2 * sizeof(size_t) + _len *  PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2;
    size_t CondCtxSize = 3 * sizeof(size_t) + (sizeof(char) * 24) + (_len *  256);

    double duration_CondEnc_HD2_Sum = 0;
    double duration_Enc_HD2_Sum = 0;
    double duration_CondDec_HD2_Sum = 0;

    ofstream CondEncHD2;
    CondEncHD2.open("CondEncHDAtmostTwoLen128.txt");
    CondEncHD2 << "The predicate is Hamming distance at most two [3 errors as worst case]******************\n \n ";

    for(int T = 0; T < Num_tests; T++) {
        char HD2_Char_ORigCTx [2 * sizeof(size_t) + _len *  PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2];
        char HD2_ctx_typo_Bytes[3 * sizeof(size_t) + (sizeof(char) * 24) + (_len *  256)];
        string typo =msg;
        string payload;

        /*Randomly making typo and the payload*/
        unsigned seed= time(0);
        int NumOfErrs = 0;
        char err1, err2, err3;
        srand(seed);
        NumOfErrs = 3;
//        NumOfErrs =rand() % 4;
        if (NumOfErrs == 1)
        {
            err1 = 32 + (rand() % 95);
            int ErrLction;
            ErrLction = rand() % (msg.size());
            typo[ErrLction] = err1;
        } else if (NumOfErrs == 2)
        {
            err1 = 32 + (rand() % 95);
            err2 = 32 + (rand() % 95);
            int ErrLction1, ErrLction2;
            ErrLction1 = rand() % msg.size();
            ErrLction2 = rand() % msg.size();
            typo[ErrLction1] = err1;
            typo[ErrLction2] = err2;
        } else if (NumOfErrs == 3)
        {
            err1 = 32 + (rand() % 95);
            err2 = 32 + (rand() % 95);
            err3 = 32 + (rand() % 95);
            int ErrLction1, ErrLction2, ErrLction3;
            ErrLction1 = rand() % msg.size();
            ErrLction2 = rand() % msg.size();
            ErrLction3 = rand() % msg.size();
            typo[ErrLction1] = err1;
            typo[ErrLction2] = err2;
            typo[ErrLction3] = err3;
        }
        payload = typo;
        string pad_typo = CryptoSymWrapperFunctions::Wrapper_pad(typo, _len);


        /* ============ */

        auto start_Enc_HD2 = high_resolution_clock::now();
        int tradEncRslt =0;
        tradEncRslt = HamDistTwo::Enc(pkobj._ppk, msg_pad, HD2_Char_ORigCTx);
        auto stop_Enc_HD2 = high_resolution_clock::now();
        auto duration_Enc_HD2 = duration_cast<milliseconds>(stop_Enc_HD2 - start_Enc_HD2);

        auto start_CondEnc_HD2 = high_resolution_clock::now();
        auto ctx_final = HamDistTwo::CondEnc(pkobj._ppk, HD2_Char_ORigCTx, typo, payload,_len, Threshold, HD2_ctx_typo_Bytes);
        auto stop_CondEnc_HD2 = high_resolution_clock::now();
        auto duration_CondEnc_HD2 = duration_cast<milliseconds>(stop_CondEnc_HD2 - start_CondEnc_HD2);

        auto start_CondDec_HD2 = high_resolution_clock::now();
        string recovered_hd2Bytes;
        int CondDecOut  = 0;
        CondDecOut = HamDistTwo::CondDec(pkobj._ppk, HD2_ctx_typo_Bytes, pkobj._psk, Threshold, recovered_hd2Bytes, _len, 28);
        auto stop_CondDec_HD2 = high_resolution_clock::now();
        auto duration_CondDec_HD2 = duration_cast<milliseconds>(stop_CondDec_HD2 - start_CondDec_HD2);
        CondEncHD2 << "Enc.Time, CondEnc.Time, Cond.Dec.Time, Ctx.Size, CondCtx.Size, CondDecRslt: (" <<
                   duration_Enc_HD2.count()
                   << ", " << duration_CondEnc_HD2.count()
                   << ", " << duration_CondDec_HD2.count()
                   << ", " << TradCtxSize
                   << ", " << CondCtxSize
                   << ", " << CondDecOut << " )\n";

        duration_Enc_HD2_Sum =  duration_Enc_HD2_Sum + duration_Enc_HD2.count();
        duration_CondEnc_HD2_Sum =  duration_CondEnc_HD2_Sum + duration_CondEnc_HD2.count();
        duration_CondDec_HD2_Sum =  duration_CondDec_HD2_Sum + duration_CondDec_HD2.count();

    }

    std::ofstream HDdataL("HDdataL_T2.dat", std::ios_base::app | std::ios_base::out);
    std::ofstream HDdataT("HDdataL128_T.dat", std::ios_base::app | std::ios_base::out);

    int MaxDist  = _len - Threshold;

    HDdataT << MaxDist << "\t"<< _len << "\t" << duration_Enc_HD2_Sum / Num_tests << "\t"
            << duration_CondEnc_HD2_Sum / Num_tests << "\t"
            << duration_CondDec_HD2_Sum / Num_tests << "\t"
            << CondCtxSize << "\t"
            << TradCtxSize << "\n";



    HDdataL << MaxDist << "\t"<< _len << "\t" << duration_Enc_HD2_Sum / Num_tests << "\t"
            << duration_CondEnc_HD2_Sum / Num_tests << "\t"
            << duration_CondDec_HD2_Sum / Num_tests << "\t"
            << CondCtxSize << "\t"
            << TradCtxSize << "\n";

    CondEncHD2.close();
    paillier_freepubkey(pkobj._ppk);
    paillier_freeprvkey(pkobj._psk);
    cout << "Hamming Distant  at most two [Threshold =_len -2, _len = 128] is finished \n";
}

TEST_CASE("Conditional Encryption: Hamming Distance at most Three [Threshold len-3, len =8] predicate")
{
    PwPkCrypto pkobj;
    pkobj.Paill_pk_init(1024);
    int Num_tests = 5;
    size_t _len = 8;
    int Threshold = _len - 3;

    string msg = "TEST";

    string msg_pad = CryptoSymWrapperFunctions::Wrapper_pad(msg, _len);
    int sizechar = sizeof(size_t);

    size_t TradCtxSize = 2 * sizeof(size_t) + _len *  PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2;
    size_t CondCtxSize = 3 * sizeof(size_t) + (sizeof(char) * 24) + (_len *  256);

    double duration_CondEnc_HD2_Sum = 0;
    double duration_Enc_HD2_Sum = 0;
    double duration_CondDec_HD2_Sum = 0;

    ofstream CondEncHD2;
    CondEncHD2.open("CondEncHDAtmostThreeLen8.txt");
    CondEncHD2 << "The predicate is Hamming distance at most two [3 errors as wors case]******************\n \n ";

    for(int T = 0; T< Num_tests; T++) {
        char HD2_Char_ORigCTx [2 * sizeof(size_t) + _len *  PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2];
        char HD2_ctx_typo_Bytes[3 * sizeof(size_t) + (sizeof(char) * 24) + (_len *  256)];
        string typo =msg;
        string payload;

        /*Randomly making typo and the payload*/
        unsigned seed= time(0);
        int NumOfErrs = 0;
        char err1, err2, err3, err4;
        srand(seed);
        NumOfErrs = 4;
//        NumOfErrs =rand() % 4;
        if (NumOfErrs == 1)
        {
            err1 = 32 + (rand() % 95);
            int ErrLction;
            ErrLction = rand() % (msg.size());
            typo[ErrLction] = err1;
        } else if (NumOfErrs == 2)
        {
            err1 = 32 + (rand() % 95);
            err2 = 32 + (rand() % 95);
            int ErrLction1, ErrLction2;
            ErrLction1 = rand() % msg.size();
            ErrLction2 = rand() % msg.size();
            typo[ErrLction1] = err1;
            typo[ErrLction2] = err2;
        } else if (NumOfErrs == 4)
        {
            err1 = 32 + (rand() % 95);
            err2 = 32 + (rand() % 95);
            err3 = 32 + (rand() % 95);
            err4 = 32 + (rand() % 95);
            int ErrLction1, ErrLction2, ErrLction3, ErrLction4;
            ErrLction1 = rand() % msg.size();
            ErrLction2 = rand() % msg.size();
            ErrLction3 = rand() % msg.size();
            ErrLction4 = rand() % msg.size();
            typo[ErrLction1] = err1;
            typo[ErrLction2] = err2;
            typo[ErrLction3] = err3;
            typo[ErrLction4] = err4;
        }
        payload = typo;
        string pad_typo = CryptoSymWrapperFunctions::Wrapper_pad(typo, _len);


        /* ============ */

        auto start_Enc_HD2 = high_resolution_clock::now();
        int tradEncRslt =0;
        tradEncRslt = HamDistTwo::Enc(pkobj._ppk, msg_pad, HD2_Char_ORigCTx);
        auto stop_Enc_HD2 = high_resolution_clock::now();
        auto duration_Enc_HD2 = duration_cast<milliseconds>(stop_Enc_HD2 - start_Enc_HD2);

        auto start_CondEnc_HD2 = high_resolution_clock::now();
        auto ctx_final = HamDistTwo::CondEnc(pkobj._ppk, HD2_Char_ORigCTx, typo, payload,_len, Threshold, HD2_ctx_typo_Bytes);
        auto stop_CondEnc_HD2 = high_resolution_clock::now();
        auto duration_CondEnc_HD2 = duration_cast<milliseconds>(stop_CondEnc_HD2 - start_CondEnc_HD2);

        auto start_CondDec_HD2 = high_resolution_clock::now();
        string recovered_hd2Bytes;
        int CondDecOut  = 0;
        CondDecOut = HamDistTwo::CondDec(pkobj._ppk, HD2_ctx_typo_Bytes, pkobj._psk, Threshold, recovered_hd2Bytes, _len, 28);
        auto stop_CondDec_HD2 = high_resolution_clock::now();
        auto duration_CondDec_HD2 = duration_cast<milliseconds>(stop_CondDec_HD2 - start_CondDec_HD2);
        CondEncHD2 << "Enc.Time, CondEnc.Time, Cond.Dec.Time, Ctx.Size, CondCtx.Size, CondDecRslt: (" <<
                   duration_Enc_HD2.count()
                   << ", " << duration_CondEnc_HD2.count()
                   << ", " << duration_CondDec_HD2.count()
                   << ", " << TradCtxSize
                   << ", " << CondCtxSize
                   << ", " << CondDecOut << " )\n";

        duration_Enc_HD2_Sum =  duration_Enc_HD2_Sum + duration_Enc_HD2.count();
        duration_CondEnc_HD2_Sum =  duration_CondEnc_HD2_Sum + duration_CondEnc_HD2.count();
        duration_CondDec_HD2_Sum =  duration_CondDec_HD2_Sum + duration_CondDec_HD2.count();

    }

    std::ofstream HDdataL("HDdataL_T3.dat", std::ios_base::app | std::ios_base::out);
    std::ofstream HDdataT("HDdataL8_T.dat", std::ios_base::app | std::ios_base::out);

    HDdataL << "T\tL\t" << "Enc\tCondEnc\tCondDec\tCondCtxtSize\tCondCtxtSize\n";
    int MaxDist  = _len - Threshold;

    HDdataT << MaxDist << "\t"<< _len << "\t" << duration_Enc_HD2_Sum / Num_tests << "\t"
            << duration_CondEnc_HD2_Sum / Num_tests << "\t"
            << duration_CondDec_HD2_Sum / Num_tests << "\t"
            << CondCtxSize << "\t"
            << TradCtxSize << "\n";



    HDdataL << MaxDist << "\t"<< _len << "\t" << duration_Enc_HD2_Sum / Num_tests << "\t"
            << duration_CondEnc_HD2_Sum / Num_tests << "\t"
            << duration_CondDec_HD2_Sum / Num_tests << "\t"
            << CondCtxSize << "\t"
            << TradCtxSize << "\n";

    CondEncHD2 << "Average Enc, CondEnc, CondDec, CtxtSize: " <<
               duration_Enc_HD2_Sum / Num_tests
               << ", " <<  duration_CondEnc_HD2_Sum / Num_tests
               << ", " <<  duration_CondDec_HD2_Sum / Num_tests << ") \n";

    CondEncHD2.close();
    paillier_freepubkey(pkobj._ppk);
    paillier_freeprvkey(pkobj._psk);
    cout << "Hamming Distant  at most Three [Threshold =_len -3, _len = 8] is finished \n";
}

TEST_CASE("Conditional Encryption: Hamming Distance at most Three [Threshold len-3, len =16] predicate")
{
    PwPkCrypto pkobj;
    pkobj.Paill_pk_init(1024);
    int Num_tests = 5;
    size_t _len = 16;
    int Threshold = _len - 3;

    string msg = "Test";


    string msg_pad = CryptoSymWrapperFunctions::Wrapper_pad(msg, _len);
    int sizechar = sizeof(size_t);

    size_t TradCtxSize = 2 * sizeof(size_t) + _len *  PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2;
    size_t CondCtxSize = 3 * sizeof(size_t) + (sizeof(char) * 24) + (_len *  256);

    double duration_CondEnc_HD2_Sum = 0;
    double duration_Enc_HD2_Sum = 0;
    double duration_CondDec_HD2_Sum = 0;

    ofstream CondEncHD2;
    CondEncHD2.open("CondEncHDAtmostThreeLen16.txt");
    CondEncHD2 << "The predicate is Hamming distance at most two [3 errors as wors case]******************\n \n ";

    for(int T = 0; T< Num_tests; T++) {
        char HD2_Char_ORigCTx [2 * sizeof(size_t) + _len *  PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2];
        char HD2_ctx_typo_Bytes[3 * sizeof(size_t) + (sizeof(char) * 24) + (_len *  256)];
        string typo =msg;
        string payload;

        /*Randomly making typo and the payload*/
        unsigned seed= time(0);
        int NumOfErrs = 0;
        char err1, err2, err3, err4;
        srand(seed);
        NumOfErrs = 4;
//        NumOfErrs =rand() % 4;
        if (NumOfErrs == 1)
        {
            err1 = 32 + (rand() % 95);
            int ErrLction;
            ErrLction = rand() % (msg.size());
            typo[ErrLction] = err1;
        } else if (NumOfErrs == 2)
        {
            err1 = 32 + (rand() % 95);
            err2 = 32 + (rand() % 95);
            int ErrLction1, ErrLction2;
            ErrLction1 = rand() % msg.size();
            ErrLction2 = rand() % msg.size();
            typo[ErrLction1] = err1;
            typo[ErrLction2] = err2;
        } else if (NumOfErrs == 4)
        {
            err1 = 32 + (rand() % 95);
            err2 = 32 + (rand() % 95);
            err3 = 32 + (rand() % 95);
            err4 = 32 + (rand() % 95);
            int ErrLction1, ErrLction2, ErrLction3, ErrLction4;
            ErrLction1 = rand() % msg.size();
            ErrLction2 = rand() % msg.size();
            ErrLction3 = rand() % msg.size();
            ErrLction4 = rand() % msg.size();
            typo[ErrLction1] = err1;
            typo[ErrLction2] = err2;
            typo[ErrLction3] = err3;
            typo[ErrLction4] = err4;
        }
        payload = typo;
        string pad_typo = CryptoSymWrapperFunctions::Wrapper_pad(typo, _len);


        /* ============ */

        auto start_Enc_HD2 = high_resolution_clock::now();
        int tradEncRslt =0;
        tradEncRslt = HamDistTwo::Enc(pkobj._ppk, msg_pad, HD2_Char_ORigCTx);
        auto stop_Enc_HD2 = high_resolution_clock::now();
        auto duration_Enc_HD2 = duration_cast<milliseconds>(stop_Enc_HD2 - start_Enc_HD2);

        auto start_CondEnc_HD2 = high_resolution_clock::now();
        auto ctx_final = HamDistTwo::CondEnc(pkobj._ppk, HD2_Char_ORigCTx, typo, payload,_len, Threshold, HD2_ctx_typo_Bytes);
        auto stop_CondEnc_HD2 = high_resolution_clock::now();
        auto duration_CondEnc_HD2 = duration_cast<milliseconds>(stop_CondEnc_HD2 - start_CondEnc_HD2);

        auto start_CondDec_HD2 = high_resolution_clock::now();
        string recovered_hd2Bytes;
        int CondDecOut  = 0;
        CondDecOut = HamDistTwo::CondDec(pkobj._ppk, HD2_ctx_typo_Bytes, pkobj._psk, Threshold, recovered_hd2Bytes, _len, 28);
        auto stop_CondDec_HD2 = high_resolution_clock::now();
        auto duration_CondDec_HD2 = duration_cast<milliseconds>(stop_CondDec_HD2 - start_CondDec_HD2);
        CondEncHD2 << "Enc.Time, CondEnc.Time, Cond.Dec.Time, Ctx.Size, CondCtx.Size, CondDecRslt: (" <<
                   duration_Enc_HD2.count()
                   << ", " << duration_CondEnc_HD2.count()
                   << ", " << duration_CondDec_HD2.count()
                   << ", " << TradCtxSize
                   << ", " << CondCtxSize
                   << ", " << CondDecOut << " )\n";

        duration_Enc_HD2_Sum =  duration_Enc_HD2_Sum + duration_Enc_HD2.count();
        duration_CondEnc_HD2_Sum =  duration_CondEnc_HD2_Sum + duration_CondEnc_HD2.count();
        duration_CondDec_HD2_Sum =  duration_CondDec_HD2_Sum + duration_CondDec_HD2.count();

    }

    std::ofstream HDdataL("HDdataL_T3.dat", std::ios_base::app | std::ios_base::out);
    std::ofstream HDdataT("HDdataL16_T.dat", std::ios_base::app | std::ios_base::out);

    int MaxDist  = _len - Threshold;

    HDdataT << MaxDist << "\t"<< _len << "\t" << duration_Enc_HD2_Sum / Num_tests << "\t"
            << duration_CondEnc_HD2_Sum / Num_tests << "\t"
            << duration_CondDec_HD2_Sum / Num_tests << "\t"
            << CondCtxSize << "\t"
            << TradCtxSize << "\n";



    HDdataL << MaxDist << "\t"<< _len << "\t" << duration_Enc_HD2_Sum / Num_tests << "\t"
            << duration_CondEnc_HD2_Sum / Num_tests << "\t"
            << duration_CondDec_HD2_Sum / Num_tests << "\t"
            << CondCtxSize << "\t"
            << TradCtxSize << "\n";

    CondEncHD2 << "Average Enc, CondEnc, CondDec, CtxtSize: " <<
               duration_Enc_HD2_Sum / Num_tests
               << ", " <<  duration_CondEnc_HD2_Sum / Num_tests
               << ", " <<  duration_CondDec_HD2_Sum / Num_tests << ") \n";

    CondEncHD2.close();
    paillier_freepubkey(pkobj._ppk);
    paillier_freeprvkey(pkobj._psk);
    cout << "Hamming Distant  at most Three [Threshold =_len -3, _len = 16] is finished \n";
}

TEST_CASE("Conditional Encryption: Hamming Distance at most Three [Threshold len-3, len =32] predicate")
{
    PwPkCrypto pkobj;
    pkobj.Paill_pk_init(1024);
    int Num_tests = 5;
    size_t _len = 32;
    int Threshold = _len - 3;

    string msg = "TheTestingPlainText";


    string msg_pad = CryptoSymWrapperFunctions::Wrapper_pad(msg, _len);
    int sizechar = sizeof(size_t);

    size_t TradCtxSize = 2 * sizeof(size_t) + _len *  PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2;
    size_t CondCtxSize = 3 * sizeof(size_t) + (sizeof(char) * 24) + (_len *  256);
    double duration_CondEnc_HD2_Sum = 0;
    double duration_Enc_HD2_Sum = 0;
    double duration_CondDec_HD2_Sum = 0;

    ofstream CondEncHD2;
    CondEncHD2.open("CondEncHDAtmostThreeLen32.txt");
    CondEncHD2 << "The predicate is Hamming distance at most two [3 errors as wors case]******************\n \n ";

    for(int T = 0; T< Num_tests; T++) {
        char HD2_Char_ORigCTx [2 * sizeof(size_t) + _len *  PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2];
        char HD2_ctx_typo_Bytes[3 * sizeof(size_t) + (sizeof(char) * 24) + (_len *  256)];
        string typo =msg;
        string payload;

        /*Randomly making typo and the payload*/
        unsigned seed= time(0);
        int NumOfErrs = 0;
        char err1, err2, err3, err4;
        srand(seed);
        NumOfErrs = 4;
//        NumOfErrs =rand() % 4;
        if (NumOfErrs == 1)
        {
            err1 = 32 + (rand() % 95);
            int ErrLction;
            ErrLction = rand() % (msg.size());
            typo[ErrLction] = err1;
        } else if (NumOfErrs == 2)
        {
            err1 = 32 + (rand() % 95);
            err2 = 32 + (rand() % 95);
            int ErrLction1, ErrLction2;
            ErrLction1 = rand() % msg.size();
            ErrLction2 = rand() % msg.size();
            typo[ErrLction1] = err1;
            typo[ErrLction2] = err2;
        } else if (NumOfErrs == 4)
        {
            err1 = 32 + (rand() % 95);
            err2 = 32 + (rand() % 95);
            err3 = 32 + (rand() % 95);
            err4 = 32 + (rand() % 95);
            int ErrLction1, ErrLction2, ErrLction3, ErrLction4;
            ErrLction1 = rand() % msg.size();
            ErrLction2 = rand() % msg.size();
            ErrLction3 = rand() % msg.size();
            ErrLction4 = rand() % msg.size();
            typo[ErrLction1] = err1;
            typo[ErrLction2] = err2;
            typo[ErrLction3] = err3;
            typo[ErrLction4] = err4;
        }
        payload = typo;
        string pad_typo = CryptoSymWrapperFunctions::Wrapper_pad(typo, _len);


        /* ============ */

        auto start_Enc_HD2 = high_resolution_clock::now();
        int tradEncRslt =0;
        tradEncRslt = HamDistTwo::Enc(pkobj._ppk, msg_pad, HD2_Char_ORigCTx);
        auto stop_Enc_HD2 = high_resolution_clock::now();
        auto duration_Enc_HD2 = duration_cast<milliseconds>(stop_Enc_HD2 - start_Enc_HD2);

        auto start_CondEnc_HD2 = high_resolution_clock::now();
        auto ctx_final = HamDistTwo::CondEnc(pkobj._ppk, HD2_Char_ORigCTx, typo, payload,_len, Threshold, HD2_ctx_typo_Bytes);
        auto stop_CondEnc_HD2 = high_resolution_clock::now();
        auto duration_CondEnc_HD2 = duration_cast<milliseconds>(stop_CondEnc_HD2 - start_CondEnc_HD2);

        auto start_CondDec_HD2 = high_resolution_clock::now();
        string recovered_hd2Bytes;
        int CondDecOut  = 0;
        CondDecOut = HamDistTwo::CondDec(pkobj._ppk, HD2_ctx_typo_Bytes, pkobj._psk, Threshold, recovered_hd2Bytes, _len, 28);
        auto stop_CondDec_HD2 = high_resolution_clock::now();
        auto duration_CondDec_HD2 = duration_cast<milliseconds>(stop_CondDec_HD2 - start_CondDec_HD2);
        CondEncHD2 << "Enc.Time, CondEnc.Time, Cond.Dec.Time, Ctx.Size, CondCtx.Size, CondDecRslt: (" <<
                   duration_Enc_HD2.count()
                   << ", " << duration_CondEnc_HD2.count()
                   << ", " << duration_CondDec_HD2.count()
                   << ", " << TradCtxSize
                   << ", " << CondCtxSize
                   << ", " << CondDecOut << " )\n";

        duration_Enc_HD2_Sum =  duration_Enc_HD2_Sum + duration_Enc_HD2.count();
        duration_CondEnc_HD2_Sum =  duration_CondEnc_HD2_Sum + duration_CondEnc_HD2.count();
        duration_CondDec_HD2_Sum =  duration_CondDec_HD2_Sum + duration_CondDec_HD2.count();

    }

    std::ofstream HDdataL("HDdataL_T3.dat", std::ios_base::app | std::ios_base::out);
    std::ofstream HDdataT("HDdataL32_T.dat", std::ios_base::app | std::ios_base::out);

    int MaxDist  = _len - Threshold;

    HDdataT << MaxDist << "\t"<< _len << "\t" << duration_Enc_HD2_Sum / Num_tests << "\t"
            << duration_CondEnc_HD2_Sum / Num_tests << "\t"
            << duration_CondDec_HD2_Sum / Num_tests << "\t"
            << CondCtxSize << "\t"
            << TradCtxSize << "\n";



    HDdataL << MaxDist << "\t"<< _len << "\t" << duration_Enc_HD2_Sum / Num_tests << "\t"
            << duration_CondEnc_HD2_Sum / Num_tests << "\t"
            << duration_CondDec_HD2_Sum / Num_tests << "\t"
            << CondCtxSize << "\t"
            << TradCtxSize << "\n";

    CondEncHD2 << "Average Enc, CondEnc, CondDec, CtxtSize: " <<
               duration_Enc_HD2_Sum / Num_tests
               << ", " <<  duration_CondEnc_HD2_Sum / Num_tests
               << ", " <<  duration_CondDec_HD2_Sum / Num_tests << ") \n";

    CondEncHD2.close();
    paillier_freepubkey(pkobj._ppk);
    paillier_freeprvkey(pkobj._psk);
    cout << "Hamming Distant  at most Three [Threshold =_len -3, _len = 32] is finished \n";
}

TEST_CASE("Conditional Encryption: Hamming Distance at most Three [Threshold len-3, len =64] predicate")
{
    PwPkCrypto pkobj;
    pkobj.Paill_pk_init(1024);
    int Num_tests = 5;
    size_t _len = 64;
    int Threshold = _len - 3;

    string msg = "TheTestingPlainText";


    string msg_pad = CryptoSymWrapperFunctions::Wrapper_pad(msg, _len);
    int sizechar = sizeof(size_t);
    size_t TradCtxSize = 2 * sizeof(size_t) + _len *  PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2;
    size_t CondCtxSize = 3 * sizeof(size_t) + (sizeof(char) * 24) + (_len *  256);
    double duration_CondEnc_HD2_Sum = 0;
    double duration_Enc_HD2_Sum = 0;
    double duration_CondDec_HD2_Sum = 0;
    ofstream CondEncHD2;
    CondEncHD2.open("CondEncHDAtmostThreeLen64.txt");
    CondEncHD2 << "The predicate is Hamming distance at most two [3 errors as wors case]******************\n \n ";

    for(int T = 0; T< Num_tests; T++) {
        char HD2_Char_ORigCTx [2 * sizeof(size_t) + _len *  PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2];
        char HD2_ctx_typo_Bytes[3 * sizeof(size_t) + (sizeof(char) * 24) + (_len *  256)];
        string typo =msg;
        string payload;

        /*Randomly making typo and the payload*/
        unsigned seed= time(0);
        int NumOfErrs = 0;
        char err1, err2, err3, err4;
        srand(seed);
        NumOfErrs = 4;
//        NumOfErrs =rand() % 4;
        if (NumOfErrs == 1)
        {
            err1 = 32 + (rand() % 95);
            int ErrLction;
            ErrLction = rand() % (msg.size());
            typo[ErrLction] = err1;
        } else if (NumOfErrs == 2)
        {
            err1 = 32 + (rand() % 95);
            err2 = 32 + (rand() % 95);
            int ErrLction1, ErrLction2;
            ErrLction1 = rand() % msg.size();
            ErrLction2 = rand() % msg.size();
            typo[ErrLction1] = err1;
            typo[ErrLction2] = err2;
        } else if (NumOfErrs == 4)
        {
            err1 = 32 + (rand() % 95);
            err2 = 32 + (rand() % 95);
            err3 = 32 + (rand() % 95);
            err4 = 32 + (rand() % 95);
            int ErrLction1, ErrLction2, ErrLction3, ErrLction4;
            ErrLction1 = rand() % msg.size();
            ErrLction2 = rand() % msg.size();
            ErrLction3 = rand() % msg.size();
            ErrLction4 = rand() % msg.size();
            typo[ErrLction1] = err1;
            typo[ErrLction2] = err2;
            typo[ErrLction3] = err3;
            typo[ErrLction4] = err4;
        }
        payload = typo;
        string pad_typo = CryptoSymWrapperFunctions::Wrapper_pad(typo, _len);


        /* ============ */

        auto start_Enc_HD2 = high_resolution_clock::now();
        int tradEncRslt =0;
        tradEncRslt = HamDistTwo::Enc(pkobj._ppk, msg_pad, HD2_Char_ORigCTx);
        auto stop_Enc_HD2 = high_resolution_clock::now();
        auto duration_Enc_HD2 = duration_cast<milliseconds>(stop_Enc_HD2 - start_Enc_HD2);

        auto start_CondEnc_HD2 = high_resolution_clock::now();
//        char* CondEncRst = new char[3 * sizeof(size_t) + (sizeof(char) * 24) + (32 *  256) + 1];
//        memset(HD2_ctx_typo_Bytes, '\0', CondCtxSize);
        auto ctx_final = HamDistTwo::CondEnc(pkobj._ppk, HD2_Char_ORigCTx, typo, payload,_len, Threshold, HD2_ctx_typo_Bytes);
//        std::string* CtxtAEStrPre = (std::string*) malloc(sizeof(char) * 24);
//        std::string s;
//        memcpy(HD2_ctx_typo_Bytes + (3 * sizeof(size_t)), &ctx_final, sizeof(char) * 24);

//        std::string* CtxtAEStrPre = (std::string*) malloc(24);
//        memcpy(&CtxtAEStrPre[0], HD2_ctx_typo_Bytes + 3 * sizeof(size_t), 24 );

        auto stop_CondEnc_HD2 = high_resolution_clock::now();
        auto duration_CondEnc_HD2 = duration_cast<milliseconds>(stop_CondEnc_HD2 - start_CondEnc_HD2);

        auto start_CondDec_HD2 = high_resolution_clock::now();
        string recovered_hd2Bytes;
        int CondDecOut  = 0;
//        while (CondDecOut != 1)
//        {
        CondDecOut = HamDistTwo::CondDec(pkobj._ppk, HD2_ctx_typo_Bytes, pkobj._psk, Threshold, recovered_hd2Bytes, _len, 28);
//        }
        auto stop_CondDec_HD2 = high_resolution_clock::now();
        auto duration_CondDec_HD2 = duration_cast<milliseconds>(stop_CondDec_HD2 - start_CondDec_HD2);
        CondEncHD2 << "Enc.Time, CondEnc.Time, Cond.Dec.Time, Ctx.Size, CondCtx.Size, CondDecRslt: (" <<
                   duration_Enc_HD2.count()
                   << ", " << duration_CondEnc_HD2.count()
                   << ", " << duration_CondDec_HD2.count()
                   << ", " << TradCtxSize
                   << ", " << CondCtxSize
                   << ", " << CondDecOut << " )\n";

        duration_Enc_HD2_Sum =  duration_Enc_HD2_Sum + duration_Enc_HD2.count();
        duration_CondEnc_HD2_Sum =  duration_CondEnc_HD2_Sum + duration_CondEnc_HD2.count();
        duration_CondDec_HD2_Sum =  duration_CondDec_HD2_Sum + duration_CondDec_HD2.count();

    }

    std::ofstream HDdataL("HDdataL_T3.dat", std::ios_base::app | std::ios_base::out);
    std::ofstream HDdataT("HDdataL64_T.dat", std::ios_base::app | std::ios_base::out);

    int MaxDist  = _len - Threshold;

    HDdataT << MaxDist << "\t"<< _len << "\t" << duration_Enc_HD2_Sum / Num_tests << "\t"
            << duration_CondEnc_HD2_Sum / Num_tests << "\t"
            << duration_CondDec_HD2_Sum / Num_tests << "\t"
            << CondCtxSize << "\t"
            << TradCtxSize << "\n";



    HDdataL << MaxDist << "\t"<< _len << "\t" << duration_Enc_HD2_Sum / Num_tests << "\t"
            << duration_CondEnc_HD2_Sum / Num_tests << "\t"
            << duration_CondDec_HD2_Sum / Num_tests << "\t"
            << CondCtxSize << "\t"
            << TradCtxSize << "\n";

    CondEncHD2 << "Average Enc, CondEnc, CondDec, CtxtSize: " <<
               duration_Enc_HD2_Sum / Num_tests
               << ", " <<  duration_CondEnc_HD2_Sum / Num_tests
               << ", " <<  duration_CondDec_HD2_Sum / Num_tests << ") \n";

    CondEncHD2.close();
    paillier_freepubkey(pkobj._ppk);
    paillier_freeprvkey(pkobj._psk);
    cout << "Hamming Distant  at most Three [Threshold =_len -3, _len = 64] is finished \n";
}

TEST_CASE("Conditional Encryption: Hamming Distance at most Three [Threshold len-3, len =128] predicate")
{
    PwPkCrypto pkobj;
    pkobj.Paill_pk_init(1024);
    int Num_tests = 1;
    size_t _len = 128;
    int Threshold = _len - 3;

    string msg = "TheTestingPlainText";


    string msg_pad = CryptoSymWrapperFunctions::Wrapper_pad(msg, _len);
    int sizechar = sizeof(size_t);

    size_t TradCtxSize = 2 * sizeof(size_t) + _len *  PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2;
    size_t CondCtxSize = 3 * sizeof(size_t) + (sizeof(char) * 24) + (_len *  256);

    double duration_CondEnc_HD2_Sum = 0;
    double duration_Enc_HD2_Sum = 0;
    double duration_CondDec_HD2_Sum = 0;

    ofstream CondEncHD2;
    CondEncHD2.open("CondEncHDAtmostThreeLen128.txt");
    CondEncHD2 << "The predicate is Hamming distance at most two [3 errors as wors case]******************\n \n ";

    for(int T = 0; T< Num_tests; T++) {
        char HD2_Char_ORigCTx [2 * sizeof(size_t) + _len *  PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2];
        char HD2_ctx_typo_Bytes[3 * sizeof(size_t) + (sizeof(char) * 24) + (_len *  256)];
        string typo =msg;
        string payload;

        /*Randomly making typo and the payload*/
        unsigned seed= time(0);
        int NumOfErrs = 0;
        char err1, err2, err3, err4;
        srand(seed);
        NumOfErrs = 4;
//        NumOfErrs =rand() % 4;
        if (NumOfErrs == 1)
        {
            err1 = 32 + (rand() % 95);
            int ErrLction;
            ErrLction = rand() % (msg.size());
            typo[ErrLction] = err1;
        } else if (NumOfErrs == 2)
        {
            err1 = 32 + (rand() % 95);
            err2 = 32 + (rand() % 95);
            int ErrLction1, ErrLction2;
            ErrLction1 = rand() % msg.size();
            ErrLction2 = rand() % msg.size();
            typo[ErrLction1] = err1;
            typo[ErrLction2] = err2;
        } else if (NumOfErrs == 4)
        {
            err1 = 32 + (rand() % 95);
            err2 = 32 + (rand() % 95);
            err3 = 32 + (rand() % 95);
            err4 = 32 + (rand() % 95);
            int ErrLction1, ErrLction2, ErrLction3, ErrLction4;
            ErrLction1 = rand() % msg.size();
            ErrLction2 = rand() % msg.size();
            ErrLction3 = rand() % msg.size();
            ErrLction4 = rand() % msg.size();
            typo[ErrLction1] = err1;
            typo[ErrLction2] = err2;
            typo[ErrLction3] = err3;
            typo[ErrLction4] = err4;
        }
        payload = typo;
        string pad_typo = CryptoSymWrapperFunctions::Wrapper_pad(typo, _len);


        /* ============ */

        auto start_Enc_HD2 = high_resolution_clock::now();
        int tradEncRslt =0;
        tradEncRslt = HamDistTwo::Enc(pkobj._ppk, msg_pad, HD2_Char_ORigCTx);
        auto stop_Enc_HD2 = high_resolution_clock::now();
        auto duration_Enc_HD2 = duration_cast<milliseconds>(stop_Enc_HD2 - start_Enc_HD2);

        auto start_CondEnc_HD2 = high_resolution_clock::now();
        auto ctx_final = HamDistTwo::CondEnc(pkobj._ppk, HD2_Char_ORigCTx, typo, payload,_len, Threshold, HD2_ctx_typo_Bytes);
        auto stop_CondEnc_HD2 = high_resolution_clock::now();
        auto duration_CondEnc_HD2 = duration_cast<milliseconds>(stop_CondEnc_HD2 - start_CondEnc_HD2);

        auto start_CondDec_HD2 = high_resolution_clock::now();
        string recovered_hd2Bytes;
        int CondDecOut  = 0;
//        CondDecOut = HamDistTwo::CondDec(pkobj._ppk, HD2_ctx_typo_Bytes, pkobj._psk, Threshold, recovered_hd2Bytes, _len, 28);
        CondDecOut = HamDistTwo::CondDec_Optimized(pkobj._ppk, HD2_ctx_typo_Bytes, pkobj._psk, Threshold, recovered_hd2Bytes, _len, 28, 19);
        auto stop_CondDec_HD2 = high_resolution_clock::now();
        auto duration_CondDec_HD2 = duration_cast<milliseconds>(stop_CondDec_HD2 - start_CondDec_HD2);
        CondEncHD2 << "Enc.Time, CondEnc.Time, Cond.Dec.Time, Ctx.Size, CondCtx.Size, CondDecRslt: (" <<
                   duration_Enc_HD2.count()
                   << ", " << duration_CondEnc_HD2.count()
                   << ", " << duration_CondDec_HD2.count()
                   << ", " << TradCtxSize
                   << ", " << CondCtxSize
                   << ", " << CondDecOut << " )\n";

        duration_Enc_HD2_Sum =  duration_Enc_HD2_Sum + duration_Enc_HD2.count();
        duration_CondEnc_HD2_Sum =  duration_CondEnc_HD2_Sum + duration_CondEnc_HD2.count();
        duration_CondDec_HD2_Sum =  duration_CondDec_HD2_Sum + duration_CondDec_HD2.count();

    }

    std::ofstream HDdataL("HDdataL_T3.dat", std::ios_base::app | std::ios_base::out);
    std::ofstream HDdataT("HDdataL128_T.dat", std::ios_base::app | std::ios_base::out);

    int MaxDist  = _len - Threshold;

    HDdataT << MaxDist << "\t"<< _len << "\t" << duration_Enc_HD2_Sum / Num_tests << "\t"
            << duration_CondEnc_HD2_Sum / Num_tests << "\t"
            << duration_CondDec_HD2_Sum / Num_tests << "\t"
            << CondCtxSize << "\t"
            << TradCtxSize << "\n";

    HDdataL << MaxDist << "\t"<< _len << "\t" << duration_Enc_HD2_Sum / Num_tests << "\t"
            << duration_CondEnc_HD2_Sum / Num_tests << "\t"
            << duration_CondDec_HD2_Sum / Num_tests << "\t"
            << CondCtxSize << "\t"
            << TradCtxSize << "\n";

    CondEncHD2 << "Average Enc, CondEnc, CondDec, CtxtSize: " <<
               duration_Enc_HD2_Sum / Num_tests
               << ", " <<  duration_CondEnc_HD2_Sum / Num_tests
               << ", " <<  duration_CondDec_HD2_Sum / Num_tests << ") \n";

    CondEncHD2.close();
    paillier_freepubkey(pkobj._ppk);
    paillier_freeprvkey(pkobj._psk);
    cout << "Hamming Distant  at most Three [Threshold =_len -3, _len = 128] is finished \n";
}

TEST_CASE("Conditional Encryption: Hamming Distance at most Four [Threshold len-4, len =8] predicate")
{
    PwPkCrypto pkobj;
    pkobj.Paill_pk_init(1024);
    int Num_tests = 5;
    size_t _len = 8;
    int Threshold = _len - 4;

    string msg = "Test";


    string msg_pad = CryptoSymWrapperFunctions::Wrapper_pad(msg, _len);
    int sizechar = sizeof(size_t);
    size_t TradCtxSize = 2 * sizeof(size_t) + _len *  PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2;
    size_t CondCtxSize = 3 * sizeof(size_t) + (sizeof(char) * 24) + (_len *  256);
    double duration_CondEnc_HD2_Sum = 0;
    double duration_Enc_HD2_Sum = 0;
    double duration_CondDec_HD2_Sum = 0;

    ofstream CondEncHD2;
    CondEncHD2.open("CondEncHDAtmostFourLen16.txt");
    CondEncHD2 << "The predicate is Hamming distance at most two [3 errors as wors case]******************\n \n ";

    for(int T = 0; T< Num_tests; T++) {
        char HD2_Char_ORigCTx [2 * sizeof(size_t) + _len *  PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2];
        char HD2_ctx_typo_Bytes[3 * sizeof(size_t) + (sizeof(char) * 24) + (_len *  256)];
        string typo =msg;
        string payload;

        /*Randomly making typo and the payload*/
        unsigned seed= time(0);
        int NumOfErrs = 0;
        char err1, err2, err3, err4, err5;
        srand(seed);
        NumOfErrs = 5;
//        NumOfErrs =rand() % 4;
        if (NumOfErrs == 1)
        {
            err1 = 32 + (rand() % 95);
            int ErrLction;
            ErrLction = rand() % (msg.size());
            typo[ErrLction] = err1;
        } else if (NumOfErrs == 2)
        {
            err1 = 32 + (rand() % 95);
            err2 = 32 + (rand() % 95);
            int ErrLction1, ErrLction2;
            ErrLction1 = rand() % msg.size();
            ErrLction2 = rand() % msg.size();
            typo[ErrLction1] = err1;
            typo[ErrLction2] = err2;
        } else if (NumOfErrs == 5)
        {
            err1 = 32 + (rand() % 95);
            err2 = 32 + (rand() % 95);
            err3 = 32 + (rand() % 95);
            err4 = 32 + (rand() % 95);
            err5 = 32 + (rand() % 95);
            int ErrLction1, ErrLction2, ErrLction3, ErrLction4, ErrLction5;
            ErrLction1 = rand() % msg.size();
            ErrLction2 = rand() % msg.size();
            ErrLction3 = rand() % msg.size();
            ErrLction4 = rand() % msg.size();
            ErrLction5 = rand() % msg.size();
            typo[ErrLction1] = err1;
            typo[ErrLction2] = err2;
            typo[ErrLction3] = err3;
            typo[ErrLction4] = err4;
            typo[ErrLction5] = err5;
        }
        payload = typo;
        string pad_typo = CryptoSymWrapperFunctions::Wrapper_pad(typo, _len);


        /* ============ */

        auto start_Enc_HD2 = high_resolution_clock::now();
        int tradEncRslt =0;
        tradEncRslt = HamDistTwo::Enc(pkobj._ppk, msg_pad, HD2_Char_ORigCTx);
        auto stop_Enc_HD2 = high_resolution_clock::now();
        auto duration_Enc_HD2 = duration_cast<milliseconds>(stop_Enc_HD2 - start_Enc_HD2);

        auto start_CondEnc_HD2 = high_resolution_clock::now();
        auto ctx_final = HamDistTwo::CondEnc(pkobj._ppk, HD2_Char_ORigCTx, typo, payload,_len, Threshold, HD2_ctx_typo_Bytes);
        auto stop_CondEnc_HD2 = high_resolution_clock::now();
        auto duration_CondEnc_HD2 = duration_cast<milliseconds>(stop_CondEnc_HD2 - start_CondEnc_HD2);

        auto start_CondDec_HD2 = high_resolution_clock::now();
        string recovered_hd2Bytes;
        int CondDecOut  = 0;
        CondDecOut = HamDistTwo::CondDec(pkobj._ppk, HD2_ctx_typo_Bytes, pkobj._psk, Threshold, recovered_hd2Bytes, _len, 28);
        auto stop_CondDec_HD2 = high_resolution_clock::now();
        auto duration_CondDec_HD2 = duration_cast<milliseconds>(stop_CondDec_HD2 - start_CondDec_HD2);

        CondEncHD2 << "Enc.Time, CondEnc.Time, Cond.Dec.Time, Ctx.Size, CondCtx.Size, CondDecRslt: (" <<
                   duration_Enc_HD2.count()
                   << ", " << duration_CondEnc_HD2.count()
                   << ", " << duration_CondDec_HD2.count()
                   << ", " << TradCtxSize
                   << ", " << CondCtxSize
                   << ", " << CondDecOut << " )\n";

        duration_Enc_HD2_Sum =  duration_Enc_HD2_Sum + duration_Enc_HD2.count();
        duration_CondEnc_HD2_Sum =  duration_CondEnc_HD2_Sum + duration_CondEnc_HD2.count();
        duration_CondDec_HD2_Sum =  duration_CondDec_HD2_Sum + duration_CondDec_HD2.count();

    }

    std::ofstream HDdataL("HDdataL_T4.dat", std::ios_base::app | std::ios_base::out);
    std::ofstream HDdataT("HDdataL8_T.dat", std::ios_base::app | std::ios_base::out);

    HDdataL << "T\tL\t" << "Enc\tCondEnc\tCondDec\tCondCtxtSize\tCondCtxtSize\n";

    int MaxDist  = _len - Threshold;

    HDdataT << MaxDist << "\t"<< _len << "\t" << duration_Enc_HD2_Sum / Num_tests << "\t"
            << duration_CondEnc_HD2_Sum / Num_tests << "\t"
            << duration_CondDec_HD2_Sum / Num_tests << "\t"
            << CondCtxSize << "\t"
            << TradCtxSize << "\n";


    HDdataL << MaxDist << "\t"<< _len << "\t" << duration_Enc_HD2_Sum / Num_tests << "\t"
            << duration_CondEnc_HD2_Sum / Num_tests << "\t"
            << duration_CondDec_HD2_Sum / Num_tests << "\t"
            << CondCtxSize << "\t"
            << TradCtxSize << "\n";

    CondEncHD2 << "Average Enc, CondEnc, CondDec, CtxtSize: " <<
               duration_Enc_HD2_Sum / Num_tests
               << ", " <<  duration_CondEnc_HD2_Sum / Num_tests
               << ", " <<  duration_CondDec_HD2_Sum / Num_tests << ") \n";

    CondEncHD2.close();
    paillier_freepubkey(pkobj._ppk);
    paillier_freeprvkey(pkobj._psk);
    cout << "Hamming Distant  at most Four [Threshold =_len -4, _len = 8] is finished \n";
}

TEST_CASE("Conditional Encryption: Hamming Distance at most Four [Threshold len-4, len =16] predicate")
{
    PwPkCrypto pkobj;
    pkobj.Paill_pk_init(1024);
    int Num_tests = 5;
    size_t _len = 16;
    int Threshold = _len - 4;

    string msg = "Test";


    string msg_pad = CryptoSymWrapperFunctions::Wrapper_pad(msg, _len);
    int sizechar = sizeof(size_t);
    size_t TradCtxSize = 2 * sizeof(size_t) + _len *  PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2;
    size_t CondCtxSize = 3 * sizeof(size_t) + (sizeof(char) * 24) + (_len *  256);
    double duration_CondEnc_HD2_Sum = 0;
    double duration_Enc_HD2_Sum = 0;
    double duration_CondDec_HD2_Sum = 0;

    ofstream CondEncHD2;
    CondEncHD2.open("CondEncHDAtmostFourLen16.txt");
    CondEncHD2 << "The predicate is Hamming distance at most two [3 errors as wors case]******************\n \n ";

    for(int T = 0; T< Num_tests; T++) {
        char HD2_Char_ORigCTx [2 * sizeof(size_t) + _len *  PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2];
        char HD2_ctx_typo_Bytes[3 * sizeof(size_t) + (sizeof(char) * 24) + (_len *  256)];
        string typo =msg;
        string payload;

        /*Randomly making typo and the payload*/
        unsigned seed= time(0);
        int NumOfErrs = 0;
        char err1, err2, err3, err4, err5;
        srand(seed);
        NumOfErrs = 5;
//        NumOfErrs =rand() % 4;
        if (NumOfErrs == 1)
        {
            err1 = 32 + (rand() % 95);
            int ErrLction;
            ErrLction = rand() % (msg.size());
            typo[ErrLction] = err1;
        } else if (NumOfErrs == 2)
        {
            err1 = 32 + (rand() % 95);
            err2 = 32 + (rand() % 95);
            int ErrLction1, ErrLction2;
            ErrLction1 = rand() % msg.size();
            ErrLction2 = rand() % msg.size();
            typo[ErrLction1] = err1;
            typo[ErrLction2] = err2;
        } else if (NumOfErrs == 5)
        {
            err1 = 32 + (rand() % 95);
            err2 = 32 + (rand() % 95);
            err3 = 32 + (rand() % 95);
            err4 = 32 + (rand() % 95);
            err5 = 32 + (rand() % 95);
            int ErrLction1, ErrLction2, ErrLction3, ErrLction4, ErrLction5;
            ErrLction1 = rand() % msg.size();
            ErrLction2 = rand() % msg.size();
            ErrLction3 = rand() % msg.size();
            ErrLction4 = rand() % msg.size();
            ErrLction5 = rand() % msg.size();
            typo[ErrLction1] = err1;
            typo[ErrLction2] = err2;
            typo[ErrLction3] = err3;
            typo[ErrLction4] = err4;
            typo[ErrLction5] = err5;
        }
        payload = typo;
        string pad_typo = CryptoSymWrapperFunctions::Wrapper_pad(typo, _len);


        /* ============ */

        auto start_Enc_HD2 = high_resolution_clock::now();
        int tradEncRslt =0;
        tradEncRslt = HamDistTwo::Enc(pkobj._ppk, msg_pad, HD2_Char_ORigCTx);
        auto stop_Enc_HD2 = high_resolution_clock::now();
        auto duration_Enc_HD2 = duration_cast<milliseconds>(stop_Enc_HD2 - start_Enc_HD2);

        auto start_CondEnc_HD2 = high_resolution_clock::now();
        auto ctx_final = HamDistTwo::CondEnc(pkobj._ppk, HD2_Char_ORigCTx, typo, payload,_len, Threshold, HD2_ctx_typo_Bytes);
        auto stop_CondEnc_HD2 = high_resolution_clock::now();
        auto duration_CondEnc_HD2 = duration_cast<milliseconds>(stop_CondEnc_HD2 - start_CondEnc_HD2);

        auto start_CondDec_HD2 = high_resolution_clock::now();
        string recovered_hd2Bytes;
        int CondDecOut  = 0;

        CondDecOut = HamDistTwo::CondDec(pkobj._ppk, HD2_ctx_typo_Bytes, pkobj._psk, Threshold, recovered_hd2Bytes, _len, 28);

        auto stop_CondDec_HD2 = high_resolution_clock::now();
        auto duration_CondDec_HD2 = duration_cast<milliseconds>(stop_CondDec_HD2 - start_CondDec_HD2);

        CondEncHD2 << "Enc.Time, CondEnc.Time, Cond.Dec.Time, Ctx.Size, CondCtx.Size, CondDecRslt: (" <<
                   duration_Enc_HD2.count()
                   << ", " << duration_CondEnc_HD2.count()
                   << ", " << duration_CondDec_HD2.count()
                   << ", " << TradCtxSize
                   << ", " << CondCtxSize
                   << ", " << CondDecOut << " )\n";

        duration_Enc_HD2_Sum =  duration_Enc_HD2_Sum + duration_Enc_HD2.count();
        duration_CondEnc_HD2_Sum =  duration_CondEnc_HD2_Sum + duration_CondEnc_HD2.count();
        duration_CondDec_HD2_Sum =  duration_CondDec_HD2_Sum + duration_CondDec_HD2.count();

    }

    std::ofstream HDdataL("HDdataL_T4.dat", std::ios_base::app | std::ios_base::out);
    std::ofstream HDdataT("HDdataL16_T.dat", std::ios_base::app | std::ios_base::out);

    int MaxDist  = _len - Threshold;

    HDdataT << MaxDist << "\t"<< _len << "\t" << duration_Enc_HD2_Sum / Num_tests << "\t"
            << duration_CondEnc_HD2_Sum / Num_tests << "\t"
            << duration_CondDec_HD2_Sum / Num_tests << "\t"
            << CondCtxSize << "\t"
            << TradCtxSize << "\n";



    HDdataL << MaxDist << "\t"<< _len << "\t" << duration_Enc_HD2_Sum / Num_tests << "\t"
            << duration_CondEnc_HD2_Sum / Num_tests << "\t"
            << duration_CondDec_HD2_Sum / Num_tests << "\t"
            << CondCtxSize << "\t"
            << TradCtxSize << "\n";

    CondEncHD2 << "Average Enc, CondEnc, CondDec, CtxtSize: " <<
               duration_Enc_HD2_Sum / Num_tests
               << ", " <<  duration_CondEnc_HD2_Sum / Num_tests
               << ", " <<  duration_CondDec_HD2_Sum / Num_tests << ") \n";

    CondEncHD2.close();
    paillier_freepubkey(pkobj._ppk);
    paillier_freeprvkey(pkobj._psk);
    cout << "Hamming Distant  at most Four [Threshold =_len -4, _len = 16] is finished \n";
}

TEST_CASE("Conditional Encryption: Hamming Distance at most Four [Threshold len-4, len =32] predicate")
{
    PwPkCrypto pkobj;
    pkobj.Paill_pk_init(1024);
    int Num_tests = 5;
    size_t _len = 32;
    int Threshold = _len - 4;

    string msg = "TheTestingPlainText";


    string msg_pad = CryptoSymWrapperFunctions::Wrapper_pad(msg, _len);
    int sizechar = sizeof(size_t);
    size_t TradCtxSize = 2 * sizeof(size_t) + _len *  PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2;
    size_t CondCtxSize = 3 * sizeof(size_t) + (sizeof(char) * 24) + (_len *  256);

    double duration_CondEnc_HD2_Sum = 0;
    double duration_Enc_HD2_Sum = 0;
    double duration_CondDec_HD2_Sum = 0;

    ofstream CondEncHD2;
    CondEncHD2.open("CondEncHDAtmostFourLen32.txt");
    CondEncHD2 << "The predicate is Hamming distance at most two [3 errors as wors case]******************\n \n ";

    for(int T = 0; T< Num_tests; T++) {
        char HD2_Char_ORigCTx [2 * sizeof(size_t) + _len *  PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2];
        char HD2_ctx_typo_Bytes[3 * sizeof(size_t) + (sizeof(char) * 24) + (_len *  256)];
        string typo =msg;
        string payload;

        /*Randomly making typo and the payload*/
        unsigned seed= time(0);
        int NumOfErrs = 0;
        char err1, err2, err3, err4, err5;
        srand(seed);
        NumOfErrs = 5;
//        NumOfErrs =rand() % 4;
        if (NumOfErrs == 1)
        {
            err1 = 32 + (rand() % 95);
            int ErrLction;
            ErrLction = rand() % (msg.size());
            typo[ErrLction] = err1;
        } else if (NumOfErrs == 2)
        {
            err1 = 32 + (rand() % 95);
            err2 = 32 + (rand() % 95);
            int ErrLction1, ErrLction2;
            ErrLction1 = rand() % msg.size();
            ErrLction2 = rand() % msg.size();
            typo[ErrLction1] = err1;
            typo[ErrLction2] = err2;
        } else if (NumOfErrs == 5)
        {
            err1 = 32 + (rand() % 95);
            err2 = 32 + (rand() % 95);
            err3 = 32 + (rand() % 95);
            err4 = 32 + (rand() % 95);
            err5 = 32 + (rand() % 95);
            int ErrLction1, ErrLction2, ErrLction3, ErrLction4, ErrLction5;
            ErrLction1 = rand() % msg.size();
            ErrLction2 = rand() % msg.size();
            ErrLction3 = rand() % msg.size();
            ErrLction4 = rand() % msg.size();
            ErrLction5 = rand() % msg.size();
            typo[ErrLction1] = err1;
            typo[ErrLction2] = err2;
            typo[ErrLction3] = err3;
            typo[ErrLction4] = err4;
            typo[ErrLction5] = err5;
        }
        payload = typo;
        string pad_typo = CryptoSymWrapperFunctions::Wrapper_pad(typo, _len);


        /* ============ */

        auto start_Enc_HD2 = high_resolution_clock::now();
        int tradEncRslt =0;
        tradEncRslt = HamDistTwo::Enc(pkobj._ppk, msg_pad, HD2_Char_ORigCTx);
        auto stop_Enc_HD2 = high_resolution_clock::now();
        auto duration_Enc_HD2 = duration_cast<milliseconds>(stop_Enc_HD2 - start_Enc_HD2);

        auto start_CondEnc_HD2 = high_resolution_clock::now();
//        char* CondEncRst = new char[3 * sizeof(size_t) + (sizeof(char) * 24) + (32 *  256) + 1];
//        memset(HD2_ctx_typo_Bytes, '\0', CondCtxSize);
        auto ctx_final = HamDistTwo::CondEnc(pkobj._ppk, HD2_Char_ORigCTx, typo, payload,_len, Threshold, HD2_ctx_typo_Bytes);

        auto stop_CondEnc_HD2 = high_resolution_clock::now();
        auto duration_CondEnc_HD2 = duration_cast<milliseconds>(stop_CondEnc_HD2 - start_CondEnc_HD2);

        auto start_CondDec_HD2 = high_resolution_clock::now();
        string recovered_hd2Bytes;
        int CondDecOut  = 0;
//        while (CondDecOut != 1)
//        {
        CondDecOut = HamDistTwo::CondDec(pkobj._ppk, HD2_ctx_typo_Bytes, pkobj._psk, Threshold, recovered_hd2Bytes, _len, 28);
//        }
        auto stop_CondDec_HD2 = high_resolution_clock::now();
        auto duration_CondDec_HD2 = duration_cast<milliseconds>(stop_CondDec_HD2 - start_CondDec_HD2);

        CondEncHD2 << "Enc.Time, CondEnc.Time, Cond.Dec.Time, Ctx.Size, CondCtx.Size, CondDecRslt: (" <<
                   duration_Enc_HD2.count()
                   << ", " << duration_CondEnc_HD2.count()
                   << ", " << duration_CondDec_HD2.count()
                   << ", " << TradCtxSize
                   << ", " << CondCtxSize
                   << ", " << CondDecOut << " )\n";

        duration_Enc_HD2_Sum =  duration_Enc_HD2_Sum + duration_Enc_HD2.count();
        duration_CondEnc_HD2_Sum =  duration_CondEnc_HD2_Sum + duration_CondEnc_HD2.count();
        duration_CondDec_HD2_Sum =  duration_CondDec_HD2_Sum + duration_CondDec_HD2.count();

    }

    std::ofstream HDdataL("HDdataL_T4.dat", std::ios_base::app | std::ios_base::out);
    std::ofstream HDdataT("HDdataL32_T.dat", std::ios_base::app | std::ios_base::out);

    HDdataL << "T\tL\t" << "Enc\tCondEnc\tCondDec\tCondCtxtSize\tCondCtxtSize\n";
    HDdataT << "T\tL\t" << "Enc\tCondEnc\tCondDec\tCondCtxtSize\tCondCtxtSize\n";
    int MaxDist  = _len - Threshold;

    HDdataT << MaxDist << "\t"<< _len << "\t" << duration_Enc_HD2_Sum / Num_tests << "\t"
            << duration_CondEnc_HD2_Sum / Num_tests << "\t"
            << duration_CondDec_HD2_Sum / Num_tests << "\t"
            << CondCtxSize << "\t"
            << TradCtxSize << "\n";



    HDdataL << MaxDist << "\t"<< _len << "\t" << duration_Enc_HD2_Sum / Num_tests << "\t"
            << duration_CondEnc_HD2_Sum / Num_tests << "\t"
            << duration_CondDec_HD2_Sum / Num_tests << "\t"
            << CondCtxSize << "\t"
            << TradCtxSize << "\n";

    CondEncHD2 << "Average Enc, CondEnc, CondDec, CtxtSize: " <<
               duration_Enc_HD2_Sum / Num_tests
               << ", " <<  duration_CondEnc_HD2_Sum / Num_tests
               << ", " <<  duration_CondDec_HD2_Sum / Num_tests << ") \n";

    CondEncHD2.close();
    paillier_freepubkey(pkobj._ppk);
    paillier_freeprvkey(pkobj._psk);
    cout << "Hamming Distant  at most Four [Threshold =_len -4, _len = 32] is finished \n";
}

TEST_CASE("Conditional Encryption: Hamming Distance at most Four [Threshold len-4, len =64] predicate")
{
    PwPkCrypto pkobj;
    pkobj.Paill_pk_init(1024);
    int Num_tests = 5;
    size_t _len = 64;
    int Threshold = _len - 4;

    string msg = "TheTestingPlainText";


    string msg_pad = CryptoSymWrapperFunctions::Wrapper_pad(msg, _len);
    int sizechar = sizeof(size_t);
    size_t TradCtxSize = 2 * sizeof(size_t) + _len *  PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2;
    size_t CondCtxSize = 3 * sizeof(size_t) + (sizeof(char) * 24) + (_len *  256);

    double duration_CondEnc_HD2_Sum = 0;
    double duration_Enc_HD2_Sum = 0;
    double duration_CondDec_HD2_Sum = 0;

    ofstream CondEncHD2;
    CondEncHD2.open("CondEncHDAtmostFourLen64.txt");
    CondEncHD2 << "The predicate is Hamming distance at most two [3 errors as wors case]******************\n \n ";

    for(int T = 0; T< Num_tests; T++) {
        char HD2_Char_ORigCTx [2 * sizeof(size_t) + _len *  PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2];
        char HD2_ctx_typo_Bytes[3 * sizeof(size_t) + (sizeof(char) * 24) + (_len *  256)];
        string typo =msg;
        string payload;

        /*Randomly making typo and the payload*/
        unsigned seed= time(0);
        int NumOfErrs = 0;
        char err1, err2, err3, err4, err5;
        srand(seed);
        NumOfErrs = 5;
//        NumOfErrs =rand() % 4;
        if (NumOfErrs == 1)
        {
            err1 = 32 + (rand() % 95);
            int ErrLction;
            ErrLction = rand() % (msg.size());
            typo[ErrLction] = err1;
        } else if (NumOfErrs == 2)
        {
            err1 = 32 + (rand() % 95);
            err2 = 32 + (rand() % 95);
            int ErrLction1, ErrLction2;
            ErrLction1 = rand() % msg.size();
            ErrLction2 = rand() % msg.size();
            typo[ErrLction1] = err1;
            typo[ErrLction2] = err2;
        } else if (NumOfErrs == 5)
        {
            err1 = 32 + (rand() % 95);
            err2 = 32 + (rand() % 95);
            err3 = 32 + (rand() % 95);
            err4 = 32 + (rand() % 95);
            err5 = 32 + (rand() % 95);
            int ErrLction1, ErrLction2, ErrLction3, ErrLction4, ErrLction5;
            ErrLction1 = rand() % msg.size();
            ErrLction2 = rand() % msg.size();
            ErrLction3 = rand() % msg.size();
            ErrLction4 = rand() % msg.size();
            ErrLction5 = rand() % msg.size();
            typo[ErrLction1] = err1;
            typo[ErrLction2] = err2;
            typo[ErrLction3] = err3;
            typo[ErrLction4] = err4;
            typo[ErrLction5] = err5;
        }
        payload = typo;
        string pad_typo = CryptoSymWrapperFunctions::Wrapper_pad(typo, _len);


        /* ============ */

        auto start_Enc_HD2 = high_resolution_clock::now();
        int tradEncRslt =0;
        tradEncRslt = HamDistTwo::Enc(pkobj._ppk, msg_pad, HD2_Char_ORigCTx);
        auto stop_Enc_HD2 = high_resolution_clock::now();
        auto duration_Enc_HD2 = duration_cast<milliseconds>(stop_Enc_HD2 - start_Enc_HD2);

        auto start_CondEnc_HD2 = high_resolution_clock::now();
        auto ctx_final = HamDistTwo::CondEnc(pkobj._ppk, HD2_Char_ORigCTx, typo, payload,_len, Threshold, HD2_ctx_typo_Bytes);
        auto stop_CondEnc_HD2 = high_resolution_clock::now();
        auto duration_CondEnc_HD2 = duration_cast<milliseconds>(stop_CondEnc_HD2 - start_CondEnc_HD2);

        auto start_CondDec_HD2 = high_resolution_clock::now();
        string recovered_hd2Bytes;
        int CondDecOut  = 0;
        CondDecOut = HamDistTwo::CondDec(pkobj._ppk, HD2_ctx_typo_Bytes, pkobj._psk, Threshold, recovered_hd2Bytes, _len, 28);

        auto stop_CondDec_HD2 = high_resolution_clock::now();
        auto duration_CondDec_HD2 = duration_cast<milliseconds>(stop_CondDec_HD2 - start_CondDec_HD2);
        CondEncHD2 << "Enc.Time, CondEnc.Time, Cond.Dec.Time, Ctx.Size, CondCtx.Size, CondDecRslt: (" <<
                   duration_Enc_HD2.count()
                   << ", " << duration_CondEnc_HD2.count()
                   << ", " << duration_CondDec_HD2.count()
                   << ", " << TradCtxSize
                   << ", " << CondCtxSize
                   << ", " << CondDecOut << " )\n";

        duration_Enc_HD2_Sum =  duration_Enc_HD2_Sum + duration_Enc_HD2.count();
        duration_CondEnc_HD2_Sum =  duration_CondEnc_HD2_Sum + duration_CondEnc_HD2.count();
        duration_CondDec_HD2_Sum =  duration_CondDec_HD2_Sum + duration_CondDec_HD2.count();

    }

    std::ofstream HDdataL("HDdataL_T4.dat", std::ios_base::app | std::ios_base::out);
    std::ofstream HDdataT("HDdataL64_T.dat", std::ios_base::app | std::ios_base::out);

    int MaxDist  = _len - Threshold;

    HDdataT << MaxDist << "\t"<< _len << "\t" << duration_Enc_HD2_Sum / Num_tests << "\t"
            << duration_CondEnc_HD2_Sum / Num_tests << "\t"
            << duration_CondDec_HD2_Sum / Num_tests << "\t"
            << CondCtxSize << "\t"
            << TradCtxSize << "\n";

    HDdataL << MaxDist << "\t"<< _len << "\t" << duration_Enc_HD2_Sum / Num_tests << "\t"
            << duration_CondEnc_HD2_Sum / Num_tests << "\t"
            << duration_CondDec_HD2_Sum / Num_tests << "\t"
            << CondCtxSize << "\t"
            << TradCtxSize << "\n";

    CondEncHD2 << "Average Enc, CondEnc, CondDec, CtxtSize: " <<
               duration_Enc_HD2_Sum / Num_tests
               << ", " <<  duration_CondEnc_HD2_Sum / Num_tests
               << ", " <<  duration_CondDec_HD2_Sum / Num_tests << ") \n";

    CondEncHD2.close();
    paillier_freepubkey(pkobj._ppk);
    paillier_freeprvkey(pkobj._psk);
    cout << "Hamming Distant  at most Four [Threshold =_len -4, _len = 64] is finished \n";
}

TEST_CASE("Conditional Encryption: Hamming Distance at most Four [Threshold len-4, len =128] predicate")
{
    PwPkCrypto pkobj;
    pkobj.Paill_pk_init(1024);
    int Num_tests = 1;
    size_t _len = 128;
    int Threshold = _len - 4;

    string msg = "TheTestingPlainText";


    string msg_pad = CryptoSymWrapperFunctions::Wrapper_pad(msg, _len);
    int sizechar = sizeof(size_t);

    size_t TradCtxSize = 2 * sizeof(size_t) + _len *  PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2;
    size_t CondCtxSize = 3 * sizeof(size_t) + (sizeof(char) * 24) + (_len *  256);
    double duration_CondEnc_HD2_Sum = 0;
    double duration_Enc_HD2_Sum = 0;
    double duration_CondDec_HD2_Sum = 0;

    ofstream CondEncHD2;
    CondEncHD2.open("CondEncHDAtmostFourLen128.txt");
    CondEncHD2 << "The predicate is Hamming distance at most two [3 errors as wors case]******************\n \n ";

    for(int T = 0; T< Num_tests; T++) {
        char HD2_Char_ORigCTx [2 * sizeof(size_t) + _len *  PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2];
        char HD2_ctx_typo_Bytes[3 * sizeof(size_t) + (sizeof(char) * 24) + (_len *  256)];
        string typo =msg;
        string payload;

        /*Randomly making typo and the payload*/
        unsigned seed= time(0);
        int NumOfErrs = 0;
        char err1, err2, err3, err4, err5;
        srand(seed);
        NumOfErrs = 5;
//        NumOfErrs =rand() % 4;
        if (NumOfErrs == 1)
        {
            err1 = 32 + (rand() % 95);
            int ErrLction;
            ErrLction = rand() % (msg.size());
            typo[ErrLction] = err1;
        } else if (NumOfErrs == 2)
        {
            err1 = 32 + (rand() % 95);
            err2 = 32 + (rand() % 95);
            int ErrLction1, ErrLction2;
            ErrLction1 = rand() % msg.size();
            ErrLction2 = rand() % msg.size();
            typo[ErrLction1] = err1;
            typo[ErrLction2] = err2;
        } else if (NumOfErrs == 5)
        {
            err1 = 32 + (rand() % 95);
            err2 = 32 + (rand() % 95);
            err3 = 32 + (rand() % 95);
            err4 = 32 + (rand() % 95);
            err5 = 32 + (rand() % 95);
            int ErrLction1, ErrLction2, ErrLction3, ErrLction4, ErrLction5;
            ErrLction1 = rand() % msg.size();
            ErrLction2 = rand() % msg.size();
            ErrLction3 = rand() % msg.size();
            ErrLction4 = rand() % msg.size();
            ErrLction5 = rand() % msg.size();
            typo[ErrLction1] = err1;
            typo[ErrLction2] = err2;
            typo[ErrLction3] = err3;
            typo[ErrLction4] = err4;
            typo[ErrLction5] = err5;
        }
        payload = typo;
        string pad_typo = CryptoSymWrapperFunctions::Wrapper_pad(typo, _len);


        /* ============ */

        auto start_Enc_HD2 = high_resolution_clock::now();
        int tradEncRslt =0;
        tradEncRslt = HamDistTwo::Enc(pkobj._ppk, msg_pad, HD2_Char_ORigCTx);
        auto stop_Enc_HD2 = high_resolution_clock::now();
        auto duration_Enc_HD2 = duration_cast<milliseconds>(stop_Enc_HD2 - start_Enc_HD2);

        auto start_CondEnc_HD2 = high_resolution_clock::now();

        auto ctx_final = HamDistTwo::CondEnc(pkobj._ppk, HD2_Char_ORigCTx, typo, payload,_len, Threshold, HD2_ctx_typo_Bytes);

        auto stop_CondEnc_HD2 = high_resolution_clock::now();
        auto duration_CondEnc_HD2 = duration_cast<milliseconds>(stop_CondEnc_HD2 - start_CondEnc_HD2);

        auto start_CondDec_HD2 = high_resolution_clock::now();
        string recovered_hd2Bytes;
        int CondDecOut  = 0;
//        CondDecOut = HamDistTwo::CondDec(pkobj._ppk, HD2_ctx_typo_Bytes, pkobj._psk, Threshold, recovered_hd2Bytes, _len, 28);
        CondDecOut = HamDistTwo::CondDec_Optimized(pkobj._ppk, HD2_ctx_typo_Bytes, pkobj._psk, Threshold, recovered_hd2Bytes, _len, 28,19);
        auto stop_CondDec_HD2 = high_resolution_clock::now();
        auto duration_CondDec_HD2 = duration_cast<milliseconds>(stop_CondDec_HD2 - start_CondDec_HD2);

        CondEncHD2 << "Enc.Time, CondEnc.Time, Cond.Dec.Time, Ctx.Size, CondCtx.Size, CondDecRslt: (" <<
                   duration_Enc_HD2.count()
                   << ", " << duration_CondEnc_HD2.count()
                   << ", " << duration_CondDec_HD2.count()
                   << ", " << TradCtxSize
                   << ", " << CondCtxSize
                   << ", " << CondDecOut << " )\n";

        duration_Enc_HD2_Sum =  duration_Enc_HD2_Sum + duration_Enc_HD2.count();
        duration_CondEnc_HD2_Sum =  duration_CondEnc_HD2_Sum + duration_CondEnc_HD2.count();
        duration_CondDec_HD2_Sum =  duration_CondDec_HD2_Sum + duration_CondDec_HD2.count();

    }

    std::ofstream HDdataL("HDdataL_T4.dat", std::ios_base::app | std::ios_base::out);
    std::ofstream HDdataT("HDdataL128_T.dat", std::ios_base::app | std::ios_base::out);


    int MaxDist  = _len - Threshold;

    HDdataT << MaxDist << "\t"<< _len << "\t" << duration_Enc_HD2_Sum / Num_tests << "\t"
            << duration_CondEnc_HD2_Sum / Num_tests << "\t"
            << duration_CondDec_HD2_Sum / Num_tests << "\t"
            << CondCtxSize << "\t"
            << TradCtxSize << "\n";



    HDdataL << MaxDist << "\t"<< _len << "\t" << duration_Enc_HD2_Sum / Num_tests << "\t"
            << duration_CondEnc_HD2_Sum / Num_tests << "\t"
            << duration_CondDec_HD2_Sum / Num_tests << "\t"
            << CondCtxSize << "\t"
            << TradCtxSize << "\n";

    CondEncHD2 << "Average Enc, CondEnc, CondDec, CtxtSize: " <<
               duration_Enc_HD2_Sum / Num_tests
               << ", " <<  duration_CondEnc_HD2_Sum / Num_tests
               << ", " <<  duration_CondDec_HD2_Sum / Num_tests << ") \n";

    CondEncHD2.close();
    paillier_freepubkey(pkobj._ppk);
    paillier_freeprvkey(pkobj._psk);
    cout << "Hamming Distant  at most Four [Threshold =_len -4, _len = 128] is finished \n";
}




TEST_CASE("Conditional Encryption: OR of predicates: Hamming distance at most two, EDOne one and Capslock On, L =8")
{
    PwPkCrypto pkobj;
    pkobj.Paill_pk_init(1024);
    int Num_tests = 20;
    size_t _len = 8;
    int threshold = _len -2; // In the OR predicate we just considered the Hammind distance at most 2 as we will consider it in the application of CEnc in TypTop

    string msg = "TEST";

    string msg_pad = CryptoSymWrapperFunctions::Wrapper_pad(msg, _len);
    size_t PailCtxtSize =  PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2;

    size_t EDOneOrigCtxSize   = 2 * sizeof(size_t) + (_len + 1)  *  PailCtxtSize;
    size_t HDTwoOrigCtxSize   = 2 * sizeof(size_t) + _len *  PailCtxtSize;
    size_t CAPSLocOrigCtxSize = 2 * sizeof(size_t) +  PailCtxtSize;

    size_t ORPrdrigCtxSize = CAPSLocOrigCtxSize + EDOneOrigCtxSize + HDTwoOrigCtxSize;


    size_t CondEncEDOneCtxSize = 3 * sizeof(size_t) + (sizeof(char) * 24) + ((2 * _len) + 1) *  PailCtxtSize;
    size_t CondEncHDTwoCtxSize = 3 * sizeof(size_t) + (sizeof(char) * 24) + (_len *  PailCtxtSize);
    size_t CondEncCPSLKCtxSize = 3 * sizeof(size_t) + (sizeof(char) * 24) +  PailCtxtSize;

    size_t CondEncOR_CtxSize = CondEncCPSLKCtxSize + CondEncEDOneCtxSize + CondEncHDTwoCtxSize;



    double duration_CondEnc_ED1_Sum = 0;
    double duration_Enc_ED1_Sum = 0;
    double duration_CondDec_ED1_Sum = 0;

    ofstream CondEncORpred;
    CondEncORpred.open("CondEncORPredicate.txt");
    CondEncORpred << "We are testing the OR predicate ******************\n \n ";

    for(int T = 0; T< Num_tests; T++) {
        char OrPred_Char_ORigCTx[ORPrdrigCtxSize];
        char OrPred_ctx_typo_Bytes[CondEncOR_CtxSize];
        string typo;
        /*Randomly making typo and the payload*/
        unsigned seed = time(0);
        int NumOfErrs = 0;
        char err1;
        srand(seed);
//        NumOfErrs =rand() % 4;
        NumOfErrs = 3;
        if (NumOfErrs== 0)
        {
            typo = msg;
        }
        else if (NumOfErrs == 1)
        {
            err1 = 32 + (rand() % 95);
            int ErrLction;
            ErrLction = rand() % msg.size();
            typo = msg.substr(0, ErrLction) +  err1 + msg.substr(ErrLction, msg.size());
//            ErrLction++;
//            typo[ErrLction] = err1;
        } else if (NumOfErrs == 2)
        {
            int ErrLction, ErrLction2;
            ErrLction = rand() % msg.size();
            typo = msg.substr(0, ErrLction) + msg.substr(ErrLction+1, msg.size());
        }else if (NumOfErrs == 3)
        {
            int ErrLction, ErrLction2;
            ErrLction = rand() % msg.size();
            typo = msg + 'a' + 'v' + 'h';
            ErrLction = rand() % msg.size();
        }
//        typo = "hASSAN";
//        typo = "Dassan";
        string payload = typo;
        string pad_typo = CryptoSymWrapperFunctions::Wrapper_pad(typo, _len);
        /* ============ */


        auto start_Enc_HD2 = high_resolution_clock::now();
        int OrigEncRst = 0;
        OrigEncRst = OrPredicate::Enc(pkobj._ppk, msg, OrPred_Char_ORigCTx, _len);
        auto stop_Enc_HD2 = high_resolution_clock::now();
        auto duration_Enc_HD2 = duration_cast<milliseconds>(stop_Enc_HD2 - start_Enc_HD2);


        std::string ctx_final;
        OrPredicate*  Class_OrPredicate = new OrPredicate;
        auto start_CondEnc_HD2 = high_resolution_clock::now();
//        int ED1CondEncRstl =0;
        ctx_final = Class_OrPredicate->CondEnc(pkobj._ppk, OrPred_Char_ORigCTx, typo, payload,_len, threshold, OrPred_ctx_typo_Bytes);
//        memcpy(OrPred_ctx_typo_Bytes + (3*sizeof(size_t)),&ctx_final[0], 24 );
//        memcpy(OrPred_ctx_typo_Bytes + CondEncCPSLKCtxSize + (3*sizeof(size_t)),&ctx_final[0] + 24, 24 );
//        memcpy(OrPred_ctx_typo_Bytes + CondEncCPSLKCtxSize + CondEncEDOneCtxSize + (3*sizeof(size_t)),&ctx_final[0] + 48, 24 );


        auto stop_CondEnc_HD2 = high_resolution_clock::now();
        auto duration_CondEnc_HD2 = duration_cast<milliseconds>(stop_CondEnc_HD2 - start_CondEnc_HD2);

        string recovered_hd2Bytes;
        int CondDecOut = 0;
        auto start_CondDec_HD2 = high_resolution_clock::now();
        CondDecOut = OrPredicate::CondDec(pkobj._ppk, OrPred_ctx_typo_Bytes, pkobj._psk, threshold, recovered_hd2Bytes, _len, 28);
//        CondDecOut = OrPredicate::CondDec(pkobj._ppk, &ctx_final[0], pkobj._psk, 30, recovered_hd2Bytes, 32, 28);

        auto stop_CondDec_HD2 = high_resolution_clock::now();
        auto duration_CondDec_HD2 = duration_cast<milliseconds>(stop_CondDec_HD2 - start_CondDec_HD2);

//        free(ED1_Char_ORigCTx);
//        free(ED1_ctx_typo_Bytes);

//        CondEncORpred << "Enc.Time, CondEnc.Time, Cond.Dec.Time, Ctx.Size, CondCtx.Size, CondDecRslt: (" <<
//                      duration_Enc_HD2.count()
//                      << ", " << duration_CondEnc_HD2.count()
//                      << ", " << duration_CondDec_HD2.count()
//                      << ", " << ORPrdrigCtxSize
//                      << ", " << CondEncOR_CtxSize
//                      << ", " << CondDecOut << " )\n";


//        size_t pos = 0;
//        std::string token;
//        std::string delimiter = ", ";
//        std::string ss = ctx_final;
//        std::vector<double>A;
//        A.reserve(2);
//        while ((pos = ss.find(delimiter)) != std::string::npos) {
//            token = ss.substr(0, pos);
//            A.push_back(stod(token));
//            ss.erase(0, pos + delimiter.length());
//        }


        duration_Enc_ED1_Sum =  duration_Enc_ED1_Sum + duration_Enc_HD2.count();
        duration_CondEnc_ED1_Sum =  duration_CondEnc_ED1_Sum + duration_CondEnc_HD2.count();
        duration_CondDec_ED1_Sum =  duration_CondDec_ED1_Sum + duration_CondDec_HD2.count();
        delete Class_OrPredicate;
        Class_OrPredicate = NULL;
    }

    CondEncORpred << "Average Enc, CondEnc, CondDec time in msec : " <<
                  duration_Enc_ED1_Sum / Num_tests
                  << ", " <<  duration_CondEnc_ED1_Sum / Num_tests
                  << ", " <<  duration_CondDec_ED1_Sum / Num_tests << ") \n";

    std::ofstream EDOnedataL("ORdataL.dat", std::ios_base::app | std::ios_base::out);

//    HDdataL << "T\tL\t" << "Enc\tCondEnc\tCondDec\tCondCtxtSize\tCondCtxtSize\n";
//    int MaxDist = 1;

    EDOnedataL << "8" << "\t" << duration_Enc_ED1_Sum / Num_tests << "\t"
               << duration_CondEnc_ED1_Sum / Num_tests << "\t"
               << duration_CondDec_ED1_Sum / Num_tests << "\t"
               << ORPrdrigCtxSize << "\t"
               << CondEncOR_CtxSize << "\n";

    CondEncORpred.close();
    paillier_freepubkey(pkobj._ppk);
    paillier_freeprvkey(pkobj._psk);
    cout << "OR predicate is finished L = 8\n";
}

TEST_CASE("Conditional Encryption: OR of predicates: Hamming distance at most two, EDOne one and Capslock On, L =16")
{
    PwPkCrypto pkobj;
    pkobj.Paill_pk_init(1024);
    int Num_tests = 20;
    size_t _len = 16;
    int threshold = _len -2; // In the OR predicate we just considered the Hammind distance at most 2 as we will consider it in the application of CEnc in TypTop

    string msg = "TEST";

    string msg_pad = CryptoSymWrapperFunctions::Wrapper_pad(msg, _len);
    size_t PailCtxtSize =  PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2;

    size_t EDOneOrigCtxSize   = 2 * sizeof(size_t) + (_len + 1)  *  PailCtxtSize;
    size_t HDTwoOrigCtxSize   = 2 * sizeof(size_t) + _len *  PailCtxtSize;
    size_t CAPSLocOrigCtxSize = 2 * sizeof(size_t) +  PailCtxtSize;

    size_t ORPrdrigCtxSize = CAPSLocOrigCtxSize + EDOneOrigCtxSize + HDTwoOrigCtxSize;


    size_t CondEncEDOneCtxSize = 3 * sizeof(size_t) + (sizeof(char) * 24) + ((2 * _len) + 1) *  PailCtxtSize;
    size_t CondEncHDTwoCtxSize = 3 * sizeof(size_t) + (sizeof(char) * 24) + (_len *  PailCtxtSize);
    size_t CondEncCPSLKCtxSize = 3 * sizeof(size_t) + (sizeof(char) * 24) +  PailCtxtSize;

    size_t CondEncOR_CtxSize = CondEncCPSLKCtxSize + CondEncEDOneCtxSize + CondEncHDTwoCtxSize;



    double duration_CondEnc_ED1_Sum = 0;
    double duration_Enc_ED1_Sum = 0;
    double duration_CondDec_ED1_Sum = 0;

    ofstream CondEncORpred;
    CondEncORpred.open("CondEncORPredicate.txt");
    CondEncORpred << "We are testing the OR predicate ******************\n \n ";
    char* OrPred_Char_ORigCTx = (char*) malloc(ORPrdrigCtxSize);
    char* OrPred_ctx_typo_Bytes = (char*) malloc(CondEncOR_CtxSize);


    for(int T = 0; T< Num_tests; T++) {
//        char OrPred_Char_ORigCTx[ORPrdrigCtxSize];
//        char OrPred_ctx_typo_Bytes[CondEncOR_CtxSize];

//        char* OrPred_Char_ORigCTx = new char[ORPrdrigCtxSize];
//        char* OrPred_ctx_typo_Bytes = new char[CondEncOR_CtxSize];

        string typo;
        /*Randomly making typo and the payload*/
        unsigned seed = time(0);
        int NumOfErrs = 0;
        char err1;
        srand(seed);
//        NumOfErrs =rand() % 4;
        NumOfErrs = 3;
        if (NumOfErrs== 0)
        {
            typo = msg;
        }
        else if (NumOfErrs == 1)
        {
            err1 = 32 + (rand() % 95);
            int ErrLction;
            ErrLction = rand() % msg.size();
            typo = msg.substr(0, ErrLction) +  err1 + msg.substr(ErrLction, msg.size());
//            ErrLction++;
//            typo[ErrLction] = err1;
        } else if (NumOfErrs == 2)
        {
            int ErrLction, ErrLction2;
            ErrLction = rand() % msg.size();
            typo = msg.substr(0, ErrLction) + msg.substr(ErrLction + 1, msg.size());
        }else if (NumOfErrs == 3)
        {
            int ErrLction, ErrLction2;
            ErrLction = rand() % msg.size();
            typo = msg + 'a' + '5' + 'h';
            ErrLction = rand() % msg.size();
        }
//        typo = "hASSAN";
//        typo = "Dassan";
        string payload = typo;
        string pad_typo = CryptoSymWrapperFunctions::Wrapper_pad(typo, _len);
        /* ============ */

        std::unique_ptr<OrPredicate> Class_OrPredicate(new OrPredicate());


        auto start_Enc_HD2 = high_resolution_clock::now();
        int OrigEncRst = 0;
        OrigEncRst = Class_OrPredicate->Enc(pkobj._ppk, msg, OrPred_Char_ORigCTx, _len);
        auto stop_Enc_HD2 = high_resolution_clock::now();
        auto duration_Enc_HD2 = duration_cast<milliseconds>(stop_Enc_HD2 - start_Enc_HD2);


        std::string ctx_final;
//        OrPredicate*  Class_OrPredicate = new OrPredicate;


        auto start_CondEnc_HD2 = high_resolution_clock::now();
//        int ED1CondEncRstl =0;
        ctx_final = Class_OrPredicate->CondEnc(pkobj._ppk, OrPred_Char_ORigCTx, typo, payload,_len, threshold, OrPred_ctx_typo_Bytes);
//        memcpy(OrPred_ctx_typo_Bytes + (3*sizeof(size_t)),&ctx_final[0], 24 );
//        memcpy(OrPred_ctx_typo_Bytes + CondEncCPSLKCtxSize + (3*sizeof(size_t)),&ctx_final[0] + 24, 24 );
//        memcpy(OrPred_ctx_typo_Bytes + CondEncCPSLKCtxSize + CondEncEDOneCtxSize + (3*sizeof(size_t)),&ctx_final[0] + 48, 24 );


        auto stop_CondEnc_HD2 = high_resolution_clock::now();
        auto duration_CondEnc_HD2 = duration_cast<milliseconds>(stop_CondEnc_HD2 - start_CondEnc_HD2);

        string recovered_hd2Bytes;
        int CondDecOut = 0;
        auto start_CondDec_HD2 = high_resolution_clock::now();
        CondDecOut = Class_OrPredicate->CondDec(pkobj._ppk, OrPred_ctx_typo_Bytes, pkobj._psk, threshold, recovered_hd2Bytes, _len, 28);
//        CondDecOut = OrPredicate::CondDec(pkobj._ppk, &ctx_final[0], pkobj._psk, 30, recovered_hd2Bytes, 32, 28);

        auto stop_CondDec_HD2 = high_resolution_clock::now();
        auto duration_CondDec_HD2 = duration_cast<milliseconds>(stop_CondDec_HD2 - start_CondDec_HD2);

//        free(ED1_Char_ORigCTx);
//        free(ED1_ctx_typo_Bytes);

//        CondEncORpred << "Enc.Time, CondEnc.Time, Cond.Dec.Time, Ctx.Size, CondCtx.Size, CondDecRslt: (" <<
//                      duration_Enc_HD2.count()
//                      << ", " << duration_CondEnc_HD2.count()
//                      << ", " << duration_CondDec_HD2.count()
//                      << ", " << ORPrdrigCtxSize
//                      << ", " << CondEncOR_CtxSize
//                      << ", " << CondDecOut << " )\n";


//        size_t pos = 0;
//        std::string token;
//        std::string delimiter = ", ";
//        std::string ss = ctx_final;
//        std::vector<double>A;
//        A.reserve(2);
//        while ((pos = ss.find(delimiter)) != std::string::npos) {
//            token = ss.substr(0, pos);
//            A.push_back(stod(token));
//            ss.erase(0, pos + delimiter.length());
//        }
//
//
//        duration_Enc_ED1_Sum =  duration_Enc_ED1_Sum + duration_Enc_HD2.count();
//        duration_CondEnc_ED1_Sum =  duration_CondEnc_ED1_Sum + A[0];
//        duration_CondDec_ED1_Sum =  duration_CondDec_ED1_Sum + stod(ss);

        duration_Enc_ED1_Sum =  duration_Enc_ED1_Sum + duration_Enc_HD2.count();
        duration_CondEnc_ED1_Sum =  duration_CondEnc_ED1_Sum + duration_CondEnc_HD2.count();
        duration_CondDec_ED1_Sum =  duration_CondDec_ED1_Sum + duration_CondDec_HD2.count();
//        delete Class_OrPredicate;
//        Class_OrPredicate = NULL;
        Class_OrPredicate.reset();

//        delete [] OrPred_Char_ORigCTx;
//        delete [] OrPred_ctx_typo_Bytes;
    }

    CondEncORpred << "Average Enc, CondEnc, CondDec time in msec : " <<
                  duration_Enc_ED1_Sum / Num_tests
                  << ", " <<  duration_CondEnc_ED1_Sum / Num_tests
                  << ", " <<  duration_CondDec_ED1_Sum / Num_tests << ") \n";

    std::ofstream EDOnedataL("ORdataL.dat", std::ios_base::app | std::ios_base::out);

//    HDdataL << "T\tL\t" << "Enc\tCondEnc\tCondDec\tCondCtxtSize\tCondCtxtSize\n";
//    int MaxDist = 1;

    EDOnedataL << "16" << "\t" << duration_Enc_ED1_Sum / Num_tests << "\t"
               << duration_CondEnc_ED1_Sum / Num_tests << "\t"
               << duration_CondDec_ED1_Sum / Num_tests << "\t"
               << ORPrdrigCtxSize << "\t"
               << CondEncOR_CtxSize << "\n";

    CondEncORpred.close();
    paillier_freepubkey(pkobj._ppk);
    paillier_freeprvkey(pkobj._psk);
    free(OrPred_Char_ORigCTx);
    free(OrPred_ctx_typo_Bytes);
    cout << "OR predicate is finished L =16 \n";
}

TEST_CASE("Conditional Encryption: OR of predicates: Hamming distance at most two, EDOne one and Capslock On, L =32")
{
    PwPkCrypto pkobj;
    pkobj.Paill_pk_init(1024);
    int Num_tests = 20;
    size_t _len = 32;
    int threshold = _len -2; // In the OR predicate we just considered the Hammind distance at most 2 as we will consider it in the application of CEnc in TypTop

    string msg = "TEST";

    string msg_pad = CryptoSymWrapperFunctions::Wrapper_pad(msg, _len);
    size_t PailCtxtSize =  PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2;

    size_t EDOneOrigCtxSize   = 2 * sizeof(size_t) + (_len + 1)  *  PailCtxtSize;
    size_t HDTwoOrigCtxSize   = 2 * sizeof(size_t) + _len *  PailCtxtSize;
    size_t CAPSLocOrigCtxSize = 2 * sizeof(size_t) +  PailCtxtSize;

    size_t ORPrdrigCtxSize = CAPSLocOrigCtxSize + EDOneOrigCtxSize + HDTwoOrigCtxSize;


    size_t CondEncEDOneCtxSize = 3 * sizeof(size_t) + (sizeof(char) * 24) + ((2 * _len) + 1) *  PailCtxtSize;
    size_t CondEncHDTwoCtxSize = 3 * sizeof(size_t) + (sizeof(char) * 24) + (_len *  PailCtxtSize);
    size_t CondEncCPSLKCtxSize = 3 * sizeof(size_t) + (sizeof(char) * 24) +  PailCtxtSize;

    size_t CondEncOR_CtxSize = CondEncCPSLKCtxSize + CondEncEDOneCtxSize + CondEncHDTwoCtxSize;



    double duration_CondEnc_ED1_Sum = 0;
    double duration_Enc_ED1_Sum = 0;
    double duration_CondDec_ED1_Sum = 0;

    ofstream CondEncORpred;
    CondEncORpred.open("CondEncORPredicate.txt");
    CondEncORpred << "We are testing the OR predicate ******************\n \n ";

    for(int T = 0; T< Num_tests; T++) {
        char OrPred_Char_ORigCTx[ORPrdrigCtxSize];
        char OrPred_ctx_typo_Bytes[CondEncOR_CtxSize];
        string typo;
        /*Randomly making typo and the payload*/
        unsigned seed = time(0);
        int NumOfErrs = 0;
        char err1;
        srand(seed);
//        NumOfErrs =rand() % 4;
        NumOfErrs = 3;
        if (NumOfErrs== 0)
        {
            typo = msg;
        }
        else if (NumOfErrs == 1)
        {
            err1 = 32 + (rand() % 95);
            int ErrLction;
            ErrLction = rand() % msg.size();
            typo = msg.substr(0, ErrLction) +  err1 + msg.substr(ErrLction, msg.size());
//            ErrLction++;
//            typo[ErrLction] = err1;
        } else if (NumOfErrs == 2)
        {
            int ErrLction, ErrLction2;
            ErrLction = rand() % msg.size();
            typo = msg.substr(0, ErrLction) + msg.substr(ErrLction+1, msg.size());
        }else if (NumOfErrs == 3)
        {
            int ErrLction, ErrLction2;
            ErrLction = rand() % msg.size();
            typo = msg + 'a' + 'v' + 's';
            ErrLction = rand() % msg.size();
        }
//        typo = "hASSAN";
//        typo = "Dassan";
        string payload = typo;
        string pad_typo = CryptoSymWrapperFunctions::Wrapper_pad(typo, _len);
        /* ============ */


        auto start_Enc_HD2 = high_resolution_clock::now();
        int OrigEncRst = 0;
        OrigEncRst = OrPredicate::Enc(pkobj._ppk, msg, OrPred_Char_ORigCTx, _len);
        auto stop_Enc_HD2 = high_resolution_clock::now();
        auto duration_Enc_HD2 = duration_cast<milliseconds>(stop_Enc_HD2 - start_Enc_HD2);


        std::string ctx_final;
        OrPredicate*  Class_OrPredicate = new OrPredicate;
        auto start_CondEnc_HD2 = high_resolution_clock::now();
//        int ED1CondEncRstl =0;
        ctx_final = Class_OrPredicate->CondEnc(pkobj._ppk, OrPred_Char_ORigCTx, typo, payload,_len, threshold, OrPred_ctx_typo_Bytes);
//        memcpy(OrPred_ctx_typo_Bytes + (3*sizeof(size_t)),&ctx_final[0], 24 );
//        memcpy(OrPred_ctx_typo_Bytes + CondEncCPSLKCtxSize + (3*sizeof(size_t)),&ctx_final[0] + 24, 24 );
//        memcpy(OrPred_ctx_typo_Bytes + CondEncCPSLKCtxSize + CondEncEDOneCtxSize + (3*sizeof(size_t)),&ctx_final[0] + 48, 24 );

        auto stop_CondEnc_HD2 = high_resolution_clock::now();
        auto duration_CondEnc_HD2 = duration_cast<milliseconds>(stop_CondEnc_HD2 - start_CondEnc_HD2);

        string recovered_hd2Bytes;
        int CondDecOut = 0;
        auto start_CondDec_HD2 = high_resolution_clock::now();
        CondDecOut = OrPredicate::CondDec(pkobj._ppk, OrPred_ctx_typo_Bytes, pkobj._psk, threshold, recovered_hd2Bytes, _len, 28);
//        CondDecOut = OrPredicate::CondDec(pkobj._ppk, &ctx_final[0], pkobj._psk, 30, recovered_hd2Bytes, 32, 28);

        auto stop_CondDec_HD2 = high_resolution_clock::now();
        auto duration_CondDec_HD2 = duration_cast<milliseconds>(stop_CondDec_HD2 - start_CondDec_HD2);

//        free(ED1_Char_ORigCTx);
//        free(ED1_ctx_typo_Bytes);

//        CondEncORpred << "Enc.Time, CondEnc.Time, Cond.Dec.Time, Ctx.Size, CondCtx.Size, CondDecRslt: (" <<
//                      duration_Enc_HD2.count()
//                      << ", " << duration_CondEnc_HD2.count()
//                      << ", " << duration_CondDec_HD2.count()
//                      << ", " << ORPrdrigCtxSize
//                      << ", " << CondEncOR_CtxSize
//                      << ", " << CondDecOut << " )\n";



        duration_Enc_ED1_Sum =  duration_Enc_ED1_Sum + duration_Enc_HD2.count();
        duration_CondEnc_ED1_Sum =  duration_CondEnc_ED1_Sum + duration_CondEnc_HD2.count();
        duration_CondDec_ED1_Sum =  duration_CondDec_ED1_Sum + duration_CondDec_HD2.count();
        delete Class_OrPredicate;
        Class_OrPredicate = NULL;
    }

    CondEncORpred << "Average Enc, CondEnc, CondDec time in msec : " <<
                  duration_Enc_ED1_Sum / Num_tests
                  << ", " <<  duration_CondEnc_ED1_Sum / Num_tests
                  << ", " <<  duration_CondDec_ED1_Sum / Num_tests << ") \n";

    std::ofstream EDOnedataL("ORdataL.dat", std::ios_base::app | std::ios_base::out);

//    HDdataL << "T\tL\t" << "Enc\tCondEnc\tCondDec\tCondCtxtSize\tCondCtxtSize\n";
//    int MaxDist = 1;

    EDOnedataL << "32" << "\t" << duration_Enc_ED1_Sum / Num_tests << "\t"
               << duration_CondEnc_ED1_Sum / Num_tests << "\t"
               << duration_CondDec_ED1_Sum / Num_tests << "\t"
               << ORPrdrigCtxSize << "\t"
               << CondEncOR_CtxSize << "\n";

    CondEncORpred.close();
    paillier_freepubkey(pkobj._ppk);
    paillier_freeprvkey(pkobj._psk);
    cout << "OR predicate is finished L =32 \n";
}

TEST_CASE("Conditional Encryption: OR of predicates: Hamming distance at most two, EDOne one and Capslock On, L =64")
{
    PwPkCrypto pkobj;
    pkobj.Paill_pk_init(1024);
    int Num_tests = 10;
    size_t _len = 64;
    int threshold = _len -2; // In the OR predicate we just considered the Hammind distance at most 2 as we will consider it in the application of CEnc in TypTop

    string msg = "TEST";

    string msg_pad = CryptoSymWrapperFunctions::Wrapper_pad(msg, _len);
    size_t PailCtxtSize =  PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2;

    size_t EDOneOrigCtxSize   = 2 * sizeof(size_t) + (_len + 1)  *  PailCtxtSize;
    size_t HDTwoOrigCtxSize   = 2 * sizeof(size_t) + _len *  PailCtxtSize;
    size_t CAPSLocOrigCtxSize = 2 * sizeof(size_t) +  PailCtxtSize;

    size_t ORPrdrigCtxSize = CAPSLocOrigCtxSize + EDOneOrigCtxSize + HDTwoOrigCtxSize;


    size_t CondEncEDOneCtxSize = 3 * sizeof(size_t) + (sizeof(char) * 24) + ((2 * _len) + 1) *  PailCtxtSize;
    size_t CondEncHDTwoCtxSize = 3 * sizeof(size_t) + (sizeof(char) * 24) + (_len *  PailCtxtSize);
    size_t CondEncCPSLKCtxSize = 3 * sizeof(size_t) + (sizeof(char) * 24) +  PailCtxtSize;

    size_t CondEncOR_CtxSize = CondEncCPSLKCtxSize + CondEncEDOneCtxSize + CondEncHDTwoCtxSize;



    double duration_CondEnc_ED1_Sum = 0;
    double duration_Enc_ED1_Sum = 0;
    double duration_CondDec_ED1_Sum = 0;

    ofstream CondEncORpred;
    CondEncORpred.open("CondEncORPredicate.txt");
    CondEncORpred << "We are testing the OR predicate ******************\n \n ";

    for(int T = 0; T< Num_tests; T++) {
        char OrPred_Char_ORigCTx[ORPrdrigCtxSize];
        char OrPred_ctx_typo_Bytes[CondEncOR_CtxSize];
        string typo;
        /*Randomly making typo and the payload*/
        unsigned seed = time(0);
        int NumOfErrs = 0;
        char err1;
        srand(seed);
//        NumOfErrs =rand() % 4;
        NumOfErrs = 3;
        if (NumOfErrs== 0)
        {
            typo = msg;
        }
        else if (NumOfErrs == 1)
        {
            err1 = 32 + (rand() % 95);
            int ErrLction;
            ErrLction = rand() % msg.size();
            typo = msg.substr(0, ErrLction) +  err1 + msg.substr(ErrLction, msg.size());
//            ErrLction++;
//            typo[ErrLction] = err1;
        } else if (NumOfErrs == 2)
        {
            int ErrLction, ErrLction2;
            ErrLction = rand() % msg.size();
            typo = msg.substr(0, ErrLction) + msg.substr(ErrLction+1, msg.size());
        }else if (NumOfErrs == 3)
        {
            int ErrLction, ErrLction2;
            ErrLction = rand() % msg.size();
            typo = msg + 'a' + 'v' + 's';
            ErrLction = rand() % msg.size();
        }
//        typo = "hASSAN";
//        typo = "Dassan";
        string payload = typo;
        string pad_typo = CryptoSymWrapperFunctions::Wrapper_pad(typo, _len);
        /* ============ */


        auto start_Enc_HD2 = high_resolution_clock::now();
        int OrigEncRst = 0;
        OrigEncRst = OrPredicate::Enc(pkobj._ppk, msg, OrPred_Char_ORigCTx, _len);
        auto stop_Enc_HD2 = high_resolution_clock::now();
        auto duration_Enc_HD2 = duration_cast<milliseconds>(stop_Enc_HD2 - start_Enc_HD2);


        std::string ctx_final;
        OrPredicate*  Class_OrPredicate = new OrPredicate;
        auto start_CondEnc_HD2 = high_resolution_clock::now();
//        int ED1CondEncRstl =0;
        ctx_final = Class_OrPredicate->CondEnc(pkobj._ppk, OrPred_Char_ORigCTx, typo, payload,_len, threshold, OrPred_ctx_typo_Bytes);
//        memcpy(OrPred_ctx_typo_Bytes + (3*sizeof(size_t)),&ctx_final[0], 24 );
//        memcpy(OrPred_ctx_typo_Bytes + CondEncCPSLKCtxSize + (3*sizeof(size_t)),&ctx_final[0] + 24, 24 );
//        memcpy(OrPred_ctx_typo_Bytes + CondEncCPSLKCtxSize + CondEncEDOneCtxSize + (3*sizeof(size_t)),&ctx_final[0] + 48, 24 );


        auto stop_CondEnc_HD2 = high_resolution_clock::now();
        auto duration_CondEnc_HD2 = duration_cast<milliseconds>(stop_CondEnc_HD2 - start_CondEnc_HD2);

        string recovered_hd2Bytes;
        int CondDecOut = 0;
        auto start_CondDec_HD2 = high_resolution_clock::now();
        CondDecOut = OrPredicate::CondDec(pkobj._ppk, OrPred_ctx_typo_Bytes, pkobj._psk, threshold, recovered_hd2Bytes, _len, 28);
//        CondDecOut = OrPredicate::CondDec(pkobj._ppk, &ctx_final[0], pkobj._psk, 30, recovered_hd2Bytes, 32, 28);

        auto stop_CondDec_HD2 = high_resolution_clock::now();
        auto duration_CondDec_HD2 = duration_cast<milliseconds>(stop_CondDec_HD2 - start_CondDec_HD2);

//        free(ED1_Char_ORigCTx);
//        free(ED1_ctx_typo_Bytes);

//        CondEncORpred << "Enc.Time, CondEnc.Time, Cond.Dec.Time, Ctx.Size, CondCtx.Size, CondDecRslt: (" <<
//                      duration_Enc_HD2.count()
//                      << ", " << duration_CondEnc_HD2.count()
//                      << ", " << duration_CondDec_HD2.count()
//                      << ", " << ORPrdrigCtxSize
//                      << ", " << CondEncOR_CtxSize
//                      << ", " << CondDecOut << " )\n";



        duration_Enc_ED1_Sum =  duration_Enc_ED1_Sum + duration_Enc_HD2.count();
        duration_CondEnc_ED1_Sum =  duration_CondEnc_ED1_Sum + duration_CondEnc_HD2.count();
        duration_CondDec_ED1_Sum =  duration_CondDec_ED1_Sum + duration_CondDec_HD2.count();
        delete Class_OrPredicate;
        Class_OrPredicate = NULL;
    }

    CondEncORpred << "Average Enc, CondEnc, CondDec time in msec : " <<
                  duration_Enc_ED1_Sum / Num_tests
                  << ", " <<  duration_CondEnc_ED1_Sum / Num_tests
                  << ", " <<  duration_CondDec_ED1_Sum / Num_tests << ") \n";

    std::ofstream EDOnedataL("ORdataL.dat", std::ios_base::app | std::ios_base::out);

//    HDdataL << "T\tL\t" << "Enc\tCondEnc\tCondDec\tCondCtxtSize\tCondCtxtSize\n";
//    int MaxDist = 1;

    EDOnedataL << "64" << "\t" << duration_Enc_ED1_Sum / Num_tests << "\t"
               << duration_CondEnc_ED1_Sum / Num_tests << "\t"
               << duration_CondDec_ED1_Sum / Num_tests << "\t"
               << ORPrdrigCtxSize << "\t"
               << CondEncOR_CtxSize << "\n";

    CondEncORpred.close();
    paillier_freepubkey(pkobj._ppk);
    paillier_freeprvkey(pkobj._psk);
    cout << "OR predicate is finished L =64 \n";
}

TEST_CASE("Conditional Encryption: OR of predicates: Hamming distance at most two, EDOne one and Capslock On, L =128")
{
    PwPkCrypto pkobj;
    pkobj.Paill_pk_init(1024);
    int Num_tests = 2;
    size_t _len = 128;
    int threshold = _len -2; // In the OR predicate we just considered the Hammind distance at most 2 as we will consider it in the application of CEnc in TypTop

    string msg = "TEST";

    string msg_pad = CryptoSymWrapperFunctions::Wrapper_pad(msg, _len);
    size_t PailCtxtSize =  PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2;

    size_t EDOneOrigCtxSize   = 2 * sizeof(size_t) + (_len + 1)  *  PailCtxtSize;
    size_t HDTwoOrigCtxSize   = 2 * sizeof(size_t) + _len *  PailCtxtSize;
    size_t CAPSLocOrigCtxSize = 2 * sizeof(size_t) +  PailCtxtSize;

    size_t ORPrdrigCtxSize = CAPSLocOrigCtxSize + EDOneOrigCtxSize + HDTwoOrigCtxSize;


    size_t CondEncEDOneCtxSize = 3 * sizeof(size_t) + (sizeof(char) * 24) + ((2 * _len) + 1) *  PailCtxtSize;
    size_t CondEncHDTwoCtxSize = 3 * sizeof(size_t) + (sizeof(char) * 24) + (_len *  PailCtxtSize);
    size_t CondEncCPSLKCtxSize = 3 * sizeof(size_t) + (sizeof(char) * 24) +  PailCtxtSize;

    size_t CondEncOR_CtxSize = CondEncCPSLKCtxSize + CondEncEDOneCtxSize + CondEncHDTwoCtxSize;



    double duration_CondEnc_ED1_Sum = 0;
    double duration_Enc_ED1_Sum = 0;
    double duration_CondDec_ED1_Sum = 0;

    ofstream CondEncORpred;
    CondEncORpred.open("CondEncORPredicate.txt");
    CondEncORpred << "We are testing the OR predicate ******************\n \n ";

    for(int T = 0; T< Num_tests; T++) {
        char OrPred_Char_ORigCTx[ORPrdrigCtxSize];
        char OrPred_ctx_typo_Bytes[CondEncOR_CtxSize];
        string typo;
        /*Randomly making typo and the payload*/
        unsigned seed = time(0);
        int NumOfErrs = 0;
        char err1;
        srand(seed);
//        NumOfErrs =rand() % 4;
        NumOfErrs = 3;
        if (NumOfErrs== 0)
        {
            typo = msg;
        }
        else if (NumOfErrs == 1)
        {
            err1 = 32 + (rand() % 95);
            int ErrLction;
            ErrLction = rand() % msg.size();
            typo = msg.substr(0, ErrLction) +  err1 + msg.substr(ErrLction, msg.size());
//            ErrLction++;
//            typo[ErrLction] = err1;
        } else if (NumOfErrs == 2)
        {
            int ErrLction, ErrLction2;
            ErrLction = rand() % msg.size();
            typo = msg.substr(0, ErrLction) + msg.substr(ErrLction+1, msg.size());
        }else if (NumOfErrs == 3)
        {
            int ErrLction, ErrLction2;
            ErrLction = rand() % msg.size();
            typo = msg + 'a' + 'v' + 's';
            ErrLction = rand() % msg.size();
        }
//        typo = "hASSAN";
//        typo = "Dassan";
        string payload = typo;
        string pad_typo = CryptoSymWrapperFunctions::Wrapper_pad(typo, _len);
        /* ============ */


        auto start_Enc_HD2 = high_resolution_clock::now();
        int OrigEncRst = 0;
        OrigEncRst = OrPredicate::Enc(pkobj._ppk, msg, OrPred_Char_ORigCTx, _len);
        auto stop_Enc_HD2 = high_resolution_clock::now();
        auto duration_Enc_HD2 = duration_cast<milliseconds>(stop_Enc_HD2 - start_Enc_HD2);


        std::string ctx_final;
        OrPredicate*  Class_OrPredicate = new OrPredicate;
        auto start_CondEnc_HD2 = high_resolution_clock::now();
//        int ED1CondEncRstl =0;
        ctx_final = Class_OrPredicate->CondEnc(pkobj._ppk, OrPred_Char_ORigCTx, typo, payload,_len, threshold, OrPred_ctx_typo_Bytes);
//        memcpy(OrPred_ctx_typo_Bytes + (3*sizeof(size_t)),&ctx_final[0], 24 );
//        memcpy(OrPred_ctx_typo_Bytes + CondEncCPSLKCtxSize + (3*sizeof(size_t)),&ctx_final[0] + 24, 24 );
//        memcpy(OrPred_ctx_typo_Bytes + CondEncCPSLKCtxSize + CondEncEDOneCtxSize + (3*sizeof(size_t)),&ctx_final[0] + 48, 24 );


        auto stop_CondEnc_HD2 = high_resolution_clock::now();
        auto duration_CondEnc_HD2 = duration_cast<milliseconds>(stop_CondEnc_HD2 - start_CondEnc_HD2);

        string recovered_hd2Bytes;
        int CondDecOut = 0;
        auto start_CondDec_HD2 = high_resolution_clock::now();
        CondDecOut = OrPredicate::CondDec(pkobj._ppk, OrPred_ctx_typo_Bytes, pkobj._psk, threshold, recovered_hd2Bytes, _len, 28);
//        CondDecOut = OrPredicate::CondDec(pkobj._ppk, &ctx_final[0], pkobj._psk, 30, recovered_hd2Bytes, 32, 28);

        auto stop_CondDec_HD2 = high_resolution_clock::now();
        auto duration_CondDec_HD2 = duration_cast<milliseconds>(stop_CondDec_HD2 - start_CondDec_HD2);

//        free(ED1_Char_ORigCTx);
//        free(ED1_ctx_typo_Bytes);

//        CondEncORpred << "Enc.Time, CondEnc.Time, Cond.Dec.Time, Ctx.Size, CondCtx.Size, CondDecRslt: (" <<
//                      duration_Enc_HD2.count()
//                      << ", " << duration_CondEnc_HD2.count()
//                      << ", " << duration_CondDec_HD2.count()
//                      << ", " << ORPrdrigCtxSize
//                      << ", " << CondEncOR_CtxSize
//                      << ", " << CondDecOut << " )\n";



        duration_Enc_ED1_Sum =  duration_Enc_ED1_Sum + duration_Enc_HD2.count();
        duration_CondEnc_ED1_Sum =  duration_CondEnc_ED1_Sum + duration_CondEnc_HD2.count();
        duration_CondDec_ED1_Sum =  duration_CondDec_ED1_Sum + duration_CondDec_HD2.count();
        delete Class_OrPredicate;
        Class_OrPredicate = NULL;
    }

    CondEncORpred << "Average Enc, CondEnc, CondDec time in msec : " <<
                  duration_Enc_ED1_Sum / Num_tests
                  << ", " <<  duration_CondEnc_ED1_Sum / Num_tests
                  << ", " <<  duration_CondDec_ED1_Sum / Num_tests << ") \n";

    std::ofstream EDOnedataL("ORdataL.dat", std::ios_base::app | std::ios_base::out);

//    HDdataL << "T\tL\t" << "Enc\tCondEnc\tCondDec\tCondCtxtSize\tCondCtxtSize\n";
//    int MaxDist = 1;

    EDOnedataL << "128" << "\t" << duration_Enc_ED1_Sum / Num_tests << "\t"
               << duration_CondEnc_ED1_Sum / Num_tests << "\t"
               << duration_CondDec_ED1_Sum / Num_tests << "\t"
               << ORPrdrigCtxSize << "\t"
               << CondEncOR_CtxSize << "\n";

    CondEncORpred.close();
    paillier_freepubkey(pkobj._ppk);
    paillier_freeprvkey(pkobj._psk);
    cout << "OR predicate is finished L =128 \n";
}



TEST_CASE("Conditional Encryption: CAPSLOCK ON predicate L = 8")
{
    PwPkCrypto pkobj;
    pkobj.Paill_pk_init(1024);
    int Num_tests = 20;
    size_t _len = 8;
    int threshold = _len -2;


    string msg = "Hassan";
    string typo = "hASSAN";
    string payload = "hASSAN";

    string  ctx_cplck;
    string ctx_typo_cplck;
    string recovered_cplck;

    char*  CAPS_Char_ORigCTx;
    char*  ctx_typo_cplckBytes;
    size_t TradCtxSize = 2 * sizeof(size_t) +  PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2;
    size_t CondCtxSize = 3 * sizeof(size_t) + 24 * sizeof(char) +   PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2;
//    char*  CAPS_Char_ORigCTx = (char*) malloc (2 * sizeof(size_t) +  PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2);
//    char*  ctx_typo_cplckBytes = (char*) malloc (2 * sizeof(size_t) +  PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2);


    vector<double> T_Enc_CondEncCAPLK[Num_tests];
    vector<double> T_CondEnc_CondEncCAPLK[Num_tests];
    vector<double> T_CondDec_CondEncCAPLK[Num_tests];

    double duration_CondEnc_CAP_Sum = 0;
    double duration_Enc_CAP_Sum = 0;
    double duration_CondDec_CAP_Sum = 0;

    ofstream CondEncCPSLCK;
    CondEncCPSLCK.open("CondEncCPSLCK.txt");
    CondEncCPSLCK << "The predicate is CPSLCK key ON ******************\n \n ";

    for(int T = 0; T< Num_tests; T++) {

        char CAPS_Char_ORigCTx[2 * sizeof(size_t) +  PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2];
        char ctx_typo_cplckBytes[ 3 * sizeof(size_t) + (sizeof(char) * 24)  +   PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2];

        auto start_Enc_CAP = high_resolution_clock::now();
        int CApsOrigCtxtRslt = CAPLOCKpredicate::Enc(pkobj._ppk, msg, CAPS_Char_ORigCTx);
        auto stop_Enc_CAP = high_resolution_clock::now();
        auto duration_Enc_CAP = duration_cast<milliseconds>(stop_Enc_CAP - start_Enc_CAP);

        auto start_CondEnc_CAP = high_resolution_clock::now();
        auto CPSLKCondEncRlt =  CAPLOCKpredicate::CondEnc(pkobj._ppk, CAPS_Char_ORigCTx, typo, payload,_len, threshold,  ctx_typo_cplckBytes);
        auto stop_CondEnc_CAP = high_resolution_clock::now();
        auto duration_CondEnc_CAP = duration_cast<milliseconds>(stop_CondEnc_CAP - start_CondEnc_CAP);


        auto start_CondDec_CAP = high_resolution_clock::now();
        string recovered_cplckBytes;
        int CondDecOut = 0;
        CondDecOut = CAPLOCKpredicate::CondDec(pkobj._ppk, ctx_typo_cplckBytes, pkobj._psk, 29, recovered_cplckBytes, msg.size(), 28);
        auto stop_CondDec_CAP = high_resolution_clock::now();
        auto duration_CondDec_CAP = duration_cast<milliseconds>(stop_CondDec_CAP - start_CondDec_CAP);


        CondEncCPSLCK << "Enc.Time, CondEnc.Time, Cond.Dec.Time, Ctx.Size, CondCtx.Size, CondDecRslt: (" <<
                      duration_Enc_CAP.count()
                      << ", " << duration_CondEnc_CAP.count()
                      << ", " << duration_CondDec_CAP.count()
                      << ", " << TradCtxSize
                      << ", " << CondCtxSize
                      << ", " << CondDecOut << " )\n";

//        free(CAPS_Char_ORigCTx);
//        free(ctx_typo_cplckBytes);

        duration_Enc_CAP_Sum =  duration_Enc_CAP_Sum + duration_Enc_CAP.count();
        duration_CondEnc_CAP_Sum =  duration_CondEnc_CAP_Sum + duration_CondEnc_CAP.count();
        duration_CondDec_CAP_Sum =  duration_CondDec_CAP_Sum + duration_CondDec_CAP.count();

    }

    std::ofstream EDOnedataL("CAPSLKdataL.dat", std::ios_base::app | std::ios_base::out);

//    HDdataL << "T\tL\t" << "Enc\tCondEnc\tCondDec\tCondCtxtSize\tCondCtxtSize\n";
//    int MaxDist = 1;

    EDOnedataL << "8" << "\t" << duration_Enc_CAP_Sum / Num_tests << "\t"
               << duration_CondEnc_CAP_Sum / Num_tests << "\t"
               << duration_CondDec_CAP_Sum / Num_tests << "\t"
               << CondCtxSize << "\t"
               << TradCtxSize << "\n";

    CondEncCPSLCK.close();
    paillier_freepubkey(pkobj._ppk);
    paillier_freeprvkey(pkobj._psk);
    cout << "CAPSLCOK is finished \n";
}

TEST_CASE("Conditional Encryption: CAPSLOCK ON predicate L = 16")
{
    PwPkCrypto pkobj;
    pkobj.Paill_pk_init(1024);
    int Num_tests = 20;
    size_t _len = 16;
    int threshold = _len -2;

    string msg = "Hassan";
    string typo = "hASSAN";
    string payload = "hASSAN";

    string  ctx_cplck;
    string ctx_typo_cplck;
    string recovered_cplck;

    char*  CAPS_Char_ORigCTx;
    char*  ctx_typo_cplckBytes;
    size_t TradCtxSize = 2 * sizeof(size_t) +  PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2;
    size_t CondCtxSize = 3 * sizeof(size_t) + 24 * sizeof(char) +   PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2;
//    char*  CAPS_Char_ORigCTx = (char*) malloc (2 * sizeof(size_t) +  PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2);
//    char*  ctx_typo_cplckBytes = (char*) malloc (2 * sizeof(size_t) +  PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2);


    vector<double> T_Enc_CondEncCAPLK[Num_tests];
    vector<double> T_CondEnc_CondEncCAPLK[Num_tests];
    vector<double> T_CondDec_CondEncCAPLK[Num_tests];

    double duration_CondEnc_CAP_Sum = 0;
    double duration_Enc_CAP_Sum = 0;
    double duration_CondDec_CAP_Sum = 0;

    ofstream CondEncCPSLCK;
    CondEncCPSLCK.open("CondEncCPSLCK.txt");
    CondEncCPSLCK << "The predicate is CPSLCK key ON ******************\n \n ";

    for(int T = 0; T< Num_tests; T++) {

        char CAPS_Char_ORigCTx[2 * sizeof(size_t) +  PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2];
        char ctx_typo_cplckBytes[ 3 * sizeof(size_t) + (sizeof(char) * 24)  +   PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2];

        auto start_Enc_CAP = high_resolution_clock::now();
        int CApsOrigCtxtRslt = CAPLOCKpredicate::Enc(pkobj._ppk, msg, CAPS_Char_ORigCTx);
        auto stop_Enc_CAP = high_resolution_clock::now();
        auto duration_Enc_CAP = duration_cast<milliseconds>(stop_Enc_CAP - start_Enc_CAP);

        auto start_CondEnc_CAP = high_resolution_clock::now();
        auto CPSLKCondEncRlt =  CAPLOCKpredicate::CondEnc(pkobj._ppk, CAPS_Char_ORigCTx, typo, payload,_len, threshold,  ctx_typo_cplckBytes);
        auto stop_CondEnc_CAP = high_resolution_clock::now();
        auto duration_CondEnc_CAP = duration_cast<milliseconds>(stop_CondEnc_CAP - start_CondEnc_CAP);


        auto start_CondDec_CAP = high_resolution_clock::now();
        string recovered_cplckBytes;
        int CondDecOut = 0;
        CondDecOut = CAPLOCKpredicate::CondDec(pkobj._ppk, ctx_typo_cplckBytes, pkobj._psk, 29, recovered_cplckBytes, msg.size(), 28);
        auto stop_CondDec_CAP = high_resolution_clock::now();
        auto duration_CondDec_CAP = duration_cast<milliseconds>(stop_CondDec_CAP - start_CondDec_CAP);


        CondEncCPSLCK << "Enc.Time, CondEnc.Time, Cond.Dec.Time, Ctx.Size, CondCtx.Size, CondDecRslt: (" <<
                      duration_Enc_CAP.count()
                      << ", " << duration_CondEnc_CAP.count()
                      << ", " << duration_CondDec_CAP.count()
                      << ", " << TradCtxSize
                      << ", " << CondCtxSize
                      << ", " << CondDecOut << " )\n";

//        free(CAPS_Char_ORigCTx);
//        free(ctx_typo_cplckBytes);

        duration_Enc_CAP_Sum =  duration_Enc_CAP_Sum + duration_Enc_CAP.count();
        duration_CondEnc_CAP_Sum =  duration_CondEnc_CAP_Sum + duration_CondEnc_CAP.count();
        duration_CondDec_CAP_Sum =  duration_CondDec_CAP_Sum + duration_CondDec_CAP.count();

    }

    std::ofstream EDOnedataL("CAPSLKdataL.dat", std::ios_base::app | std::ios_base::out);

//    HDdataL << "T\tL\t" << "Enc\tCondEnc\tCondDec\tCondCtxtSize\tCondCtxtSize\n";
//    int MaxDist = 1;

    EDOnedataL << "8" << "\t" << duration_Enc_CAP_Sum / Num_tests << "\t"
               << duration_CondEnc_CAP_Sum / Num_tests << "\t"
               << duration_CondDec_CAP_Sum / Num_tests << "\t"
               << CondCtxSize << "\t"
               << TradCtxSize << "\n";

    CondEncCPSLCK.close();
    paillier_freepubkey(pkobj._ppk);
    paillier_freeprvkey(pkobj._psk);
    cout << "CAPSLCOK is finished \n";
}

TEST_CASE("Conditional Encryption: CAPSLOCK ON predicate L = 32")
{
    PwPkCrypto pkobj;
    pkobj.Paill_pk_init(1024);
    int Num_tests = 20;
    size_t _len = 32;
    int threshold = _len -2;

    string msg = "Hassan";
    string typo = "hASSAN";
    string payload = "hASSAN";

    string  ctx_cplck;
    string ctx_typo_cplck;
    string recovered_cplck;

    char*  CAPS_Char_ORigCTx;
    char*  ctx_typo_cplckBytes;
    size_t TradCtxSize = 2 * sizeof(size_t) +  PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2;
    size_t CondCtxSize = 3 * sizeof(size_t) + 24 * sizeof(char) +   PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2;
//    char*  CAPS_Char_ORigCTx = (char*) malloc (2 * sizeof(size_t) +  PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2);
//    char*  ctx_typo_cplckBytes = (char*) malloc (2 * sizeof(size_t) +  PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2);


    vector<double> T_Enc_CondEncCAPLK[Num_tests];
    vector<double> T_CondEnc_CondEncCAPLK[Num_tests];
    vector<double> T_CondDec_CondEncCAPLK[Num_tests];

    double duration_CondEnc_CAP_Sum = 0;
    double duration_Enc_CAP_Sum = 0;
    double duration_CondDec_CAP_Sum = 0;

    ofstream CondEncCPSLCK;
    CondEncCPSLCK.open("CondEncCPSLCK.txt");
    CondEncCPSLCK << "The predicate is CPSLCK key ON ******************\n \n ";

    for(int T = 0; T< Num_tests; T++) {

        char CAPS_Char_ORigCTx[2 * sizeof(size_t) +  PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2];
        char ctx_typo_cplckBytes[ 3 * sizeof(size_t) + (sizeof(char) * 24)  +   PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2];

        auto start_Enc_CAP = high_resolution_clock::now();
        int CApsOrigCtxtRslt = CAPLOCKpredicate::Enc(pkobj._ppk, msg, CAPS_Char_ORigCTx);
        auto stop_Enc_CAP = high_resolution_clock::now();
        auto duration_Enc_CAP = duration_cast<milliseconds>(stop_Enc_CAP - start_Enc_CAP);

        auto start_CondEnc_CAP = high_resolution_clock::now();
        auto CPSLKCondEncRlt =  CAPLOCKpredicate::CondEnc(pkobj._ppk, CAPS_Char_ORigCTx, typo, payload,_len, threshold,  ctx_typo_cplckBytes);
        auto stop_CondEnc_CAP = high_resolution_clock::now();
        auto duration_CondEnc_CAP = duration_cast<milliseconds>(stop_CondEnc_CAP - start_CondEnc_CAP);


        auto start_CondDec_CAP = high_resolution_clock::now();
        string recovered_cplckBytes;
        int CondDecOut = 0;
        CondDecOut = CAPLOCKpredicate::CondDec(pkobj._ppk, ctx_typo_cplckBytes, pkobj._psk, 29, recovered_cplckBytes, msg.size(), 28);
        auto stop_CondDec_CAP = high_resolution_clock::now();
        auto duration_CondDec_CAP = duration_cast<milliseconds>(stop_CondDec_CAP - start_CondDec_CAP);


        CondEncCPSLCK << "Enc.Time, CondEnc.Time, Cond.Dec.Time, Ctx.Size, CondCtx.Size, CondDecRslt: (" <<
                      duration_Enc_CAP.count()
                      << ", " << duration_CondEnc_CAP.count()
                      << ", " << duration_CondDec_CAP.count()
                      << ", " << TradCtxSize
                      << ", " << CondCtxSize
                      << ", " << CondDecOut << " )\n";

//        free(CAPS_Char_ORigCTx);
//        free(ctx_typo_cplckBytes);

        duration_Enc_CAP_Sum =  duration_Enc_CAP_Sum + duration_Enc_CAP.count();
        duration_CondEnc_CAP_Sum =  duration_CondEnc_CAP_Sum + duration_CondEnc_CAP.count();
        duration_CondDec_CAP_Sum =  duration_CondDec_CAP_Sum + duration_CondDec_CAP.count();

    }

    std::ofstream EDOnedataL("CAPSLKdataL.dat", std::ios_base::app | std::ios_base::out);

//    HDdataL << "T\tL\t" << "Enc\tCondEnc\tCondDec\tCondCtxtSize\tCondCtxtSize\n";
//    int MaxDist = 1;

    EDOnedataL << "8" << "\t" << duration_Enc_CAP_Sum / Num_tests << "\t"
               << duration_CondEnc_CAP_Sum / Num_tests << "\t"
               << duration_CondDec_CAP_Sum / Num_tests << "\t"
               << CondCtxSize << "\t"
               << TradCtxSize << "\n";

    CondEncCPSLCK.close();
    paillier_freepubkey(pkobj._ppk);
    paillier_freeprvkey(pkobj._psk);
    cout << "CAPSLCOK is finished \n";
}

TEST_CASE("Conditional Encryption: CAPSLOCK ON predicate L = 64")
{
    PwPkCrypto pkobj;
    pkobj.Paill_pk_init(1024);
    int Num_tests = 20;
    size_t _len = 64;
    int threshold = _len -2;


    string msg = "Hassan";
    string typo = "hASSAN";
    string payload = "hASSAN";

    string  ctx_cplck;
    string ctx_typo_cplck;
    string recovered_cplck;

    char*  CAPS_Char_ORigCTx;
    char*  ctx_typo_cplckBytes;
    size_t TradCtxSize = 2 * sizeof(size_t) +  PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2;
    size_t CondCtxSize = 3 * sizeof(size_t) + 24 * sizeof(char) +   PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2;
//    char*  CAPS_Char_ORigCTx = (char*) malloc (2 * sizeof(size_t) +  PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2);
//    char*  ctx_typo_cplckBytes = (char*) malloc (2 * sizeof(size_t) +  PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2);


    vector<double> T_Enc_CondEncCAPLK[Num_tests];
    vector<double> T_CondEnc_CondEncCAPLK[Num_tests];
    vector<double> T_CondDec_CondEncCAPLK[Num_tests];

    double duration_CondEnc_CAP_Sum = 0;
    double duration_Enc_CAP_Sum = 0;
    double duration_CondDec_CAP_Sum = 0;

    ofstream CondEncCPSLCK;
    CondEncCPSLCK.open("CondEncCPSLCK.txt");
    CondEncCPSLCK << "The predicate is CPSLCK key ON ******************\n \n ";

    for(int T = 0; T< Num_tests; T++) {

        char CAPS_Char_ORigCTx[2 * sizeof(size_t) +  PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2];
        char ctx_typo_cplckBytes[ 3 * sizeof(size_t) + (sizeof(char) * 24)  +   PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2];

        auto start_Enc_CAP = high_resolution_clock::now();
        int CApsOrigCtxtRslt = CAPLOCKpredicate::Enc(pkobj._ppk, msg, CAPS_Char_ORigCTx);
        auto stop_Enc_CAP = high_resolution_clock::now();
        auto duration_Enc_CAP = duration_cast<milliseconds>(stop_Enc_CAP - start_Enc_CAP);

        auto start_CondEnc_CAP = high_resolution_clock::now();
        auto CPSLKCondEncRlt =  CAPLOCKpredicate::CondEnc(pkobj._ppk, CAPS_Char_ORigCTx, typo, payload,_len, threshold,  ctx_typo_cplckBytes);
        auto stop_CondEnc_CAP = high_resolution_clock::now();
        auto duration_CondEnc_CAP = duration_cast<milliseconds>(stop_CondEnc_CAP - start_CondEnc_CAP);


        auto start_CondDec_CAP = high_resolution_clock::now();
        string recovered_cplckBytes;
        int CondDecOut = 0;
        CondDecOut = CAPLOCKpredicate::CondDec(pkobj._ppk, ctx_typo_cplckBytes, pkobj._psk, 29, recovered_cplckBytes, msg.size(), 28);
        auto stop_CondDec_CAP = high_resolution_clock::now();
        auto duration_CondDec_CAP = duration_cast<milliseconds>(stop_CondDec_CAP - start_CondDec_CAP);


        CondEncCPSLCK << "Enc.Time, CondEnc.Time, Cond.Dec.Time, Ctx.Size, CondCtx.Size, CondDecRslt: (" <<
                      duration_Enc_CAP.count()
                      << ", " << duration_CondEnc_CAP.count()
                      << ", " << duration_CondDec_CAP.count()
                      << ", " << TradCtxSize
                      << ", " << CondCtxSize
                      << ", " << CondDecOut << " )\n";

//        free(CAPS_Char_ORigCTx);
//        free(ctx_typo_cplckBytes);

        duration_Enc_CAP_Sum =  duration_Enc_CAP_Sum + duration_Enc_CAP.count();
        duration_CondEnc_CAP_Sum =  duration_CondEnc_CAP_Sum + duration_CondEnc_CAP.count();
        duration_CondDec_CAP_Sum =  duration_CondDec_CAP_Sum + duration_CondDec_CAP.count();

    }

    std::ofstream EDOnedataL("CAPSLKdataL.dat", std::ios_base::app | std::ios_base::out);

//    HDdataL << "T\tL\t" << "Enc\tCondEnc\tCondDec\tCondCtxtSize\tCondCtxtSize\n";
//    int MaxDist = 1;

    EDOnedataL << "8" << "\t" << duration_Enc_CAP_Sum / Num_tests << "\t"
               << duration_CondEnc_CAP_Sum / Num_tests << "\t"
               << duration_CondDec_CAP_Sum / Num_tests << "\t"
               << CondCtxSize << "\t"
               << TradCtxSize << "\n";

    CondEncCPSLCK.close();
    paillier_freepubkey(pkobj._ppk);
    paillier_freeprvkey(pkobj._psk);
    cout << "CAPSLCOK is finished \n";
}

TEST_CASE("Conditional Encryption: CAPSLOCK ON predicate L = 128")
{
    PwPkCrypto pkobj;
    pkobj.Paill_pk_init(1024);
    int Num_tests = 20;
    size_t _len = 128;
    int threshold = _len -2;


    string msg = "Hassan";
    string typo = "hASSAN";
    string payload = "hASSAN";

    string  ctx_cplck;
    string ctx_typo_cplck;
    string recovered_cplck;

    char*  CAPS_Char_ORigCTx;
    char*  ctx_typo_cplckBytes;
    size_t TradCtxSize = 2 * sizeof(size_t) +  PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2;
    size_t CondCtxSize = 3 * sizeof(size_t) + 24 * sizeof(char) +   PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2;
//    char*  CAPS_Char_ORigCTx = (char*) malloc (2 * sizeof(size_t) +  PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2);
//    char*  ctx_typo_cplckBytes = (char*) malloc (2 * sizeof(size_t) +  PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2);


    vector<double> T_Enc_CondEncCAPLK[Num_tests];
    vector<double> T_CondEnc_CondEncCAPLK[Num_tests];
    vector<double> T_CondDec_CondEncCAPLK[Num_tests];

    double duration_CondEnc_CAP_Sum = 0;
    double duration_Enc_CAP_Sum = 0;
    double duration_CondDec_CAP_Sum = 0;

    ofstream CondEncCPSLCK;
    CondEncCPSLCK.open("CondEncCPSLCK.txt");
    CondEncCPSLCK << "The predicate is CPSLCK key ON ******************\n \n ";

    for(int T = 0; T< Num_tests; T++) {

        char CAPS_Char_ORigCTx[2 * sizeof(size_t) +  PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2];
        char ctx_typo_cplckBytes[ 3 * sizeof(size_t) + (sizeof(char) * 24)  +   PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2];

        auto start_Enc_CAP = high_resolution_clock::now();
        int CApsOrigCtxtRslt = CAPLOCKpredicate::Enc(pkobj._ppk, msg, CAPS_Char_ORigCTx);
        auto stop_Enc_CAP = high_resolution_clock::now();
        auto duration_Enc_CAP = duration_cast<milliseconds>(stop_Enc_CAP - start_Enc_CAP);

        auto start_CondEnc_CAP = high_resolution_clock::now();
        auto CPSLKCondEncRlt =  CAPLOCKpredicate::CondEnc(pkobj._ppk, CAPS_Char_ORigCTx, typo, payload,_len, threshold,  ctx_typo_cplckBytes);
        auto stop_CondEnc_CAP = high_resolution_clock::now();
        auto duration_CondEnc_CAP = duration_cast<milliseconds>(stop_CondEnc_CAP - start_CondEnc_CAP);


        auto start_CondDec_CAP = high_resolution_clock::now();
        string recovered_cplckBytes;
        int CondDecOut = 0;
        CondDecOut = CAPLOCKpredicate::CondDec(pkobj._ppk, ctx_typo_cplckBytes, pkobj._psk, 29, recovered_cplckBytes, msg.size(), 28);
        auto stop_CondDec_CAP = high_resolution_clock::now();
        auto duration_CondDec_CAP = duration_cast<milliseconds>(stop_CondDec_CAP - start_CondDec_CAP);


        CondEncCPSLCK << "Enc.Time, CondEnc.Time, Cond.Dec.Time, Ctx.Size, CondCtx.Size, CondDecRslt: (" <<
                      duration_Enc_CAP.count()
                      << ", " << duration_CondEnc_CAP.count()
                      << ", " << duration_CondDec_CAP.count()
                      << ", " << TradCtxSize
                      << ", " << CondCtxSize
                      << ", " << CondDecOut << " )\n";

//        free(CAPS_Char_ORigCTx);
//        free(ctx_typo_cplckBytes);

        duration_Enc_CAP_Sum =  duration_Enc_CAP_Sum + duration_Enc_CAP.count();
        duration_CondEnc_CAP_Sum =  duration_CondEnc_CAP_Sum + duration_CondEnc_CAP.count();
        duration_CondDec_CAP_Sum =  duration_CondDec_CAP_Sum + duration_CondDec_CAP.count();

    }

    std::ofstream EDOnedataL("CAPSLKdataL.dat", std::ios_base::app | std::ios_base::out);

//    HDdataL << "T\tL\t" << "Enc\tCondEnc\tCondDec\tCondCtxtSize\tCondCtxtSize\n";
//    int MaxDist = 1;

    EDOnedataL << "8" << "\t" << duration_Enc_CAP_Sum / Num_tests << "\t"
               << duration_CondEnc_CAP_Sum / Num_tests << "\t"
               << duration_CondDec_CAP_Sum / Num_tests << "\t"
               << CondCtxSize << "\t"
               << TradCtxSize << "\n";

    CondEncCPSLCK.close();
    paillier_freepubkey(pkobj._ppk);
    paillier_freeprvkey(pkobj._psk);
    cout << "CAPSLCOK is finished \n";
}



TEST_CASE("Conditional Encryption: Edit Distance One predicate Two errors, L=8")
{
    PwPkCrypto pkobj;
    pkobj.Paill_pk_init(1024);
    int Num_tests = 20;
    size_t _len = 8;
    size_t threshold = _len -2;


    string msg = "TEST";

    string msg_pad = CryptoSymWrapperFunctions::Wrapper_pad(msg, _len);


    size_t TradCtxSize = 2 * sizeof(size_t) + ( _len+1) *  PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2;
    size_t CondCtxSize = 3 * sizeof(size_t) + 24 + (_len + _len +1) * PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2;

    double duration_CondEnc_ED1_Sum = 0;
    double duration_Enc_ED1_Sum = 0;
    double duration_CondDec_ED1_Sum = 0;

    ofstream CondEncED1;
    CondEncED1.open("CondEncED1TwoErr.txt");
    CondEncED1 << "The predicate is Edit distance One [two errors] ******************\n \n ";

    for(int T = 0; T< Num_tests; T++) {
        char ED1_Char_ORigCTx [2 * sizeof(size_t) + (_len + 1)  *  PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2];
        char ED1_ctx_typo_Bytes [ ((( 3 * sizeof(size_t) )+ 24 * sizeof (char)) + ((2*_len + 1) *  PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2))];
        string typo;
        /*Randomly making typo and the payload*/
        unsigned seed= time(0);
        int NumOfErrs = 0;
        char err1;
        srand(seed);
//        NumOfErrs =rand() % 3;
        NumOfErrs = 1;
        if (NumOfErrs== 0)
        {
            typo = msg;
        }
        else if (NumOfErrs == 1)
        {
            err1 = _len + (rand() % 95);
            int ErrLction;
            ErrLction = rand() % msg.size();
            typo = msg.substr(0, ErrLction) +  err1 + msg.substr(ErrLction, msg.size()) + err1;
//            ErrLction++;
//            typo[ErrLction] = err1;
        } else if (NumOfErrs == 2)
        {
            int ErrLction, ErrLction2;
            ErrLction = rand() % msg.size();
            typo = msg.substr(0, ErrLction) + msg.substr(ErrLction+1, msg.size());
        }
        string payload = typo;
        string pad_typo = CryptoSymWrapperFunctions::Wrapper_pad(typo, _len);
        /* ============ */


        auto start_Enc_HD2 = high_resolution_clock::now();
        int OrigEncRst = 0;
        OrigEncRst = EditDistOne::Enc(pkobj._ppk, msg_pad, ED1_Char_ORigCTx);
        auto stop_Enc_HD2 = high_resolution_clock::now();
        auto duration_Enc_HD2 = duration_cast<milliseconds>(stop_Enc_HD2 - start_Enc_HD2);

        auto start_CondEnc_HD2 = high_resolution_clock::now();
//        int ED1CondEncRstl =0;
        auto ctx_final =  EditDistOne::CondEnc(pkobj._ppk, ED1_Char_ORigCTx, pad_typo, payload,_len, threshold, ED1_ctx_typo_Bytes);
        auto stop_CondEnc_HD2 = high_resolution_clock::now();
        auto duration_CondEnc_HD2 = duration_cast<milliseconds>(stop_CondEnc_HD2 - start_CondEnc_HD2);


        auto start_CondDec_HD2 = high_resolution_clock::now();
        string recovered_hd2Bytes;
        int CondDecOut = 0;
        CondDecOut = EditDistOne::CondDec(pkobj._ppk, ED1_ctx_typo_Bytes, pkobj._psk, threshold, recovered_hd2Bytes, _len, 28);
        auto stop_CondDec_HD2 = high_resolution_clock::now();
        auto duration_CondDec_HD2 = duration_cast<milliseconds>(stop_CondDec_HD2 - start_CondDec_HD2);

//        free(ED1_Char_ORigCTx);
//        free(ED1_ctx_typo_Bytes);

        CondEncED1 << "Enc.Time, CondEnc.Time, Cond.Dec.Time, Ctx.Size, CondCtx.Size, CondDecRslt: (" <<
                   duration_Enc_HD2.count()
                   << ", " << duration_CondEnc_HD2.count()
                   << ", " << duration_CondDec_HD2.count()
                   << ", " << TradCtxSize
                   << ", " << CondCtxSize
                   << ", " << CondDecOut << " )\n";


        duration_Enc_ED1_Sum =  duration_Enc_ED1_Sum + duration_Enc_HD2.count();
        duration_CondEnc_ED1_Sum =  duration_CondEnc_ED1_Sum + duration_CondEnc_HD2.count();
        duration_CondDec_ED1_Sum =  duration_CondDec_ED1_Sum + duration_CondDec_HD2.count();

    }

    std::ofstream EDOnedataL("EDOnedataL.dat", std::ios_base::app | std::ios_base::out);

//    HDdataL << "T\tL\t" << "Enc\tCondEnc\tCondDec\tCondCtxtSize\tCondCtxtSize\n";
//    int MaxDist = 1;

    EDOnedataL << _len << "\t" << duration_Enc_ED1_Sum / Num_tests << "\t"
               << duration_CondEnc_ED1_Sum / Num_tests << "\t"
               << duration_CondDec_ED1_Sum / Num_tests << "\t"
               << CondCtxSize << "\t"
               << TradCtxSize << "\n";

    CondEncED1.close();
    paillier_freepubkey(pkobj._ppk);
    paillier_freeprvkey(pkobj._psk);
    cout << "Edit distacne One TwoErrs is finished, L = 8 \n";
}

TEST_CASE("Conditional Encryption: Edit Distance One predicate Two errors, L=16")
{
    PwPkCrypto pkobj;
    pkobj.Paill_pk_init(1024);
    int Num_tests = 20;
    size_t _len = 16;
    size_t threshold = _len -2;


    string msg = "TEST";

    string msg_pad = CryptoSymWrapperFunctions::Wrapper_pad(msg, _len);


    size_t TradCtxSize = 2 * sizeof(size_t) + ( _len + 1) *  PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2;
    size_t CondCtxSize = 3 * sizeof(size_t) + 24 + (_len + _len +1) * PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2;

    double duration_CondEnc_ED1_Sum = 0;
    double duration_Enc_ED1_Sum = 0;
    double duration_CondDec_ED1_Sum = 0;

    ofstream CondEncED1;
    CondEncED1.open("CondEncED1TwoErr.txt");
    CondEncED1 << "The predicate is Edit distance One [two errors] ******************\n \n ";

    for(int T = 0; T< Num_tests; T++) {
        char ED1_Char_ORigCTx [2 * sizeof(size_t) + (_len + 1)  *  PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2];
        char ED1_ctx_typo_Bytes [ ((( 3 * sizeof(size_t) )+ 24 * sizeof (char)) + ((2*_len + 1) *  PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2))];
        string typo;
        /*Randomly making typo and the payload*/
        unsigned seed= time(0);
        int NumOfErrs = 0;
        char err1;
        srand(seed);
//        NumOfErrs =rand() % 3;
        NumOfErrs = 1;
        if (NumOfErrs== 0)
        {
            typo = msg;
        }
        else if (NumOfErrs == 1)
        {
            err1 = _len + (rand() % 95);
            int ErrLction;
            ErrLction = rand() % msg.size();
            typo = msg.substr(0, ErrLction) +  err1 + msg.substr(ErrLction, msg.size()) + err1;
//            ErrLction++;
//            typo[ErrLction] = err1;
        } else if (NumOfErrs == 2)
        {
            int ErrLction, ErrLction2;
            ErrLction = rand() % msg.size();
            typo = msg.substr(0, ErrLction) + msg.substr(ErrLction+1, msg.size());
        }
        string payload = typo;
        string pad_typo = CryptoSymWrapperFunctions::Wrapper_pad(typo, _len);
        /* ============ */


        auto start_Enc_HD2 = high_resolution_clock::now();
        int OrigEncRst = 0;
        OrigEncRst = EditDistOne::Enc(pkobj._ppk, msg_pad, ED1_Char_ORigCTx);
        auto stop_Enc_HD2 = high_resolution_clock::now();
        auto duration_Enc_HD2 = duration_cast<milliseconds>(stop_Enc_HD2 - start_Enc_HD2);

        auto start_CondEnc_HD2 = high_resolution_clock::now();
//        int ED1CondEncRstl =0;
        auto ctx_final =  EditDistOne::CondEnc(pkobj._ppk, ED1_Char_ORigCTx, pad_typo, payload,_len, threshold, ED1_ctx_typo_Bytes);
        auto stop_CondEnc_HD2 = high_resolution_clock::now();
        auto duration_CondEnc_HD2 = duration_cast<milliseconds>(stop_CondEnc_HD2 - start_CondEnc_HD2);


        auto start_CondDec_HD2 = high_resolution_clock::now();
        string recovered_hd2Bytes;
        int CondDecOut = 0;
        CondDecOut = EditDistOne::CondDec(pkobj._ppk, ED1_ctx_typo_Bytes, pkobj._psk, threshold, recovered_hd2Bytes, _len, 28);
        auto stop_CondDec_HD2 = high_resolution_clock::now();
        auto duration_CondDec_HD2 = duration_cast<milliseconds>(stop_CondDec_HD2 - start_CondDec_HD2);

//        free(ED1_Char_ORigCTx);
//        free(ED1_ctx_typo_Bytes);

        CondEncED1 << "Enc.Time, CondEnc.Time, Cond.Dec.Time, Ctx.Size, CondCtx.Size, CondDecRslt: (" <<
                   duration_Enc_HD2.count()
                   << ", " << duration_CondEnc_HD2.count()
                   << ", " << duration_CondDec_HD2.count()
                   << ", " << TradCtxSize
                   << ", " << CondCtxSize
                   << ", " << CondDecOut << " )\n";


        duration_Enc_ED1_Sum =  duration_Enc_ED1_Sum + duration_Enc_HD2.count();
        duration_CondEnc_ED1_Sum =  duration_CondEnc_ED1_Sum + duration_CondEnc_HD2.count();
        duration_CondDec_ED1_Sum =  duration_CondDec_ED1_Sum + duration_CondDec_HD2.count();

    }

    std::ofstream EDOnedataL("EDOnedataL.dat", std::ios_base::app | std::ios_base::out);

//    HDdataL << "T\tL\t" << "Enc\tCondEnc\tCondDec\tCondCtxtSize\tCondCtxtSize\n";
//    int MaxDist = 1;

    EDOnedataL << _len << "\t" << duration_Enc_ED1_Sum / Num_tests << "\t"
               << duration_CondEnc_ED1_Sum / Num_tests << "\t"
               << duration_CondDec_ED1_Sum / Num_tests << "\t"
               << CondCtxSize << "\t"
               << TradCtxSize << "\n";

    CondEncED1.close();
    paillier_freepubkey(pkobj._ppk);
    paillier_freeprvkey(pkobj._psk);
    cout << "Edit distacne One TwoErrs is finished, L = 16 \n";
}

TEST_CASE("Conditional Encryption: Edit Distance One predicate Two errors, L=32")
{
    PwPkCrypto pkobj;
    pkobj.Paill_pk_init(1024);
    int Num_tests = 20;
    size_t _len = 32;
    size_t threshold = _len -2;

    string msg = "TEST";

    string msg_pad = CryptoSymWrapperFunctions::Wrapper_pad(msg, _len);


    size_t TradCtxSize = 2 * sizeof(size_t) + ( _len+1) *  PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2;
    size_t CondCtxSize = 3 * sizeof(size_t) + 24 + (_len + _len +1) * PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2;

    double duration_CondEnc_ED1_Sum = 0;
    double duration_Enc_ED1_Sum = 0;
    double duration_CondDec_ED1_Sum = 0;

    ofstream CondEncED1;
    CondEncED1.open("CondEncED1TwoErr.txt");
    CondEncED1 << "The predicate is Edit distance One [two errors] ******************\n \n ";

    for(int T = 0; T< Num_tests; T++) {
        char ED1_Char_ORigCTx [2 * sizeof(size_t) + (_len + 1)  *  PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2];
        char ED1_ctx_typo_Bytes [ ((( 3 * sizeof(size_t) )+ 24 * sizeof (char)) + ((2*_len + 1) *  PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2))];
        string typo;
        /*Randomly making typo and the payload*/
        unsigned seed= time(0);
        int NumOfErrs = 0;
        char err1;
        srand(seed);
//        NumOfErrs =rand() % 3;
        NumOfErrs = 1;
        if (NumOfErrs== 0)
        {
            typo = msg;
        }
        else if (NumOfErrs == 1)
        {
            err1 = _len + (rand() % 95);
            int ErrLction;
            ErrLction = rand() % msg.size();
            typo = msg.substr(0, ErrLction) +  err1 + msg.substr(ErrLction, msg.size()) + err1;
//            ErrLction++;
//            typo[ErrLction] = err1;
        } else if (NumOfErrs == 2)
        {
            int ErrLction, ErrLction2;
            ErrLction = rand() % msg.size();
            typo = msg.substr(0, ErrLction) + msg.substr(ErrLction+1, msg.size());
        }
        string payload = typo;
        string pad_typo = CryptoSymWrapperFunctions::Wrapper_pad(typo, _len);
        /* ============ */


        auto start_Enc_HD2 = high_resolution_clock::now();
        int OrigEncRst = 0;
        OrigEncRst = EditDistOne::Enc(pkobj._ppk, msg_pad, ED1_Char_ORigCTx);
        auto stop_Enc_HD2 = high_resolution_clock::now();
        auto duration_Enc_HD2 = duration_cast<milliseconds>(stop_Enc_HD2 - start_Enc_HD2);

        auto start_CondEnc_HD2 = high_resolution_clock::now();
//        int ED1CondEncRstl =0;
        auto ctx_final =  EditDistOne::CondEnc(pkobj._ppk, ED1_Char_ORigCTx, pad_typo, payload,_len, threshold, ED1_ctx_typo_Bytes);
        auto stop_CondEnc_HD2 = high_resolution_clock::now();
        auto duration_CondEnc_HD2 = duration_cast<milliseconds>(stop_CondEnc_HD2 - start_CondEnc_HD2);


        auto start_CondDec_HD2 = high_resolution_clock::now();
        string recovered_hd2Bytes;
        int CondDecOut = 0;
        CondDecOut = EditDistOne::CondDec(pkobj._ppk, ED1_ctx_typo_Bytes, pkobj._psk, threshold, recovered_hd2Bytes, _len, 28);
        auto stop_CondDec_HD2 = high_resolution_clock::now();
        auto duration_CondDec_HD2 = duration_cast<milliseconds>(stop_CondDec_HD2 - start_CondDec_HD2);

//        free(ED1_Char_ORigCTx);
//        free(ED1_ctx_typo_Bytes);

        CondEncED1 << "Enc.Time, CondEnc.Time, Cond.Dec.Time, Ctx.Size, CondCtx.Size, CondDecRslt: (" <<
                   duration_Enc_HD2.count()
                   << ", " << duration_CondEnc_HD2.count()
                   << ", " << duration_CondDec_HD2.count()
                   << ", " << TradCtxSize
                   << ", " << CondCtxSize
                   << ", " << CondDecOut << " )\n";


        duration_Enc_ED1_Sum =  duration_Enc_ED1_Sum + duration_Enc_HD2.count();
        duration_CondEnc_ED1_Sum =  duration_CondEnc_ED1_Sum + duration_CondEnc_HD2.count();
        duration_CondDec_ED1_Sum =  duration_CondDec_ED1_Sum + duration_CondDec_HD2.count();

    }

    std::ofstream EDOnedataL("EDOnedataL.dat", std::ios_base::app | std::ios_base::out);

//    HDdataL << "T\tL\t" << "Enc\tCondEnc\tCondDec\tCondCtxtSize\tCondCtxtSize\n";
//    int MaxDist = 1;

    EDOnedataL << _len << "\t" << duration_Enc_ED1_Sum / Num_tests << "\t"
            << duration_CondEnc_ED1_Sum / Num_tests << "\t"
            << duration_CondDec_ED1_Sum / Num_tests << "\t"
            << CondCtxSize << "\t"
            << TradCtxSize << "\n";

    CondEncED1.close();
    paillier_freepubkey(pkobj._ppk);
    paillier_freeprvkey(pkobj._psk);
    cout << "Edit distacne One TwoErrs is finished, L = 32 \n";
}

TEST_CASE("Conditional Encryption: Edit Distance One predicate Two errors, L=64")
{
    PwPkCrypto pkobj;
    pkobj.Paill_pk_init(1024);
    int Num_tests = 20;
    size_t _len = 64;
    size_t threshold = _len -2;

    string msg = "TEST";

    string msg_pad = CryptoSymWrapperFunctions::Wrapper_pad(msg, _len);


    size_t TradCtxSize = 2 * sizeof(size_t) + ( _len+1) *  PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2;
    size_t CondCtxSize = 3 * sizeof(size_t) + 24 + (_len + _len +1) * PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2;

    double duration_CondEnc_ED1_Sum = 0;
    double duration_Enc_ED1_Sum = 0;
    double duration_CondDec_ED1_Sum = 0;

    ofstream CondEncED1;
    CondEncED1.open("CondEncED1TwoErr.txt");
    CondEncED1 << "The predicate is Edit distance One [two errors] ******************\n \n ";

    for(int T = 0; T< Num_tests; T++) {
        char ED1_Char_ORigCTx [2 * sizeof(size_t) + (_len + 1)  *  PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2];
        char ED1_ctx_typo_Bytes [ ((( 3 * sizeof(size_t) )+ 24 * sizeof (char)) + ((2*_len + 1) *  PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2))];
        string typo;
        /*Randomly making typo and the payload*/
        unsigned seed= time(0);
        int NumOfErrs = 0;
        char err1;
        srand(seed);
//        NumOfErrs =rand() % 3;
        NumOfErrs = 1;
        if (NumOfErrs== 0)
        {
            typo = msg;
        }
        else if (NumOfErrs == 1)
        {
            err1 = _len + (rand() % 95);
            int ErrLction;
            ErrLction = rand() % msg.size();
            typo = msg.substr(0, ErrLction) +  err1 + msg.substr(ErrLction, msg.size()) + err1;
//            ErrLction++;
//            typo[ErrLction] = err1;
        } else if (NumOfErrs == 2)
        {
            int ErrLction, ErrLction2;
            ErrLction = rand() % msg.size();
            typo = msg.substr(0, ErrLction) + msg.substr(ErrLction+1, msg.size());
        }
        string payload = typo;
        string pad_typo = CryptoSymWrapperFunctions::Wrapper_pad(typo, _len);
        /* ============ */


        auto start_Enc_HD2 = high_resolution_clock::now();
        int OrigEncRst = 0;
        OrigEncRst = EditDistOne::Enc(pkobj._ppk, msg_pad, ED1_Char_ORigCTx);
        auto stop_Enc_HD2 = high_resolution_clock::now();
        auto duration_Enc_HD2 = duration_cast<milliseconds>(stop_Enc_HD2 - start_Enc_HD2);

        auto start_CondEnc_HD2 = high_resolution_clock::now();
//        int ED1CondEncRstl =0;
        auto ctx_final =  EditDistOne::CondEnc(pkobj._ppk, ED1_Char_ORigCTx, pad_typo, payload,_len, threshold, ED1_ctx_typo_Bytes);
        auto stop_CondEnc_HD2 = high_resolution_clock::now();
        auto duration_CondEnc_HD2 = duration_cast<milliseconds>(stop_CondEnc_HD2 - start_CondEnc_HD2);


        auto start_CondDec_HD2 = high_resolution_clock::now();
        string recovered_hd2Bytes;
        int CondDecOut = 0;
        CondDecOut = EditDistOne::CondDec(pkobj._ppk, ED1_ctx_typo_Bytes, pkobj._psk, threshold, recovered_hd2Bytes, _len, 28);
        auto stop_CondDec_HD2 = high_resolution_clock::now();
        auto duration_CondDec_HD2 = duration_cast<milliseconds>(stop_CondDec_HD2 - start_CondDec_HD2);

//        free(ED1_Char_ORigCTx);
//        free(ED1_ctx_typo_Bytes);

        CondEncED1 << "Enc.Time, CondEnc.Time, Cond.Dec.Time, Ctx.Size, CondCtx.Size, CondDecRslt: (" <<
                   duration_Enc_HD2.count()
                   << ", " << duration_CondEnc_HD2.count()
                   << ", " << duration_CondDec_HD2.count()
                   << ", " << TradCtxSize
                   << ", " << CondCtxSize
                   << ", " << CondDecOut << " )\n";


        duration_Enc_ED1_Sum =  duration_Enc_ED1_Sum + duration_Enc_HD2.count();
        duration_CondEnc_ED1_Sum =  duration_CondEnc_ED1_Sum + duration_CondEnc_HD2.count();
        duration_CondDec_ED1_Sum =  duration_CondDec_ED1_Sum + duration_CondDec_HD2.count();

    }

    std::ofstream EDOnedataL("EDOnedataL.dat", std::ios_base::app | std::ios_base::out);

//    HDdataL << "T\tL\t" << "Enc\tCondEnc\tCondDec\tCondCtxtSize\tCondCtxtSize\n";
//    int MaxDist = 1;

    EDOnedataL << _len << "\t" << duration_Enc_ED1_Sum / Num_tests << "\t"
               << duration_CondEnc_ED1_Sum / Num_tests << "\t"
               << duration_CondDec_ED1_Sum / Num_tests << "\t"
               << CondCtxSize << "\t"
               << TradCtxSize << "\n";

    CondEncED1.close();
    paillier_freepubkey(pkobj._ppk);
    paillier_freeprvkey(pkobj._psk);
    cout << "Edit distacne One TwoErrs is finished, L = 64 \n";
}

TEST_CASE("Conditional Encryption: Edit Distance One predicate Two errors, L=128")
{
    PwPkCrypto pkobj;
    pkobj.Paill_pk_init(1024);
    int Num_tests = 20;
    size_t _len = 128;
    size_t threshold = _len -2;

    string msg = "TEST";

    string msg_pad = CryptoSymWrapperFunctions::Wrapper_pad(msg, _len);


    size_t TradCtxSize = 2 * sizeof(size_t) + ( _len+1) *  PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2;
    size_t CondCtxSize = 3 * sizeof(size_t) + 24 + (_len + _len +1) * PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2;

    double duration_CondEnc_ED1_Sum = 0;
    double duration_Enc_ED1_Sum = 0;
    double duration_CondDec_ED1_Sum = 0;

    ofstream CondEncED1;
    CondEncED1.open("CondEncED1TwoErr.txt");
    CondEncED1 << "The predicate is Edit distance One [two errors] ******************\n \n ";

    for(int T = 0; T< Num_tests; T++) {
        char ED1_Char_ORigCTx [2 * sizeof(size_t) + (_len + 1)  *  PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2];
        char ED1_ctx_typo_Bytes [ ((( 3 * sizeof(size_t) )+ 24 * sizeof (char)) + ((2*_len + 1) *  PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2))];
        string typo;
        /*Randomly making typo and the payload*/
        unsigned seed= time(0);
        int NumOfErrs = 0;
        char err1;
        srand(seed);
//        NumOfErrs =rand() % 3;
        NumOfErrs = 1;
        if (NumOfErrs== 0)
        {
            typo = msg;
        }
        else if (NumOfErrs == 1)
        {
            err1 = _len + (rand() % 95);
            int ErrLction;
            ErrLction = rand() % msg.size();
            typo = msg.substr(0, ErrLction) +  err1 + msg.substr(ErrLction, msg.size()) + err1;
//            ErrLction++;
//            typo[ErrLction] = err1;
        } else if (NumOfErrs == 2)
        {
            int ErrLction, ErrLction2;
            ErrLction = rand() % msg.size();
            typo = msg.substr(0, ErrLction) + msg.substr(ErrLction+1, msg.size());
        }
        string payload = typo;
        string pad_typo = CryptoSymWrapperFunctions::Wrapper_pad(typo, _len);
        /* ============ */


        auto start_Enc_HD2 = high_resolution_clock::now();
        int OrigEncRst = 0;
        OrigEncRst = EditDistOne::Enc(pkobj._ppk, msg_pad, ED1_Char_ORigCTx);
        auto stop_Enc_HD2 = high_resolution_clock::now();
        auto duration_Enc_HD2 = duration_cast<milliseconds>(stop_Enc_HD2 - start_Enc_HD2);

        auto start_CondEnc_HD2 = high_resolution_clock::now();
//        int ED1CondEncRstl =0;
        auto ctx_final =  EditDistOne::CondEnc(pkobj._ppk, ED1_Char_ORigCTx, pad_typo, payload,_len, threshold, ED1_ctx_typo_Bytes);
        auto stop_CondEnc_HD2 = high_resolution_clock::now();
        auto duration_CondEnc_HD2 = duration_cast<milliseconds>(stop_CondEnc_HD2 - start_CondEnc_HD2);


        auto start_CondDec_HD2 = high_resolution_clock::now();
        string recovered_hd2Bytes;
        int CondDecOut = 0;
        CondDecOut = EditDistOne::CondDec(pkobj._ppk, ED1_ctx_typo_Bytes, pkobj._psk, threshold, recovered_hd2Bytes, _len, 28);
        auto stop_CondDec_HD2 = high_resolution_clock::now();
        auto duration_CondDec_HD2 = duration_cast<milliseconds>(stop_CondDec_HD2 - start_CondDec_HD2);

//        free(ED1_Char_ORigCTx);
//        free(ED1_ctx_typo_Bytes);

        CondEncED1 << "Enc.Time, CondEnc.Time, Cond.Dec.Time, Ctx.Size, CondCtx.Size, CondDecRslt: (" <<
                   duration_Enc_HD2.count()
                   << ", " << duration_CondEnc_HD2.count()
                   << ", " << duration_CondDec_HD2.count()
                   << ", " << TradCtxSize
                   << ", " << CondCtxSize
                   << ", " << CondDecOut << " )\n";


        duration_Enc_ED1_Sum =  duration_Enc_ED1_Sum + duration_Enc_HD2.count();
        duration_CondEnc_ED1_Sum =  duration_CondEnc_ED1_Sum + duration_CondEnc_HD2.count();
        duration_CondDec_ED1_Sum =  duration_CondDec_ED1_Sum + duration_CondDec_HD2.count();

    }

    std::ofstream EDOnedataL("EDOnedataL.dat", std::ios_base::app | std::ios_base::out);

//    HDdataL << "T\tL\t" << "Enc\tCondEnc\tCondDec\tCondCtxtSize\tCondCtxtSize\n";
//    int MaxDist = 1;

    EDOnedataL << _len << "\t" << duration_Enc_ED1_Sum / Num_tests << "\t"
               << duration_CondEnc_ED1_Sum / Num_tests << "\t"
               << duration_CondDec_ED1_Sum / Num_tests << "\t"
               << CondCtxSize << "\t"
               << TradCtxSize << "\n";

    CondEncED1.close();
    paillier_freepubkey(pkobj._ppk);
    paillier_freeprvkey(pkobj._psk);
    cout << "Edit distacne One TwoErrs is finished, L = 128 \n";
}


TEST_CASE("Conditional Encryption: Hamming Distance at most Two (Just for 32) [Threshold len-2, len =32] predicate")
{
    PwPkCrypto pkobj;
    pkobj.Paill_pk_init(1024);
    int Num_tests = 30;
    size_t _len = 32;
    int Threshold = _len - 2;

    string msg = "TheTestingPlainText";


    string msg_pad = CryptoSymWrapperFunctions::Wrapper_pad(msg, _len);
    int sizechar = sizeof(size_t);
//    unique_ptr<char []> ctx_final(new char[3 * sizeof(size_t) + (sizeof(char) * 24) + (32 *  256) + 1]);

//    char*  HD2_ctx_typo_Bytes = new char[3 * sizeof(size_t) + (sizeof(char) * 24) + (32 *  256) + 1];
//    char* HD2_ctx_typo_Bytes = (char*) malloc (  3 * sizeof(size_t) + (sizeof(char) * 24) + (32 *  256) );

    size_t TradCtxSize = 2 * sizeof(size_t) + _len *  PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2;
    size_t CondCtxSize = 3 * sizeof(size_t) + (sizeof(char) * 24) + (_len *  256);

    double duration_CondEnc_HD2_Sum = 0;
    double duration_Enc_HD2_Sum = 0;
    double duration_CondDec_HD2_Sum = 0;

    ofstream CondEncHD2;
    CondEncHD2.open("CondEncHDAtmostTwo.txt");
    CondEncHD2 << "The predicate is Hamming distance at most two [3 errors as wors case]******************\n \n ";

    for(int T = 0; T< Num_tests; T++) {
        char HD2_Char_ORigCTx [2 * sizeof(size_t) + _len *  PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2];
        char HD2_ctx_typo_Bytes[3 * sizeof(size_t) + (sizeof(char) * 24) + (_len *  256)];
        string typo =msg;
        string payload;

        /*Randomly making typo and the payload*/
        unsigned seed= time(0);
        int NumOfErrs = 0;
        char err1, err2, err3;
        srand(seed);
        NumOfErrs = 3;
//        NumOfErrs =rand() % 4;
        if (NumOfErrs == 1)
        {
            err1 = 32 + (rand() % 95);
            int ErrLction;
            ErrLction = rand() % (msg.size());
            typo[ErrLction] = err1;
        } else if (NumOfErrs == 2)
        {
            err1 = 32 + (rand() % 95);
            err2 = 32 + (rand() % 95);
            int ErrLction1, ErrLction2;
            ErrLction1 = rand() % msg.size();
            ErrLction2 = rand() % msg.size();
            typo[ErrLction1] = err1;
            typo[ErrLction2] = err2;
        } else if (NumOfErrs == 3)
        {
            err1 = 32 + (rand() % 95);
            err2 = 32 + (rand() % 95);
            err3 = 32 + (rand() % 95);
            int ErrLction1, ErrLction2, ErrLction3;
            ErrLction1 = rand() % msg.size();
            ErrLction2 = rand() % msg.size();
            ErrLction3 = rand() % msg.size();
            typo[ErrLction1] = err1;
            typo[ErrLction2] = err2;
            typo[ErrLction3] = err3;
        }
        payload = typo;
        string pad_typo = CryptoSymWrapperFunctions::Wrapper_pad(typo, _len);


        /* ============ */

        auto start_Enc_HD2 = high_resolution_clock::now();
        int tradEncRslt =0;
        tradEncRslt = HamDistTwo::Enc(pkobj._ppk, msg_pad, HD2_Char_ORigCTx);
        auto stop_Enc_HD2 = high_resolution_clock::now();
        auto duration_Enc_HD2 = duration_cast<milliseconds>(stop_Enc_HD2 - start_Enc_HD2);

        auto start_CondEnc_HD2 = high_resolution_clock::now();
//        char* CondEncRst = new char[3 * sizeof(size_t) + (sizeof(char) * 24) + (32 *  256) + 1];
//        memset(HD2_ctx_typo_Bytes, '\0', CondCtxSize);
        auto ctx_final = HamDistTwo::CondEnc(pkobj._ppk, HD2_Char_ORigCTx, typo, payload,_len, Threshold, HD2_ctx_typo_Bytes);
//        std::string* CtxtAEStrPre = (std::string*) malloc(sizeof(char) * 24);
//        std::string s;
//        memcpy(HD2_ctx_typo_Bytes + (3 * sizeof(size_t)), &ctx_final, sizeof(char) * 24);

//        std::string* CtxtAEStrPre = (std::string*) malloc(24);
//        memcpy(&CtxtAEStrPre[0], HD2_ctx_typo_Bytes + 3 * sizeof(size_t), 24 );

        auto stop_CondEnc_HD2 = high_resolution_clock::now();
        auto duration_CondEnc_HD2 = duration_cast<milliseconds>(stop_CondEnc_HD2 - start_CondEnc_HD2);

        auto start_CondDec_HD2 = high_resolution_clock::now();
        string recovered_hd2Bytes;
        int CondDecOut  = 0;
//        while (CondDecOut != 1)
//        {
        CondDecOut = HamDistTwo::CondDec(pkobj._ppk, HD2_ctx_typo_Bytes, pkobj._psk, Threshold, recovered_hd2Bytes, _len, 28);
//        }
        auto stop_CondDec_HD2 = high_resolution_clock::now();
        auto duration_CondDec_HD2 = duration_cast<milliseconds>(stop_CondDec_HD2 - start_CondDec_HD2);

//        free(HD2_Char_ORigCTx);
//        free(HD2_ctx_typo_Bytes);
//        delete [] HD2_ctx_typo_Bytes;
//        delete [] CondEncRst;
        CondEncHD2 << "Enc.Time, CondEnc.Time, Cond.Dec.Time, Ctx.Size, CondCtx.Size, CondDecRslt: (" <<
                   duration_Enc_HD2.count()
                   << ", " << duration_CondEnc_HD2.count()
                   << ", " << duration_CondDec_HD2.count()
                   << ", " << TradCtxSize
                   << ", " << CondCtxSize
                   << ", " << CondDecOut << " )\n";

        duration_Enc_HD2_Sum =  duration_Enc_HD2_Sum + duration_Enc_HD2.count();
        duration_CondEnc_HD2_Sum =  duration_CondEnc_HD2_Sum + duration_CondEnc_HD2.count();
        duration_CondDec_HD2_Sum =  duration_CondDec_HD2_Sum + duration_CondDec_HD2.count();

    }

    CondEncHD2 << "Average Enc, CondEnc, CondDec in msec: " <<
               duration_Enc_HD2_Sum / Num_tests
               << ", " <<  duration_CondEnc_HD2_Sum / Num_tests
               << ", " <<  duration_CondDec_HD2_Sum / Num_tests << ") \n";

    CondEncHD2.close();
    paillier_freepubkey(pkobj._ppk);
    paillier_freeprvkey(pkobj._psk);
    cout << "Hamming Distant  at most two [Threshold =_len -2, _len = 32] is finished \n";
}

TEST_CASE("Conditional Encryption: Hamming Distance at most Three (Just for 32)[Threshold len-3, len =32] predicate")
{
    PwPkCrypto pkobj;
    pkobj.Paill_pk_init(1024);
    int Num_tests = 20;
    size_t _len = 32;
    int Threshold = _len - 3;

    string msg = "TheTestingPlainText";


    string msg_pad = CryptoSymWrapperFunctions::Wrapper_pad(msg, _len);
    int sizechar = sizeof(size_t);
//    unique_ptr<char []> ctx_final(new char[3 * sizeof(size_t) + (sizeof(char) * 24) + (32 *  256) + 1]);

//    char*  HD2_ctx_typo_Bytes = new char[3 * sizeof(size_t) + (sizeof(char) * 24) + (32 *  256) + 1];
//    char* HD2_ctx_typo_Bytes = (char*) malloc (  3 * sizeof(size_t) + (sizeof(char) * 24) + (32 *  256) );

    size_t TradCtxSize = 2 * sizeof(size_t) + _len *  PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2;
    size_t CondCtxSize = 3 * sizeof(size_t) + (sizeof(char) * 24) + (_len *  256);
//    char*  CAPS_Char_ORigCTx = (char*) malloc (2 * sizeof(size_t) +  PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2);
//    char*  ctx_typo_cplckBytes = (char*) malloc (2 * sizeof(size_t) +  PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2);


//    vector<double> T_Enc_CondEncCAPLK[Num_tests];
//    vector<double> T_CondEnc_CondEncCAPLK[Num_tests];
//    vector<double> T_CondDec_CondEncCAPLK[Num_tests];

    double duration_CondEnc_HD2_Sum = 0;
    double duration_Enc_HD2_Sum = 0;
    double duration_CondDec_HD2_Sum = 0;

    ofstream CondEncHD2;
    CondEncHD2.open("CondEncHDThree.txt");
    CondEncHD2 << "The predicate is Hamming distance at most Three [four errs as worst case]******************\n \n ";

    for(int T = 0; T< Num_tests; T++) {
        char HD2_Char_ORigCTx [2 * sizeof(size_t) + _len *  PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2];
        char HD2_ctx_typo_Bytes[3 * sizeof(size_t) + (sizeof(char) * 24) + (_len *  256)];
        string typo =msg;
        string payload;

        /*Randomly making typo and the payload*/
        unsigned seed= time(0);
        int NumOfErrs = 0;
        char err1, err2, err3, err4;
        srand(seed);
        NumOfErrs = 4;
//        NumOfErrs =rand() % 4;
        if (NumOfErrs == 1)
        {
            err1 = 32 + (rand() % 95);
            int ErrLction;
            ErrLction = rand() % (msg.size());
            typo[ErrLction] = err1;
        } else if (NumOfErrs == 2)
        {
            err1 = 32 + (rand() % 95);
            err2 = 32 + (rand() % 95);
            int ErrLction1, ErrLction2;
            ErrLction1 = rand() % msg.size();
            ErrLction2 = rand() % msg.size();
            typo[ErrLction1] = err1;
            typo[ErrLction2] = err2;
        } else if (NumOfErrs == 3)
        {
            err1 = 32 + (rand() % 95);
            err2 = 32 + (rand() % 95);
            err3 = 32 + (rand() % 95);
            int ErrLction1, ErrLction2, ErrLction3;
            ErrLction1 = rand() % msg.size();
            ErrLction2 = rand() % msg.size();
            ErrLction3 = rand() % msg.size();
            typo[ErrLction1] = err1;
            typo[ErrLction2] = err2;
            typo[ErrLction3] = err3;
        }else if (NumOfErrs == 4)
        {
            err1 = 32 + (rand() % 95);
            err2 = 32 + (rand() % 95);
            err3 = 32 + (rand() % 95);
            err4 = 32 + (rand() % 95);
            int ErrLction1, ErrLction2, ErrLction3, ErrLction4;
            ErrLction1 = rand() % msg.size();
            ErrLction2 = rand() % msg.size();
            ErrLction3 = rand() % msg.size();
            ErrLction4 = rand() % msg.size();
            typo[ErrLction1] = err1;
            typo[ErrLction2] = err2;
            typo[ErrLction3] = err3;
            typo[ErrLction4] = err4;
        }
        payload = typo;
        string pad_typo = CryptoSymWrapperFunctions::Wrapper_pad(typo, _len);


        /* ============ */

        auto start_Enc_HD2 = high_resolution_clock::now();
        int tradEncRslt =0;
        tradEncRslt = HamDistTwo::Enc(pkobj._ppk, msg_pad, HD2_Char_ORigCTx);
        auto stop_Enc_HD2 = high_resolution_clock::now();
        auto duration_Enc_HD2 = duration_cast<milliseconds>(stop_Enc_HD2 - start_Enc_HD2);

        auto start_CondEnc_HD2 = high_resolution_clock::now();
//        char* CondEncRst = new char[3 * sizeof(size_t) + (sizeof(char) * 24) + (32 *  256) + 1];
//        memset(HD2_ctx_typo_Bytes, '\0', CondCtxSize);
        auto ctx_final = HamDistTwo::CondEnc(pkobj._ppk, HD2_Char_ORigCTx, typo, payload,_len, Threshold, HD2_ctx_typo_Bytes);
//        std::string* CtxtAEStrPre = (std::string*) malloc(sizeof(char) * 24);
//        std::string s;
//        memcpy(HD2_ctx_typo_Bytes + (3 * sizeof(size_t)), &ctx_final, sizeof(char) * 24);

//        std::string* CtxtAEStrPre = (std::string*) malloc(24);
//        memcpy(&CtxtAEStrPre[0], HD2_ctx_typo_Bytes + 3 * sizeof(size_t), 24 );

        auto stop_CondEnc_HD2 = high_resolution_clock::now();
        auto duration_CondEnc_HD2 = duration_cast<milliseconds>(stop_CondEnc_HD2 - start_CondEnc_HD2);

        auto start_CondDec_HD2 = high_resolution_clock::now();
        string recovered_hd2Bytes;
        int CondDecOut  = 0;
//        while (CondDecOut != 1)
//        {
        CondDecOut = HamDistTwo::CondDec(pkobj._ppk, HD2_ctx_typo_Bytes, pkobj._psk, Threshold, recovered_hd2Bytes, _len, 28);
//        }
        auto stop_CondDec_HD2 = high_resolution_clock::now();
        auto duration_CondDec_HD2 = duration_cast<milliseconds>(stop_CondDec_HD2 - start_CondDec_HD2);

//        free(HD2_Char_ORigCTx);
//        free(HD2_ctx_typo_Bytes);
//        delete [] HD2_ctx_typo_Bytes;
//        delete [] CondEncRst;
        CondEncHD2 << "Enc.Time, CondEnc.Time, Cond.Dec.Time, Ctx.Size, CondCtx.Size, CondDecRslt: (" <<
                   duration_Enc_HD2.count()
                   << ", " << duration_CondEnc_HD2.count()
                   << ", " << duration_CondDec_HD2.count()
                   << ", " << TradCtxSize
                   << ", " << CondCtxSize
                   << ", " << CondDecOut << " )\n";

        duration_Enc_HD2_Sum =  duration_Enc_HD2_Sum + duration_Enc_HD2.count();
        duration_CondEnc_HD2_Sum =  duration_CondEnc_HD2_Sum + duration_CondEnc_HD2.count();
        duration_CondDec_HD2_Sum =  duration_CondDec_HD2_Sum + duration_CondDec_HD2.count();

    }

    CondEncHD2 << "Average Enc, CondEnc, CondDec in msec: " <<
               duration_Enc_HD2_Sum / Num_tests
               << ", " <<  duration_CondEnc_HD2_Sum / Num_tests
               << ", " <<  duration_CondDec_HD2_Sum / Num_tests << ") \n";

    CondEncHD2.close();
    paillier_freepubkey(pkobj._ppk);
    paillier_freeprvkey(pkobj._psk);
    cout << "Hamming Distant  at most Three [Threshold =_len -3, _len = 32] is finished \n";
}


TEST_CASE("Conditional Encryption: OR of predicates: Hamming distance at most two, Edit diatance one and Capslock On.")
{
    PwPkCrypto pkobj;
    pkobj.Paill_pk_init(1024);
    int Num_tests = 30;
    size_t _len = 32;

    string msg = "Hassan";

    string msg_pad = CryptoSymWrapperFunctions::Wrapper_pad(msg, _len);
    size_t PailCtxtSize =  PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2;

    size_t EDOneOrigCtxSize   = 2 * sizeof(size_t) + (_len + 1)  *  PailCtxtSize;
    size_t HDTwoOrigCtxSize   = 2 * sizeof(size_t) + _len *  PailCtxtSize;
    size_t CAPSLocOrigCtxSize = 2 * sizeof(size_t) +  PailCtxtSize;

    size_t ORPrdrigCtxSize = CAPSLocOrigCtxSize + EDOneOrigCtxSize + HDTwoOrigCtxSize;


    size_t CondEncEDOneCtxSize = 3 * sizeof(size_t) + (sizeof(char) * 24) + ((2 * _len) + 1) *  PailCtxtSize;
    size_t CondEncHDTwoCtxSize = 3 * sizeof(size_t) + (sizeof(char) * 24) + (_len *  PailCtxtSize);
    size_t CondEncCPSLKCtxSize = 3 * sizeof(size_t) + (sizeof(char) * 24) +  PailCtxtSize;

    size_t CondEncOR_CtxSize = CondEncCPSLKCtxSize + CondEncEDOneCtxSize + CondEncHDTwoCtxSize;



    double duration_CondEnc_ED1_Sum = 0;
    double duration_Enc_ED1_Sum = 0;
    double duration_CondDec_ED1_Sum = 0;

    ofstream CondEncORpred;
    CondEncORpred.open("CondEncORPredicate.txt");
    CondEncORpred << "We are testing the OR predicate ******************\n \n ";

    for(int T = 0; T< Num_tests; T++) {
        char OrPred_Char_ORigCTx[ORPrdrigCtxSize];
        char OrPred_ctx_typo_Bytes[CondEncOR_CtxSize];
        string typo;
        /*Randomly making typo and the payload*/
        unsigned seed = time(0);
        int NumOfErrs = 0;
        char err1;
        srand(seed);
//        NumOfErrs =rand() % 4;
        NumOfErrs = 3;
        if (NumOfErrs== 0)
        {
            typo = msg;
        }
        else if (NumOfErrs == 1)
        {
            err1 = 32 + (rand() % 95);
            int ErrLction;
            ErrLction = rand() % msg.size();
            typo = msg.substr(0, ErrLction) +  err1 + msg.substr(ErrLction, msg.size());
//            ErrLction++;
//            typo[ErrLction] = err1;
        } else if (NumOfErrs == 2)
        {
            int ErrLction, ErrLction2;
            ErrLction = rand() % msg.size();
            typo = msg.substr(0, ErrLction) + msg.substr(ErrLction+1, msg.size());
        }else if (NumOfErrs == 3)
        {
            int ErrLction, ErrLction2;
            ErrLction = rand() % msg.size();
            typo = msg + 'a' + 'v';
            ErrLction = rand() % msg.size();
        }
//        typo = "hASSAN";
//        typo = "Dassan";
        string payload = typo;
        string pad_typo = CryptoSymWrapperFunctions::Wrapper_pad(typo, 32);
        /* ============ */


        auto start_Enc_HD2 = high_resolution_clock::now();
        int OrigEncRst = 0;
        OrigEncRst = OrPredicate::Enc(pkobj._ppk, msg, OrPred_Char_ORigCTx, _len);
        auto stop_Enc_HD2 = high_resolution_clock::now();
        auto duration_Enc_HD2 = duration_cast<milliseconds>(stop_Enc_HD2 - start_Enc_HD2);


        std::string ctx_final;
        OrPredicate*  Class_OrPredicate = new OrPredicate;
        auto start_CondEnc_HD2 = high_resolution_clock::now();
//        int ED1CondEncRstl =0;
        ctx_final = Class_OrPredicate->CondEnc(pkobj._ppk, OrPred_Char_ORigCTx, typo, payload,32, 30, OrPred_ctx_typo_Bytes);
//        memcpy(OrPred_ctx_typo_Bytes + (3*sizeof(size_t)),&ctx_final[0], 24 );
//        memcpy(OrPred_ctx_typo_Bytes + CondEncCPSLKCtxSize + (3*sizeof(size_t)),&ctx_final[0] + 24, 24 );
//        memcpy(OrPred_ctx_typo_Bytes + CondEncCPSLKCtxSize + CondEncEDOneCtxSize + (3*sizeof(size_t)),&ctx_final[0] + 48, 24 );


        auto stop_CondEnc_HD2 = high_resolution_clock::now();
        auto duration_CondEnc_HD2 = duration_cast<milliseconds>(stop_CondEnc_HD2 - start_CondEnc_HD2);

        string recovered_hd2Bytes;
        int CondDecOut = 0;
        auto start_CondDec_HD2 = high_resolution_clock::now();
//        CondDecOut = OrPredicate::CondDec(pkobj._ppk, OrPred_ctx_typo_Bytes, pkobj._psk, 30, recovered_hd2Bytes, 32, 28);
//        CondDecOut = OrPredicate::CondDec(pkobj._ppk, &ctx_final[0], pkobj._psk, 30, recovered_hd2Bytes, 32, 28);

        auto stop_CondDec_HD2 = high_resolution_clock::now();
        auto duration_CondDec_HD2 = duration_cast<milliseconds>(stop_CondDec_HD2 - start_CondDec_HD2);

//        free(ED1_Char_ORigCTx);
//        free(ED1_ctx_typo_Bytes);

//        CondEncORpred << "Enc.Time, CondEnc.Time, Cond.Dec.Time, Ctx.Size, CondCtx.Size, CondDecRslt: (" <<
//                      duration_Enc_HD2.count()
//                      << ", " << duration_CondEnc_HD2.count()
//                      << ", " << duration_CondDec_HD2.count()
//                      << ", " << ORPrdrigCtxSize
//                      << ", " << CondEncOR_CtxSize
//                      << ", " << CondDecOut << " )\n";
        CondEncORpred << "Enc.Time, CondEnc.Time, Cond.Dec.Time, Ctx.Size, CondCtx.Size, CondDecRslt: (" <<
                      duration_Enc_HD2.count()
                      << ", " << ctx_final
                      << ", " << ORPrdrigCtxSize
                      << ", " << CondEncOR_CtxSize
                      << ", " << CondDecOut << " )\n";

        size_t pos = 0;
        std::string token;
        std::string delimiter = ", ";
        std::string ss = ctx_final;
        std::vector<double>A;
        A.reserve(2);
        while ((pos = ss.find(delimiter)) != std::string::npos) {
            token = ss.substr(0, pos);
            A.push_back(stod(token));
            ss.erase(0, pos + delimiter.length());
        }


        duration_Enc_ED1_Sum =  duration_Enc_ED1_Sum + duration_Enc_HD2.count();
        duration_CondEnc_ED1_Sum =  duration_CondEnc_ED1_Sum + A[0];
        duration_CondDec_ED1_Sum =  duration_CondDec_ED1_Sum + stod(ss);
        delete Class_OrPredicate;
        Class_OrPredicate = NULL;
    }

    CondEncORpred << "Average Enc, CondEnc, CondDec time in msec : " <<
                  duration_Enc_ED1_Sum / Num_tests
                  << ", " <<  duration_CondEnc_ED1_Sum / Num_tests
                  << ", " <<  duration_CondDec_ED1_Sum / Num_tests << ") \n";

    CondEncORpred.close();
    paillier_freepubkey(pkobj._ppk);
    paillier_freeprvkey(pkobj._psk);
    cout << "OR predicate is finished \n";
}

TEST_CASE("Conditional Encryption: Edit Distance One predicate No error")
{
    PwPkCrypto pkobj;
    pkobj.Paill_pk_init(1024);
    int Num_tests = 20;

    string msg = "TheTestingPlainText";

    string msg_pad = CryptoSymWrapperFunctions::Wrapper_pad(msg, 32);


    size_t TradCtxSize = ( 32 + 2) * sizeof(size_t) + ( 32+1) *  PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2;
    size_t CondCtxSize = 3 * sizeof(size_t) + 24 + (32 + 32 +1) * PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2;

    double duration_CondEnc_ED1_Sum = 0;
    double duration_Enc_ED1_Sum = 0;
    double duration_CondDec_ED1_Sum = 0;

    ofstream CondEncED1;
    CondEncED1.open("CondEncED1NoErr.txt");
    CondEncED1 << "The predicate is Edit distance One ******************\n \n ";

    for(int T = 0; T< Num_tests; T++) {
        char ED1_Char_ORigCTx [2 * sizeof(size_t) + (32 + 1)  *  PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2];
        char ED1_ctx_typo_Bytes [ ((( 3 * sizeof(size_t) )+ 24 * sizeof (char)) + (65 *  PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2))];
        string typo;
        /*Randomly making typo and the payload*/
        unsigned seed= time(0);
        int NumOfErrs = 0;
        char err1;
        srand(seed);
//        NumOfErrs =rand() % 3;
        NumOfErrs = 0;
        if (NumOfErrs== 0)
        {
            typo = msg;
        }
        else if (NumOfErrs == 1)
        {
            err1 = 32 + (rand() % 95);
            int ErrLction;
            ErrLction = rand() % msg.size();
            typo = msg.substr(0, ErrLction) +  err1 + msg.substr(ErrLction, msg.size());
//            ErrLction++;
//            typo[ErrLction] = err1;
        } else if (NumOfErrs == 2)
        {
            int ErrLction, ErrLction2;
            ErrLction = rand() % msg.size();
            typo = msg.substr(0, ErrLction) + msg.substr(ErrLction+1, msg.size());
        }
        string payload = typo;
        string pad_typo = CryptoSymWrapperFunctions::Wrapper_pad(typo, 32);
        /* ============ */


        auto start_Enc_HD2 = high_resolution_clock::now();
        int OrigEncRst = 0;
        OrigEncRst = EditDistOne::Enc(pkobj._ppk, msg_pad, ED1_Char_ORigCTx);
        auto stop_Enc_HD2 = high_resolution_clock::now();
        auto duration_Enc_HD2 = duration_cast<milliseconds>(stop_Enc_HD2 - start_Enc_HD2);

        auto start_CondEnc_HD2 = high_resolution_clock::now();
//        int ED1CondEncRstl =0;
        auto ctx_final =  EditDistOne::CondEnc(pkobj._ppk, ED1_Char_ORigCTx, pad_typo, payload,32, 30, ED1_ctx_typo_Bytes);
        auto stop_CondEnc_HD2 = high_resolution_clock::now();
        auto duration_CondEnc_HD2 = duration_cast<milliseconds>(stop_CondEnc_HD2 - start_CondEnc_HD2);


        auto start_CondDec_HD2 = high_resolution_clock::now();
        string recovered_hd2Bytes;
        int CondDecOut = 0;
        CondDecOut = EditDistOne::CondDec(pkobj._ppk, ED1_ctx_typo_Bytes, pkobj._psk, 30, recovered_hd2Bytes, 32, 28);
        auto stop_CondDec_HD2 = high_resolution_clock::now();
        auto duration_CondDec_HD2 = duration_cast<milliseconds>(stop_CondDec_HD2 - start_CondDec_HD2);

//        free(ED1_Char_ORigCTx);
//        free(ED1_ctx_typo_Bytes);

        CondEncED1 << "Enc.Time, CondEnc.Time, Cond.Dec.Time, Ctx.Size, CondCtx.Size, CondDecRslt: (" <<
                   duration_Enc_HD2.count()
                   << ", " << duration_CondEnc_HD2.count()
                   << ", " << duration_CondDec_HD2.count()
                   << ", " << TradCtxSize
                   << ", " << CondCtxSize
                   << ", " << CondDecOut << " )\n";


        duration_Enc_ED1_Sum =  duration_Enc_ED1_Sum + duration_Enc_HD2.count();
        duration_CondEnc_ED1_Sum =  duration_CondEnc_ED1_Sum + duration_CondEnc_HD2.count();
        duration_CondDec_ED1_Sum =  duration_CondDec_ED1_Sum + duration_CondDec_HD2.count();

    }

    CondEncED1 << "Average Enc, CondEnc, CondDec time in msec : " <<
               duration_Enc_ED1_Sum / Num_tests
               << ", " <<  duration_CondEnc_ED1_Sum / Num_tests
               << ", " <<  duration_CondDec_ED1_Sum / Num_tests << ") \n";

    CondEncED1.close();
    paillier_freepubkey(pkobj._ppk);
    paillier_freeprvkey(pkobj._psk);
    cout << "Edit distacne One No_Err is finished \n";
}

TEST_CASE("Conditional Encryption: Edit Distance One predicate One error")
{
    PwPkCrypto pkobj;
    pkobj.Paill_pk_init(1024);
    int Num_tests = 20;

    string msg = "TheTestingPlainText";

    string msg_pad = CryptoSymWrapperFunctions::Wrapper_pad(msg, 32);


    size_t TradCtxSize = ( 32 + 2) * sizeof(size_t) + ( 32+1) *  PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2;
    size_t CondCtxSize = 3 * sizeof(size_t) + 24 + (32 + 32 +1) * PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2;

    double duration_CondEnc_ED1_Sum = 0;
    double duration_Enc_ED1_Sum = 0;
    double duration_CondDec_ED1_Sum = 0;

    ofstream CondEncED1;
    CondEncED1.open("CondEncED1OneErr.txt");
    CondEncED1 << "The predicate is Edit distance One ******************\n \n ";

    for(int T = 0; T< Num_tests; T++) {
        char ED1_Char_ORigCTx [2 * sizeof(size_t) + (32 + 1)  *  PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2];
        char ED1_ctx_typo_Bytes [ ((( 3 * sizeof(size_t) )+ 24 * sizeof (char)) + (65 *  PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2))];
        string typo;
        /*Randomly making typo and the payload*/
        unsigned seed= time(0);
        int NumOfErrs = 0;
        char err1;
        srand(seed);
//        NumOfErrs =rand() % 3;
        NumOfErrs = 1;
        if (NumOfErrs== 0)
        {
            typo = msg;
        }
        else if (NumOfErrs == 1)
        {
            err1 = 32 + (rand() % 95);
            int ErrLction;
            ErrLction = rand() % msg.size();
            typo = msg.substr(0, ErrLction) +  err1 + msg.substr(ErrLction, msg.size());
//            ErrLction++;
//            typo[ErrLction] = err1;
        } else if (NumOfErrs == 2)
        {
            int ErrLction, ErrLction2;
            ErrLction = rand() % msg.size();
            typo = msg.substr(0, ErrLction) + msg.substr(ErrLction+1, msg.size());
        }
        string payload = typo;
        string pad_typo = CryptoSymWrapperFunctions::Wrapper_pad(typo, 32);
        /* ============ */


        auto start_Enc_HD2 = high_resolution_clock::now();
        int OrigEncRst = 0;
        OrigEncRst = EditDistOne::Enc(pkobj._ppk, msg_pad, ED1_Char_ORigCTx);
        auto stop_Enc_HD2 = high_resolution_clock::now();
        auto duration_Enc_HD2 = duration_cast<milliseconds>(stop_Enc_HD2 - start_Enc_HD2);

        auto start_CondEnc_HD2 = high_resolution_clock::now();
//        int ED1CondEncRstl =0;
        auto ctx_final =  EditDistOne::CondEnc(pkobj._ppk, ED1_Char_ORigCTx, pad_typo, payload,32, 30, ED1_ctx_typo_Bytes);
        auto stop_CondEnc_HD2 = high_resolution_clock::now();
        auto duration_CondEnc_HD2 = duration_cast<milliseconds>(stop_CondEnc_HD2 - start_CondEnc_HD2);


        auto start_CondDec_HD2 = high_resolution_clock::now();
        string recovered_hd2Bytes;
        int CondDecOut = 0;
        CondDecOut = EditDistOne::CondDec(pkobj._ppk, ED1_ctx_typo_Bytes, pkobj._psk, 30, recovered_hd2Bytes, 32, 28);
        auto stop_CondDec_HD2 = high_resolution_clock::now();
        auto duration_CondDec_HD2 = duration_cast<milliseconds>(stop_CondDec_HD2 - start_CondDec_HD2);

//        free(ED1_Char_ORigCTx);
//        free(ED1_ctx_typo_Bytes);

        CondEncED1 << "Enc.Time, CondEnc.Time, Cond.Dec.Time, Ctx.Size, CondCtx.Size, CondDecRslt: (" <<
                   duration_Enc_HD2.count()
                   << ", " << duration_CondEnc_HD2.count()
                   << ", " << duration_CondDec_HD2.count()
                   << ", " << TradCtxSize
                   << ", " << CondCtxSize
                   << ", " << CondDecOut << " )\n";


        duration_Enc_ED1_Sum =  duration_Enc_ED1_Sum + duration_Enc_HD2.count();
        duration_CondEnc_ED1_Sum =  duration_CondEnc_ED1_Sum + duration_CondEnc_HD2.count();
        duration_CondDec_ED1_Sum =  duration_CondDec_ED1_Sum + duration_CondDec_HD2.count();

    }

    CondEncED1 << "Average Enc, CondEnc, CondDec time in msec : " <<
               duration_Enc_ED1_Sum / Num_tests
               << ", " <<  duration_CondEnc_ED1_Sum / Num_tests
               << ", " <<  duration_CondDec_ED1_Sum / Num_tests << ") \n";

    CondEncED1.close();
    paillier_freepubkey(pkobj._ppk);
    paillier_freeprvkey(pkobj._psk);
    cout << "Edit distacne One OneErr is finished \n";
}

TEST_CASE("Conditional Encryption: Hamming Distance at most two [no error ] predicate")
{
    PwPkCrypto pkobj;
    pkobj.Paill_pk_init(1024);
    int Num_tests = 30;

    string msg = "TheTestingPlainText";


    string msg_pad = CryptoSymWrapperFunctions::Wrapper_pad(msg, 32);
    int sizechar = sizeof(size_t);
//    unique_ptr<char []> ctx_final(new char[3 * sizeof(size_t) + (sizeof(char) * 24) + (32 *  256) + 1]);

//    char*  HD2_ctx_typo_Bytes = new char[3 * sizeof(size_t) + (sizeof(char) * 24) + (32 *  256) + 1];
//    char* HD2_ctx_typo_Bytes = (char*) malloc (  3 * sizeof(size_t) + (sizeof(char) * 24) + (32 *  256) );

    size_t TradCtxSize = 2 * sizeof(size_t) + 32 *  PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2;
    size_t CondCtxSize = 3 * sizeof(size_t) + (sizeof(char) * 24) + (32 *  256);
//    char*  CAPS_Char_ORigCTx = (char*) malloc (2 * sizeof(size_t) +  PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2);
//    char*  ctx_typo_cplckBytes = (char*) malloc (2 * sizeof(size_t) +  PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2);


//    vector<double> T_Enc_CondEncCAPLK[Num_tests];
//    vector<double> T_CondEnc_CondEncCAPLK[Num_tests];
//    vector<double> T_CondDec_CondEncCAPLK[Num_tests];

    double duration_CondEnc_HD2_Sum = 0;
    double duration_Enc_HD2_Sum = 0;
    double duration_CondDec_HD2_Sum = 0;

    ofstream CondEncHD2;
    CondEncHD2.open("CondEncHD2NoErr.txt");
    CondEncHD2 << "The predicate is Hamming distance at most two [No error]******************\n \n ";

    for(int T = 0; T< Num_tests; T++) {
        char HD2_Char_ORigCTx [2 * sizeof(size_t) + 32 *  PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2];
        char HD2_ctx_typo_Bytes[3 * sizeof(size_t) + (sizeof(char) * 24) + (32 *  256)];
        string typo =msg;
        string payload;

        /*Randomly making typo and the payload*/
        unsigned seed= time(0);
        int NumOfErrs = 0;
        char err1, err2, err3;
        srand(seed);
        NumOfErrs = 0;
//        NumOfErrs =rand() % 4;
        if (NumOfErrs == 1)
        {
            err1 = 32 + (rand() % 95);
            int ErrLction;
            ErrLction = rand() % (msg.size());
            typo[ErrLction] = err1;
        } else if (NumOfErrs == 2)
        {
            err1 = 32 + (rand() % 95);
            err2 = 32 + (rand() % 95);
            int ErrLction1, ErrLction2;
            ErrLction1 = rand() % msg.size();
            ErrLction2 = rand() % msg.size();
            typo[ErrLction1] = err1;
            typo[ErrLction2] = err2;
        } else if (NumOfErrs == 3)
        {
            err1 = 32 + (rand() % 95);
            err2 = 32 + (rand() % 95);
            err3 = 32 + (rand() % 95);
            int ErrLction1, ErrLction2, ErrLction3;
            ErrLction1 = rand() % msg.size();
            ErrLction2 = rand() % msg.size();
            ErrLction3 = rand() % msg.size();
            typo[ErrLction1] = err1;
            typo[ErrLction2] = err2;
            typo[ErrLction3] = err3;
        }
        payload = typo;
        string pad_typo = CryptoSymWrapperFunctions::Wrapper_pad(typo, 32);


        /* ============ */

        auto start_Enc_HD2 = high_resolution_clock::now();
        int tradEncRslt =0;
        tradEncRslt = HamDistTwo::Enc(pkobj._ppk, msg_pad, HD2_Char_ORigCTx);
        auto stop_Enc_HD2 = high_resolution_clock::now();
        auto duration_Enc_HD2 = duration_cast<milliseconds>(stop_Enc_HD2 - start_Enc_HD2);

        auto start_CondEnc_HD2 = high_resolution_clock::now();
//        char* CondEncRst = new char[3 * sizeof(size_t) + (sizeof(char) * 24) + (32 *  256) + 1];
//        memset(HD2_ctx_typo_Bytes, '\0', CondCtxSize);
        auto ctx_final = HamDistTwo::CondEnc(pkobj._ppk, HD2_Char_ORigCTx, typo, payload,32, 30, HD2_ctx_typo_Bytes);
//        std::string* CtxtAEStrPre = (std::string*) malloc(sizeof(char) * 24);
//        std::string s;
//        memcpy(HD2_ctx_typo_Bytes + (3 * sizeof(size_t)), &ctx_final, sizeof(char) * 24);

//        std::string* CtxtAEStrPre = (std::string*) malloc(24);
//        memcpy(&CtxtAEStrPre[0], HD2_ctx_typo_Bytes + 3 * sizeof(size_t), 24 );

        auto stop_CondEnc_HD2 = high_resolution_clock::now();
        auto duration_CondEnc_HD2 = duration_cast<milliseconds>(stop_CondEnc_HD2 - start_CondEnc_HD2);

        auto start_CondDec_HD2 = high_resolution_clock::now();
        string recovered_hd2Bytes;
        int CondDecOut  = 0;
//        while (CondDecOut != 1)
//        {
        CondDecOut = HamDistTwo::CondDec(pkobj._ppk, HD2_ctx_typo_Bytes, pkobj._psk, 30, recovered_hd2Bytes, 32, 28);
//        }
        auto stop_CondDec_HD2 = high_resolution_clock::now();
        auto duration_CondDec_HD2 = duration_cast<milliseconds>(stop_CondDec_HD2 - start_CondDec_HD2);

//        free(HD2_Char_ORigCTx);
//        free(HD2_ctx_typo_Bytes);
//        delete [] HD2_ctx_typo_Bytes;
//        delete [] CondEncRst;
        CondEncHD2 << "Enc.Time, CondEnc.Time, Cond.Dec.Time, Ctx.Size, CondCtx.Size, CondDecRslt: (" <<
                   duration_Enc_HD2.count()
                   << ", " << duration_CondEnc_HD2.count()
                   << ", " << duration_CondDec_HD2.count()
                   << ", " << TradCtxSize
                   << ", " << CondCtxSize
                   << ", " << CondDecOut << " )\n";

        duration_Enc_HD2_Sum =  duration_Enc_HD2_Sum + duration_Enc_HD2.count();
        duration_CondEnc_HD2_Sum =  duration_CondEnc_HD2_Sum + duration_CondEnc_HD2.count();
        duration_CondDec_HD2_Sum =  duration_CondDec_HD2_Sum + duration_CondDec_HD2.count();

    }

    CondEncHD2 << "Average Enc, CondEnc, CondDec in msec: " <<
               duration_Enc_HD2_Sum / Num_tests
               << ", " <<  duration_CondEnc_HD2_Sum / Num_tests
               << ", " <<  duration_CondDec_HD2_Sum / Num_tests << ") \n";

    CondEncHD2.close();
    paillier_freepubkey(pkobj._ppk);
    paillier_freeprvkey(pkobj._psk);
    cout << "Hamming Distant  at most two [No Errors] is finished \n";
}

TEST_CASE("Conditional Encryption: Hamming Distance at most two One Error predicate")
{
    PwPkCrypto pkobj;
    pkobj.Paill_pk_init(1024);
    int Num_tests = 20;

    string msg = "TheTestingPlainText";


    string msg_pad = CryptoSymWrapperFunctions::Wrapper_pad(msg, 32);
    int sizechar = sizeof(size_t);
//    unique_ptr<char []> ctx_final(new char[3 * sizeof(size_t) + (sizeof(char) * 24) + (32 *  256) + 1]);

//    char*  HD2_ctx_typo_Bytes = new char[3 * sizeof(size_t) + (sizeof(char) * 24) + (32 *  256) + 1];
//    char* HD2_ctx_typo_Bytes = (char*) malloc (  3 * sizeof(size_t) + (sizeof(char) * 24) + (32 *  256) );

    size_t TradCtxSize = 2 * sizeof(size_t) + 32 *  PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2;
    size_t CondCtxSize = 3 * sizeof(size_t) + (sizeof(char) * 24) + (32 *  256);
//    char*  CAPS_Char_ORigCTx = (char*) malloc (2 * sizeof(size_t) +  PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2);
//    char*  ctx_typo_cplckBytes = (char*) malloc (2 * sizeof(size_t) +  PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2);


//    vector<double> T_Enc_CondEncCAPLK[Num_tests];
//    vector<double> T_CondEnc_CondEncCAPLK[Num_tests];
//    vector<double> T_CondDec_CondEncCAPLK[Num_tests];

    double duration_CondEnc_HD2_Sum = 0;
    double duration_Enc_HD2_Sum = 0;
    double duration_CondDec_HD2_Sum = 0;

    ofstream CondEncHD2;
    CondEncHD2.open("CondEncHD2OneErr.txt");
    CondEncHD2 << "The predicate is Hamming distance at most two [One error]******************\n \n ";

    for(int T = 0; T< Num_tests; T++) {
        char HD2_Char_ORigCTx [2 * sizeof(size_t) + 32 *  PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2];
        char HD2_ctx_typo_Bytes[3 * sizeof(size_t) + (sizeof(char) * 24) + (32 *  256)];
        string typo =msg;
        string payload;

        /*Randomly making typo and the payload*/
        unsigned seed= time(0);
        int NumOfErrs = 0;
        char err1, err2, err3;
        srand(seed);
        NumOfErrs = 1;
//        NumOfErrs =rand() % 4;
        if (NumOfErrs == 1)
        {
            err1 = 32 + (rand() % 95);
            int ErrLction;
            ErrLction = rand() % (msg.size());
            typo[ErrLction] = err1;
        } else if (NumOfErrs == 2)
        {
            err1 = 32 + (rand() % 95);
            err2 = 32 + (rand() % 95);
            int ErrLction1, ErrLction2;
            ErrLction1 = rand() % msg.size();
            ErrLction2 = rand() % msg.size();
            typo[ErrLction1] = err1;
            typo[ErrLction2] = err2;
        } else if (NumOfErrs == 3)
        {
            err1 = 32 + (rand() % 95);
            err2 = 32 + (rand() % 95);
            err3 = 32 + (rand() % 95);
            int ErrLction1, ErrLction2, ErrLction3;
            ErrLction1 = rand() % msg.size();
            ErrLction2 = rand() % msg.size();
            ErrLction3 = rand() % msg.size();
            typo[ErrLction1] = err1;
            typo[ErrLction2] = err2;
            typo[ErrLction3] = err3;
        }
        payload = typo;
        string pad_typo = CryptoSymWrapperFunctions::Wrapper_pad(typo, 32);


        /* ============ */

        auto start_Enc_HD2 = high_resolution_clock::now();
        int tradEncRslt =0;
        tradEncRslt = HamDistTwo::Enc(pkobj._ppk, msg_pad, HD2_Char_ORigCTx);
        auto stop_Enc_HD2 = high_resolution_clock::now();
        auto duration_Enc_HD2 = duration_cast<milliseconds>(stop_Enc_HD2 - start_Enc_HD2);

        auto start_CondEnc_HD2 = high_resolution_clock::now();
//        char* CondEncRst = new char[3 * sizeof(size_t) + (sizeof(char) * 24) + (32 *  256) + 1];
//        memset(HD2_ctx_typo_Bytes, '\0', CondCtxSize);
        auto ctx_final = HamDistTwo::CondEnc(pkobj._ppk, HD2_Char_ORigCTx, typo, payload,32, 30, HD2_ctx_typo_Bytes);

        auto stop_CondEnc_HD2 = high_resolution_clock::now();
        auto duration_CondEnc_HD2 = duration_cast<milliseconds>(stop_CondEnc_HD2 - start_CondEnc_HD2);

        auto start_CondDec_HD2 = high_resolution_clock::now();
        string recovered_hd2Bytes;
        int CondDecOut  = 0;
//        while (CondDecOut != 1)
//        {
        CondDecOut = HamDistTwo::CondDec(pkobj._ppk, HD2_ctx_typo_Bytes, pkobj._psk, 30, recovered_hd2Bytes, 32, 28);
//        }
        auto stop_CondDec_HD2 = high_resolution_clock::now();
        auto duration_CondDec_HD2 = duration_cast<milliseconds>(stop_CondDec_HD2 - start_CondDec_HD2);

        CondEncHD2 << "Enc.Time, CondEnc.Time, Cond.Dec.Time, Ctx.Size, CondCtx.Size, CondDecRslt: (" <<
                   duration_Enc_HD2.count()
                   << ", " << duration_CondEnc_HD2.count()
                   << ", " << duration_CondDec_HD2.count()
                   << ", " << TradCtxSize
                   << ", " << CondCtxSize
                   << ", " << CondDecOut << " )\n";

        duration_Enc_HD2_Sum =  duration_Enc_HD2_Sum + duration_Enc_HD2.count();
        duration_CondEnc_HD2_Sum =  duration_CondEnc_HD2_Sum + duration_CondEnc_HD2.count();
        duration_CondDec_HD2_Sum =  duration_CondDec_HD2_Sum + duration_CondDec_HD2.count();

    }

    CondEncHD2 << "Average Enc, CondEnc, CondDec in msec: " <<
               duration_Enc_HD2_Sum / Num_tests
               << ", " <<  duration_CondEnc_HD2_Sum / Num_tests
               << ", " <<  duration_CondDec_HD2_Sum / Num_tests << ") \n";

    CondEncHD2.close();
    paillier_freepubkey(pkobj._ppk);
    paillier_freeprvkey(pkobj._psk);
    cout << "Hamming Distant  at most two [One Error] is finished \n";
}

TEST_CASE("Conditional Encryption: Hamming Distance at most two Two Error predicate")
{
    PwPkCrypto pkobj;
    pkobj.Paill_pk_init(1024);
    int Num_tests = 20;

    string msg = "TheTestingPlainText";


    string msg_pad = CryptoSymWrapperFunctions::Wrapper_pad(msg, 32);
    int sizechar = sizeof(size_t);
//    unique_ptr<char []> ctx_final(new char[3 * sizeof(size_t) + (sizeof(char) * 24) + (32 *  256) + 1]);

//    char*  HD2_ctx_typo_Bytes = new char[3 * sizeof(size_t) + (sizeof(char) * 24) + (32 *  256) + 1];
//    char* HD2_ctx_typo_Bytes = (char*) malloc (  3 * sizeof(size_t) + (sizeof(char) * 24) + (32 *  256) );

    size_t TradCtxSize = 2 * sizeof(size_t) + 32 *  PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2;
    size_t CondCtxSize = 3 * sizeof(size_t) + (sizeof(char) * 24) + (32 *  256);
//    char*  CAPS_Char_ORigCTx = (char*) malloc (2 * sizeof(size_t) +  PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2);
//    char*  ctx_typo_cplckBytes = (char*) malloc (2 * sizeof(size_t) +  PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2);


//    vector<double> T_Enc_CondEncCAPLK[Num_tests];
//    vector<double> T_CondEnc_CondEncCAPLK[Num_tests];
//    vector<double> T_CondDec_CondEncCAPLK[Num_tests];

    double duration_CondEnc_HD2_Sum = 0;
    double duration_Enc_HD2_Sum = 0;
    double duration_CondDec_HD2_Sum = 0;

    ofstream CondEncHD2;
    CondEncHD2.open("CondEncHD2TwoErr.txt");
    CondEncHD2 << "The predicate is Hamming distance at most two [Two errors]******************\n \n ";

    for(int T = 0; T< Num_tests; T++) {
        char HD2_Char_ORigCTx [2 * sizeof(size_t) + 32 *  PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2];
        char HD2_ctx_typo_Bytes[3 * sizeof(size_t) + (sizeof(char) * 24) + (32 *  256)];
        string typo =msg;
        string payload;

        /*Randomly making typo and the payload*/
        unsigned seed= time(0);
        int NumOfErrs = 0;
        char err1, err2, err3;
        srand(seed);
        NumOfErrs = 2;
//        NumOfErrs =rand() % 4;
        if (NumOfErrs == 1)
        {
            err1 = 32 + (rand() % 95);
            int ErrLction;
            ErrLction = rand() % (msg.size());
            typo[ErrLction] = err1;
        } else if (NumOfErrs == 2)
        {
            err1 = 32 + (rand() % 95);
            err2 = 32 + (rand() % 95);
            int ErrLction1, ErrLction2;
            ErrLction1 = rand() % msg.size();
            ErrLction2 = rand() % msg.size();
            typo[ErrLction1] = err1;
            typo[ErrLction2] = err2;
        } else if (NumOfErrs == 3)
        {
            err1 = 32 + (rand() % 95);
            err2 = 32 + (rand() % 95);
            err3 = 32 + (rand() % 95);
            int ErrLction1, ErrLction2, ErrLction3;
            ErrLction1 = rand() % msg.size();
            ErrLction2 = rand() % msg.size();
            ErrLction3 = rand() % msg.size();
            typo[ErrLction1] = err1;
            typo[ErrLction2] = err2;
            typo[ErrLction3] = err3;
        }
        payload = typo;
        string pad_typo = CryptoSymWrapperFunctions::Wrapper_pad(typo, 32);


        /* ============ */

        auto start_Enc_HD2 = high_resolution_clock::now();
        int tradEncRslt =0;
        tradEncRslt = HamDistTwo::Enc(pkobj._ppk, msg_pad, HD2_Char_ORigCTx);
        auto stop_Enc_HD2 = high_resolution_clock::now();
        auto duration_Enc_HD2 = duration_cast<milliseconds>(stop_Enc_HD2 - start_Enc_HD2);

        auto start_CondEnc_HD2 = high_resolution_clock::now();
//        char* CondEncRst = new char[3 * sizeof(size_t) + (sizeof(char) * 24) + (32 *  256) + 1];
//        memset(HD2_ctx_typo_Bytes, '\0', CondCtxSize);
        auto ctx_final = HamDistTwo::CondEnc(pkobj._ppk, HD2_Char_ORigCTx, typo, payload,32, 30, HD2_ctx_typo_Bytes);

        auto stop_CondEnc_HD2 = high_resolution_clock::now();
        auto duration_CondEnc_HD2 = duration_cast<milliseconds>(stop_CondEnc_HD2 - start_CondEnc_HD2);

        auto start_CondDec_HD2 = high_resolution_clock::now();
        string recovered_hd2Bytes;
        int CondDecOut  = 0;
//        while (CondDecOut != 1)
//        {
        CondDecOut = HamDistTwo::CondDec(pkobj._ppk, HD2_ctx_typo_Bytes, pkobj._psk, 30, recovered_hd2Bytes, 32, 28);
//        }
        auto stop_CondDec_HD2 = high_resolution_clock::now();
        auto duration_CondDec_HD2 = duration_cast<milliseconds>(stop_CondDec_HD2 - start_CondDec_HD2);

        CondEncHD2 << "Enc.Time, CondEnc.Time, Cond.Dec.Time, Ctx.Size, CondCtx.Size, CondDecRslt: (" <<
                   duration_Enc_HD2.count()
                   << ", " << duration_CondEnc_HD2.count()
                   << ", " << duration_CondDec_HD2.count()
                   << ", " << TradCtxSize
                   << ", " << CondCtxSize
                   << ", " << CondDecOut << " )\n";

        duration_Enc_HD2_Sum =  duration_Enc_HD2_Sum + duration_Enc_HD2.count();
        duration_CondEnc_HD2_Sum =  duration_CondEnc_HD2_Sum + duration_CondEnc_HD2.count();
        duration_CondDec_HD2_Sum =  duration_CondDec_HD2_Sum + duration_CondDec_HD2.count();

    }

    CondEncHD2 << "Average Enc, CondEnc, CondDec in msec: " <<
               duration_Enc_HD2_Sum / Num_tests
               << ", " <<  duration_CondEnc_HD2_Sum / Num_tests
               << ", " <<  duration_CondDec_HD2_Sum / Num_tests << ") \n";

    CondEncHD2.close();
    paillier_freepubkey(pkobj._ppk);
    paillier_freeprvkey(pkobj._psk);
    cout << "Hamming Distant  at most two [Two Error] is finished \n";
}

TEST_CASE("Conditional Encryption: Hamming Distance at most two Three Error predicate")
{
    PwPkCrypto pkobj;
    pkobj.Paill_pk_init(1024);
    int Num_tests = 20;

    string msg = "TheTestingPlainText";


    string msg_pad = CryptoSymWrapperFunctions::Wrapper_pad(msg, 32);
    int sizechar = sizeof(size_t);
//    unique_ptr<char []> ctx_final(new char[3 * sizeof(size_t) + (sizeof(char) * 24) + (32 *  256) + 1]);

//    char*  HD2_ctx_typo_Bytes = new char[3 * sizeof(size_t) + (sizeof(char) * 24) + (32 *  256) + 1];
//    char* HD2_ctx_typo_Bytes = (char*) malloc (  3 * sizeof(size_t) + (sizeof(char) * 24) + (32 *  256) );

    size_t TradCtxSize = 2 * sizeof(size_t) + 32 *  PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2;
    size_t CondCtxSize = 3 * sizeof(size_t) + (sizeof(char) * 24) + (32 *  256);
//    char*  CAPS_Char_ORigCTx = (char*) malloc (2 * sizeof(size_t) +  PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2);
//    char*  ctx_typo_cplckBytes = (char*) malloc (2 * sizeof(size_t) +  PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2);


//    vector<double> T_Enc_CondEncCAPLK[Num_tests];
//    vector<double> T_CondEnc_CondEncCAPLK[Num_tests];
//    vector<double> T_CondDec_CondEncCAPLK[Num_tests];

    double duration_CondEnc_HD2_Sum = 0;
    double duration_Enc_HD2_Sum = 0;
    double duration_CondDec_HD2_Sum = 0;

    ofstream CondEncHD2;
    CondEncHD2.open("CondEncHD2ThreeErr.txt");
    CondEncHD2 << "The predicate is Hamming distance at most two [Three errors]******************\n \n ";

    for(int T = 0; T< Num_tests; T++) {
        char HD2_Char_ORigCTx [2 * sizeof(size_t) + 32 *  PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2];
        char HD2_ctx_typo_Bytes[3 * sizeof(size_t) + (sizeof(char) * 24) + (32 *  256)];
        string typo =msg;
        string payload;

        /*Randomly making typo and the payload*/
        unsigned seed= time(0);
        int NumOfErrs = 0;
        char err1, err2, err3;
        srand(seed);
        NumOfErrs = 3;
//        NumOfErrs =rand() % 4;
        if (NumOfErrs == 1)
        {
            err1 = 32 + (rand() % 95);
            int ErrLction;
            ErrLction = rand() % (msg.size());
            typo[ErrLction] = err1;
        } else if (NumOfErrs == 2)
        {
            err1 = 32 + (rand() % 95);
            err2 = 32 + (rand() % 95);
            int ErrLction1, ErrLction2;
            ErrLction1 = rand() % msg.size();
            ErrLction2 = rand() % msg.size();
            typo[ErrLction1] = err1;
            typo[ErrLction2] = err2;
        } else if (NumOfErrs == 3)
        {
            err1 = 32 + (rand() % 95);
            err2 = 32 + (rand() % 95);
            err3 = 32 + (rand() % 95);
            int ErrLction1, ErrLction2, ErrLction3;
            ErrLction1 = rand() % msg.size();
            ErrLction2 = rand() % msg.size();
            ErrLction3 = rand() % msg.size();
            typo[ErrLction1] = err1;
            typo[ErrLction2] = err2;
            typo[ErrLction3] = err3;
        }
        payload = typo;
        string pad_typo = CryptoSymWrapperFunctions::Wrapper_pad(typo, 32);


        /* ============ */

        auto start_Enc_HD2 = high_resolution_clock::now();
        int tradEncRslt =0;
        tradEncRslt = HamDistTwo::Enc(pkobj._ppk, msg_pad, HD2_Char_ORigCTx);
        auto stop_Enc_HD2 = high_resolution_clock::now();
        auto duration_Enc_HD2 = duration_cast<milliseconds>(stop_Enc_HD2 - start_Enc_HD2);

        auto start_CondEnc_HD2 = high_resolution_clock::now();
//        char* CondEncRst = new char[3 * sizeof(size_t) + (sizeof(char) * 24) + (32 *  256) + 1];
//        memset(HD2_ctx_typo_Bytes, '\0', CondCtxSize);
        auto ctx_final = HamDistTwo::CondEnc(pkobj._ppk, HD2_Char_ORigCTx, typo, payload,32, 30, HD2_ctx_typo_Bytes);

        auto stop_CondEnc_HD2 = high_resolution_clock::now();
        auto duration_CondEnc_HD2 = duration_cast<milliseconds>(stop_CondEnc_HD2 - start_CondEnc_HD2);

        auto start_CondDec_HD2 = high_resolution_clock::now();
        string recovered_hd2Bytes;
        int CondDecOut  = 0;
//        while (CondDecOut != 1)
//        {
        CondDecOut = HamDistTwo::CondDec(pkobj._ppk, HD2_ctx_typo_Bytes, pkobj._psk, 30, recovered_hd2Bytes, 32, 28);
//        }
        auto stop_CondDec_HD2 = high_resolution_clock::now();
        auto duration_CondDec_HD2 = duration_cast<milliseconds>(stop_CondDec_HD2 - start_CondDec_HD2);

        CondEncHD2 << "Enc.Time, CondEnc.Time, Cond.Dec.Time, Ctx.Size, CondCtx.Size, CondDecRslt: (" <<
                   duration_Enc_HD2.count()
                   << ", " << duration_CondEnc_HD2.count()
                   << ", " << duration_CondDec_HD2.count()
                   << ", " << TradCtxSize
                   << ", " << CondCtxSize
                   << ", " << CondDecOut << " )\n";

        duration_Enc_HD2_Sum =  duration_Enc_HD2_Sum + duration_Enc_HD2.count();
        duration_CondEnc_HD2_Sum =  duration_CondEnc_HD2_Sum + duration_CondEnc_HD2.count();
        duration_CondDec_HD2_Sum =  duration_CondDec_HD2_Sum + duration_CondDec_HD2.count();

    }

    CondEncHD2 << "Average Enc, CondEnc, CondDec in msec: " <<
               duration_Enc_HD2_Sum / Num_tests
               << ", " <<  duration_CondEnc_HD2_Sum / Num_tests
               << ", " <<  duration_CondDec_HD2_Sum / Num_tests << ") \n";

    CondEncHD2.close();
    paillier_freepubkey(pkobj._ppk);
    paillier_freeprvkey(pkobj._psk);
    cout << "Hamming Distant  at most two [Three Errors] is finished \n";
}

TEST_CASE("Conditional Encryption: CAPSLOCK ON predicate")
{
    PwPkCrypto pkobj;
    pkobj.Paill_pk_init(1024);
    int Num_tests = 20;

    string msg = "Hassan";
    string typo = "hASSAN";
    string payload = "hASSAN";

    string  ctx_cplck;
    string ctx_typo_cplck;
    string recovered_cplck;

    char*  CAPS_Char_ORigCTx;
    char*  ctx_typo_cplckBytes;
    size_t TradCtxSize = 2 * sizeof(size_t) +  PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2;
    size_t CondCtxSize = 3 * sizeof(size_t) + 24 * sizeof(char) +   PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2;
//    char*  CAPS_Char_ORigCTx = (char*) malloc (2 * sizeof(size_t) +  PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2);
//    char*  ctx_typo_cplckBytes = (char*) malloc (2 * sizeof(size_t) +  PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2);


    vector<double> T_Enc_CondEncCAPLK[Num_tests];
    vector<double> T_CondEnc_CondEncCAPLK[Num_tests];
    vector<double> T_CondDec_CondEncCAPLK[Num_tests];

    double duration_CondEnc_CAP_Sum = 0;
    double duration_Enc_CAP_Sum = 0;
    double duration_CondDec_CAP_Sum = 0;

    ofstream CondEncCPSLCK;
    CondEncCPSLCK.open("CondEncCPSLCK.txt");
    CondEncCPSLCK << "The predicate is CPSLCK key ON ******************\n \n ";

    for(int T = 0; T< Num_tests; T++) {

        char CAPS_Char_ORigCTx[2 * sizeof(size_t) +  PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2];
        char ctx_typo_cplckBytes[ 3 * sizeof(size_t) + (sizeof(char) * 24)  +   PAILLIER_BITS_TO_BYTES(pkobj._ppk->bits)*2];

        auto start_Enc_CAP = high_resolution_clock::now();
        int CApsOrigCtxtRslt = CAPLOCKpredicate::Enc(pkobj._ppk, msg, CAPS_Char_ORigCTx);
        auto stop_Enc_CAP = high_resolution_clock::now();
        auto duration_Enc_CAP = duration_cast<milliseconds>(stop_Enc_CAP - start_Enc_CAP);

        auto start_CondEnc_CAP = high_resolution_clock::now();
        auto CPSLKCondEncRlt =  CAPLOCKpredicate::CondEnc(pkobj._ppk, CAPS_Char_ORigCTx, typo, payload,32, 30,  ctx_typo_cplckBytes);
        auto stop_CondEnc_CAP = high_resolution_clock::now();
        auto duration_CondEnc_CAP = duration_cast<milliseconds>(stop_CondEnc_CAP - start_CondEnc_CAP);


        auto start_CondDec_CAP = high_resolution_clock::now();
        string recovered_cplckBytes;
        int CondDecOut = 0;
        CondDecOut = CAPLOCKpredicate::CondDec(pkobj._ppk, ctx_typo_cplckBytes, pkobj._psk, 29, recovered_cplckBytes, msg.size(), 28);
        auto stop_CondDec_CAP = high_resolution_clock::now();
        auto duration_CondDec_CAP = duration_cast<milliseconds>(stop_CondDec_CAP - start_CondDec_CAP);


        CondEncCPSLCK << "Enc.Time, CondEnc.Time, Cond.Dec.Time, Ctx.Size, CondCtx.Size, CondDecRslt: (" <<
                      duration_Enc_CAP.count()
                      << ", " << duration_CondEnc_CAP.count()
                      << ", " << duration_CondDec_CAP.count()
                      << ", " << TradCtxSize
                      << ", " << CondCtxSize
                      << ", " << CondDecOut << " )\n";

//        free(CAPS_Char_ORigCTx);
//        free(ctx_typo_cplckBytes);

        duration_Enc_CAP_Sum =  duration_Enc_CAP_Sum + duration_Enc_CAP.count();
        duration_CondEnc_CAP_Sum =  duration_CondEnc_CAP_Sum + duration_CondEnc_CAP.count();
        duration_CondDec_CAP_Sum =  duration_CondDec_CAP_Sum + duration_CondDec_CAP.count();

    }

    CondEncCPSLCK << "Average Enc, CondEnc, CondDec in msec: " <<
     duration_Enc_CAP_Sum / Num_tests
     << ", " <<  duration_CondEnc_CAP_Sum / Num_tests
     << ", " <<  duration_CondDec_CAP_Sum / Num_tests << ") \n";

    CondEncCPSLCK.close();
    paillier_freepubkey(pkobj._ppk);
    paillier_freeprvkey(pkobj._psk);
    cout << "CAPSLCOK is finished \n";
}

TEST_CASE("Generating the data from the extracted execution time")
{
    string Filename = "CondEnc";
    std::vector<int> LengthList  = {8, 16, 32, 64, 128}; // The list of all possible padded lengths.
    std::vector<int> TheThresholdList = {1, 2, 3, 4,5 }; //The set of all possible threshold values
    std::vector<string> ThePredicatesList = {"HD", "EDOne", "CPSLCK", "OR"};
    string Starting = "Average Enc, CondEnc, CondDec, CtxtSize: ";
    int StartingSize = Starting.size();




    for (auto i : LengthList )
    {
        for(auto j: TheThresholdList)
        {

            string NewFileName = "data";
            ofstream data;

            data.open("dataL.dat");
//            data_T.open("dataT.dat");

//            HDdata_L << "L" << "\t" << "Enc" << "\t" << "CondEnc"<< "\t" << "CondDec" << "\t" << "CtxtSize";
//            HDdata_T << "T" << "\t" << "Enc" << "\t" << "CondEnc"<< "\t" << "CondDec" << "\t" << "CtxtSize";
            for (auto k: ThePredicatesList)
            {

                if(k == "HD")
                {
                    string AuxFile = Filename + "_" + k + "_T" + to_string(j) + "_L" + to_string(i);
                    ifstream inFile; //The input file
                    inFile.open (AuxFile);
                    string line;
                    std::vector<string> Eval;
                    while (getline(inFile, line))
                    {
                        if (line.find(Starting) != string::npos)
                        {

                            std::string data = line.substr(StartingSize, line.size());
                            std::string s = data;


                            std::string delimiter = ", ";

                            size_t pos = 0;
                            std::string token;
                            while ((pos = s.find(delimiter)) != std::string::npos) {
                                token = s.substr(0, pos);
                                Eval.push_back(token);
                                s.erase(0, pos + delimiter.length());
                            }

                            Eval.push_back(s);

                        }

                    }

//                    HDdata_L << i << "\t" << Eval[0]
//                    << "\t" << Eval[1] << "\t" << Eval[2]
//                    << "\t" << Eval[3];
//
//                    HDdata_L << j << "\t" << Eval[0]
//                             << "\t" << Eval[1] << "\t" << Eval[2]
//                             << "\t" << Eval[3];
                }
                else
                {
                    string AuxFile = Filename + "_L" + to_string(i);
                    ifstream inFile; //The input file
                    inFile.open (AuxFile);
                }









            }
        }
    }

    //we have the data file which collects all the data from all the predicate encryptions schemes.

}



//TEST_CASE("pw_crypto") {
//    PwPkCrypto pkobj;
////    string large_msg = "very large message";
//    string large_msg = "message";
//    for(int i=0; i < 2; i++) large_msg += large_msg;
//    SECTION("pad-unpad") {
//        string s("Hello Brother");
//        string pad_s = pkobj.pad(s);
//        CHECK(pad_s.size() == pkobj.len_limit());
//        CHECK(pad_s != s);
//        string unpad_s = pkobj.unpad(pad_s);
//        CHECK(unpad_s == s);
//
//        s = large_msg;
//        pad_s = pkobj.pad(s);
//        CHECK(pad_s.size() == pkobj.len_limit());
//        CHECK(pad_s != s);
//        unpad_s = pkobj.unpad(pad_s);
//        CHECK(unpad_s == s.substr(0, pkobj.len_limit()));
//    }
//
//    SECTION("PwPkCrypto.basic") {
//        PwPkCrypto pkobj;
//        string sk_str = CryptoSymWrapperFunctions::Wrapper_b64decode("MEECAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQcEJzAlAg"\
//                                  "EBBCAUsnXuu6Zj3CjT0Xd6BXOqg5jB7zgWfvCGsjC3NZRaQw");
//        pkobj.set_sk(sk_str, true); // generate pk
////        string msg = random_msg(), ctx, rdata;
//        string msg = "hello_pass", ctx, rdata;
////        string Padmsg = pkobj.pad(msg);
////        pkobj.pk_encrypt(msg, ctx);
//
////        pkobj._can_decrypt_Pail = true;
//        pkobj.initialize();
//        pkobj.Paill_pk_encrypt(pkobj.pad(msg), ctx);
////        pkobj.pk_decrypt(ctx, rdata);
////        pkobj._ppk = pkobj.pk_Pail_Extract();
////        pkobj._psk = pkobj.sk_Pail_Extract();
//        pkobj.Paill_pk_decrypt(ctx, rdata, 0);
////        string Unpadmsg = pkobj.unpad(rdata);
////        string RlPwd_ctx_pull = real_pw_ctx.rlpwdctx();
//        string typo_ctx;
////        pkobj.SecretShare_MHammDis(ctx, "hello_pas", typo_ctx);
//
//        REQUIRE(pkobj.unpad(rdata) == msg);
//        REQUIRE(CryptoSymWrapperFunctions::Wrapper_b64encode(pkobj.unpad(rdata)) == CryptoSymWrapperFunctions::Wrapper_b64encode(msg));
//
//
//        SECTION("0: pk encrypt-decrypt") {
//            byte _t1[] = {0x23, 0x56, 0x00, 0xf4, 0x46, 0xff};
//            string msgs[] = {
//                    "Hey here I am",
//                    "aaaaaaa",
//                    {_t1, _t1 + 6},
//                    ""
//            };
//            for (int i = 0; i < 3; i++) {
////                string Padmsgs = pkobj.pad(msgs[i]);
//                pkobj.pw_pk_encrypt(msgs[i], ctx);
//                pkobj.pw_pk_decrypt(ctx, rdata);
////                string Unpadrdata = pkobj.unpad(rdata);
////                CHECK(rdata == Padmsgs);
////                REQUIRE(rdata.size() == msgs[i].size());
//                CHECK(rdata == msgs[i]);
//                REQUIRE(rdata.size() == msgs[i].size());
//
//            }
//        }
//    }
//
//    SECTION("Large message") {
//        PwPkCrypto pkobj;
//        pkobj.initialize();
//        string ctx, rdata;
//        string msg = "Hello brother";
//        pkobj.pw_pk_encrypt(msg, ctx);
//        // 85 comes from the other overheads
//        CHECK(ctx.length() <= pkobj.len_limit() * 2);
//        cout << "Ciphertext size: " << ctx.size() << endl;
//        pkobj.pw_pk_decrypt(ctx, rdata);
//        CHECK(rdata.size() <= pkobj.len_limit());
//    }
//}

TEST_CASE("pk_crypto") {

    SECTION ("b64 encode decode") {
        byte _t1[] = {0x12, 0x12, 0x45, 0xf2, 0x34};
        vector<SecByteBlock> raw_bytes = {
                SecByteBlock((const byte *) "aaa13", 5),
                SecByteBlock((const byte *) "", 0),
                SecByteBlock(_t1, 5)
        };
        for (size_t i = 0; i < raw_bytes.size(); i++) {
            string _t_encoded, _t_byte_str;
            string res = CryptoSymWrapperFunctions::Wrapper_b64decode(CryptoSymWrapperFunctions::Wrapper_b64encode(raw_bytes[i]));
            // cout << "~~> " << raw_bytes[i] << endl;
            int b = raw_bytes[i] == res.data();
            if (b != 0) {
                cout << "i: " << i << endl;
                cout << res << endl;
                cout << raw_bytes[i].data() << endl;
            }
            REQUIRE(b == 0);
            CHECK(CryptoSymWrapperFunctions::Wrapper_b64encode(raw_bytes[i]) == CryptoSymWrapperFunctions::Wrapper_b64encode(raw_bytes[i]));
        }
    }

    SECTION("harden_pw") {
        string pw = "SecretPass";
        SecByteBlock salt, key, nkey;
        CryptoSymWrapperFunctions::Wrapper_harden_pw(pw, salt, key);
        CryptoSymWrapperFunctions::Wrapper_harden_pw(pw, salt, nkey);
        CHECK(CryptoSymWrapperFunctions::Wrapper_b64encode(key) == CryptoSymWrapperFunctions::Wrapper_b64encode(nkey));
        nkey.resize(0);
        CryptoSymWrapperFunctions::Wrapper_harden_pw(pw + "1", salt, nkey);
        CHECK_FALSE(CryptoSymWrapperFunctions::Wrapper_b64encode(key) == CryptoSymWrapperFunctions::Wrapper_b64encode(nkey));
        salt.resize(0);
        nkey.resize(0);
        CryptoSymWrapperFunctions::Wrapper_harden_pw(pw, salt, nkey);
        nkey.resize(0);
        CryptoSymWrapperFunctions::Wrapper_harden_pw(pw, salt, nkey);
        CHECK_FALSE(CryptoSymWrapperFunctions::Wrapper_b64encode(key) == CryptoSymWrapperFunctions::Wrapper_b64encode(nkey));
    }

    SECTION("pwencrypt-decrypt") {
        string pw = "Super secret pw";
        byte _t1[] = {0x23, 0x56, 0x00, 0xf4, 0x46, 0xff};
        string s(_t1, _t1 + 6);
        vector<string> msgs = {
                "Hey here I am",
                "aaaaaaa",
                "",
                ""
        };
        string ctx, rdata;
        msgs[3] = string((char *) _t1, 6);
        for (size_t i = 0; i < 20; i++) {
            if(msgs.size() <= i) {
                SecByteBlock sb(300);
                PRNG.GenerateBlock(sb.data(), sb.size());
                msgs.push_back(string(sb.begin(), sb.end()));
            }
            CryptoSymWrapperFunctions::Wrapper_AuthEncrypt(pw, msgs[i], ctx);
            REQUIRE(CryptoSymWrapperFunctions::Wrapper_AuthDecrypt(pw, ctx, rdata));
            REQUIRE(rdata == msgs[i]);
            REQUIRE(ctx != msgs[i]);
            REQUIRE(ctx.size() > msgs[i].size());
            REQUIRE_FALSE(CryptoSymWrapperFunctions::Wrapper_AuthDecrypt(pw + ' ', ctx, rdata));
        }
    }


    SECTION("PkCrypto.basic") {
        PkCrypto pkobj;
        PwPkCrypto t;
        string sk_str = CryptoSymWrapperFunctions::Wrapper_b64decode("MEECAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQcEJzAlAg"\
                                  "EBBCAUsnXuu6Zj3CjT0Xd6BXOqg5jB7zgWfvCGsjC3NZRaQw");

        pkobj.set_sk(sk_str, true); // generate pk

        string msg = random_msg(), ctx, rdata;
//        pkobj.pk_encrypt(msg, ctx);
        pkobj.initialize();
        pkobj.Paill_pk_encrypt(t.pad(msg), ctx);
//        pkobj.pk_decrypt(ctx, rdata);
        pkobj.Paill_pk_decrypt(ctx, rdata, 0);
        REQUIRE(t.unpad(rdata) == msg);
        REQUIRE(CryptoSymWrapperFunctions::Wrapper_b64encode(t.unpad(rdata)) == CryptoSymWrapperFunctions::Wrapper_b64encode(msg));

        SECTION("0: pk encrypt-decrypt") {
            byte _t1[] = {0x23, 0x56, 0x00, 0xf4, 0x46, 0xff};
            string msgs[] = {
                    "Hey here I am",
                    "aaaaaaa",
                    {_t1, _t1 + 6},
                    ""
            };
            for (int i = 0; i < 3; i++) {
//                pkobj.pk_encrypt(msgs[i], ctx);

                pkobj.Paill_pk_encrypt(t.pad(msgs[i]), ctx);
//                pkobj.pk_decrypt(ctx, rdata);
                pkobj.Paill_pk_decrypt(ctx, rdata, 0);
                REQUIRE(t.unpad(rdata) == msgs[i]);
            }
        }

        SECTION("1: pk load and dump key") {
            PkCrypto pkobj1;
//            pkobj1.initialize();
            pkobj1.set_pk(pkobj.serialize_pk());
            pkobj1._ppk =  pkobj.pk_Pail_Extract();
            PkCrypto pkobj2;
//            pkobj2.initialize();
            pkobj2._ppk =  pkobj.pk_Pail_Extract();
            pkobj2._psk =  pkobj.sk_Pail_Extract();
            pkobj2.set_sk(pkobj.serialize_sk());
//            pkobj1.pk_encrypt(msg, ctx);
            pkobj1.Paill_pk_encrypt(msg, ctx);
//            pkobj2.pk_decrypt(ctx, rdata);
            pkobj2.Paill_pk_decrypt(ctx, rdata, 0);
            REQUIRE(rdata == msg);
        }

        SECTION("2: Cipher must be in correct format") {
//            pkobj.pk_encrypt(msg, ctx);
            pkobj.Paill_pk_encrypt(t.pad(msg), ctx);
            CHECK_THROWS(pkobj.Paill_pk_decrypt(ctx + "adfasdf", rdata, 0));
            CHECK(t.unpad(rdata) != msg);
            CHECK(rdata.find(msg) == string::npos);
        }

        /*SECTION("Check a weird failing case") {
            string sk_str = b64decode("MEECAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQcEJzAlAgEBBCBHYss"\
            "FAMNGU5ZNpGrCBRsHmxTC_LGiQZEYhlQj6QZuLA");
            pkobj.set_sk(sk_str);
            string ench_ctx = b64decode("BHSzINxb56rx1M3np2KtMMgjfmxvwbuHgO1o1JfOJb5KxUaO6GWf"\
            "4wM5E8iyYOzH7lMtUeJGGNvStBSKMJ9wpHIj38tvlzfA6awL3bgQh94558BtbKYVbW3CaKpCE8AuKlkM8y"\
            "N2C-bMTzHP--Y-M8jZP-lGXH1Mozv-loRKh9tx0n9fKBZ-v5vO88rsNeU530iGGDMd4zctWqGioNrbKrc");
            string ench_str;
            pkobj.pk_decrypt(ench_ctx, ench_str);
            typtop::EncHeaderData ench;
            ench.ParseFromString(ench_str);
            cerr << ench.pw() << endl;
        }*/

        SECTION("Decrypt with wrong key") {
//            pkobj.pk_encrypt(msg, ctx);
            pkobj.Paill_pk_encrypt(t.pad(msg), ctx);
            pkobj.initialize();
//            CHECK_THROWS(pkobj.pk_decrypt(ctx, rdata));
            CHECK_THROWS(pkobj.Paill_pk_decrypt(ctx, rdata, 0));
            CHECK_FALSE(t.unpad(rdata) == msg);
        }

        SECTION("pk_encrypt-decrypt long messages") {
            msg.resize(20, 76);
//            pkobj.pk_encrypt(msg, ctx);
            pkobj.Paill_pk_encrypt(msg, ctx);
//            pkobj.pk_decrypt(ctx, rdata);
            pkobj.Paill_pk_decrypt(ctx, rdata, 0);
            CHECK(CryptoSymWrapperFunctions::Wrapper_b64encode(rdata) == CryptoSymWrapperFunctions::Wrapper_b64encode(msg));
        }

        SECTION("pk encrypt decrypt many messages") {
            msg.resize(10);
            for (size_t i = 0; i < 32; i += 1) {
                PRNG.GenerateBlock((byte *) msg.data(), msg.size());
//                pkobj.pk_encrypt(msg, ctx);
                pkobj.Paill_pk_encrypt(t.pad(msg), ctx);
//                pkobj.pk_decrypt(ctx, rdata);
                pkobj.Paill_pk_decrypt(ctx, rdata, 0);
                CHECK(t.unpad(rdata) == msg);
                if (i % 4 == 0) {
                    string pk = pkobj.serialize_pk();
                    pkobj.set_sk(pkobj.serialize_sk());
                    CHECK(pkobj.serialize_pk() == pk);
                }
            }
        }

        SECTION("pk_encrypt with google protobuf") {
            typtop::EncHeaderData ench;
            get_random_ench(ench);
            string ench_str, ench_ctx;
//            pkobj.pk_encrypt(ench.SerializeAsString(), ench_ctx);
            pkobj.Paill_pk_encrypt(ench.SerializeAsString(), ench_ctx);
//            pkobj.pk_decrypt(ench_ctx, ench_str);
            pkobj.Paill_pk_decrypt(ench_ctx, ench_str, 0);
            CHECK(ench_str == ench.SerializeAsString());

            typtop::EncHeaderData o_ench;
            o_ench.ParseFromString(ench_str);
            PkCrypto pkobj1;
            pkobj1.set_sk(pkobj.serialize_sk());
            pkobj1.set_pk(pkobj.serialize_pk());
            ench_ctx.clear();
            ench_str.clear();
//            pkobj1.pk_encrypt(o_ench.SerializeAsString(), ench_ctx);
            pkobj1.Paill_pk_encrypt(o_ench.SerializeAsString(), ench_ctx);
//            pkobj1.pk_decrypt(ench_ctx, ench_str);
            pkobj1.Paill_pk_decrypt(ench_ctx, ench_str, 0);
            CHECK(ench_str == o_ench.SerializeAsString());
        }
    }


    SECTION("Serialization") {
        PkCrypto pkobj, pkobj1, pkobj2;
        PwPkCrypto t1;
        pkobj.initialize();
        pkobj1.initialize();
        pkobj2.initialize();

        string ctx, rdata, msg = "Message from God!!\1";
//        string msg = pkobj.pad(umsg);
        string sk = pkobj.serialize_sk();
        string pk = pkobj.serialize_pk();

        SECTION("check pk for multiple set_sk with same sk") {
            REQUIRE(pkobj.serialize_pk() == pk);
            pkobj1.set_sk(pkobj.serialize_sk());
            CHECK(CryptoSymWrapperFunctions::Wrapper_b64encode(pkobj1.serialize_sk()) == CryptoSymWrapperFunctions::Wrapper_b64encode(sk));
            pkobj1.set_pk(pkobj.serialize_pk());
            CHECK(CryptoSymWrapperFunctions::Wrapper_b64encode(pkobj1.serialize_pk()) == CryptoSymWrapperFunctions::Wrapper_b64encode(pk));

            pkobj1.set_sk(pkobj.serialize_sk());
            pkobj1.set_pk(pk);
            CHECK(CryptoSymWrapperFunctions::Wrapper_b64encode(pkobj1.serialize_pk()) == CryptoSymWrapperFunctions::Wrapper_b64encode(pk));
        }

        SECTION("check uninitialized keys") {
            CHECK_THROWS(pkobj1.pk_encrypt(sk, ctx));
//            CHECK_THROWS(pkobj1.Paill_pk_encrypt(sk, ctx));
            CHECK_FALSE(pkobj1.can_decrypt());
            CHECK_FALSE(pkobj1.can_encrypt());
        }
        SECTION("set_sk and set_pk") {
            pkobj1.set_sk(sk);
            CHECK(pkobj1.can_decrypt());
            CHECK_FALSE(pkobj1.can_encrypt());
            pkobj1.set_pk(pk);
            CHECK(pkobj1.can_decrypt());
            CHECK(pkobj1.can_encrypt());
        }
        SECTION("check wrong keys") {
            CHECK_THROWS(pkobj.set_pk("adfafasdf"));
            CHECK_THROWS(pkobj.set_sk("adfafasdf"));
        }
        SECTION("Interoperability"){
            pkobj.pk_encrypt(msg, ctx);
//            pkobj.Paill_pk_encrypt(t1.pad(msg), ctx);
            pkobj.pk_decrypt(ctx, rdata);
//            pkobj.Paill_pk_decrypt(ctx, rdata);
            REQUIRE(t1.unpad(rdata) == msg);
            pkobj2.set_pk(pk); pkobj1.set_sk(sk);
            pkobj1.pk_decrypt(ctx, rdata);
//            pkobj1.Paill_pk_decrypt(ctx, rdata);
            CHECK(t1.unpad(rdata) == msg);
            pkobj2.pk_encrypt(msg, ctx);
//            pkobj2.Paill_pk_encrypt(t1.pad(msg), ctx);
            pkobj1.pk_decrypt(ctx, rdata);
//            pkobj1.Paill_pk_decrypt(ctx, rdata);
            CHECK(t1.unpad(rdata) == msg);
        }
    }
}
