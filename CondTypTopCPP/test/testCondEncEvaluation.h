//
// Created by mameriek on 9/26/23.
//


/*
 * In this document we will provide and extensive performance evaluation
 * of our suggested conditional encryption schemes designed for different
 * binary predicates.
 *
 * */

#ifndef TYPTOP_TESTCONDENCEVALUATION_H
#define TYPTOP_TESTCONDENCEVALUATION_H


#include <iostream>
#include <string>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <netdb.h>
#include <sys/uio.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <fstream>
#include <random>

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

//    std::ofstream HDdataL("HDdataL.dat", std::ios_base::app | std::ios_base::out);
//    std::ofstream HDdataT("HDdataT.dat", std::ios_base::app | std::ios_base::out);
//    std::ofstream EDOnedataL("EDOnedataL.dat", std::ios_base::app | std::ios_base::out);
//    std::ofstream CAPSLKdataL("CAPSLKdataL.dat", std::ios_base::app | std::ios_base::out);
//    std::ofstream ORdataL("ORdataL.dat", std::ios_base::app | std::ios_base::out);
//    std::ofstream SSdataL("SecretSharing.dat", std::ios_base::app | std::ios_base::out);


//    HDdataL << "L" << "\t" << "Enc" << "\t" << "CondEnc"<< "\t" << "CondDec" << "\t" << "CtxtSize" << "\t" << "CondCtxtSize\n";
//    HDdataT << "T" << "\t" << "Enc" << "\t" << "CondEnc"<< "\t" << "CondDec" << "\t" << "CtxtSize" << "\t" << "CondCtxtSize\n";
//    EDOnedataL << "L" << "\t" << "Enc" << "\t" << "CondEnc"<< "\t" << "CondDec" << "\t" << "CtxtSize" << "\t" << "CondCtxtSize\n";
//    CAPSLKdataL << "L" << "\t" << "Enc" << "\t" << "CondEnc"<< "\t" << "CondDec" << "\t" << "CtxtSize" << "\t" << "CondCtxtSize\n";
//    ORdataL << "L" << "\t" << "Enc" << "\t" << "CondEnc"<< "\t" << "CondDec" << "\t" << "CtxtSize" << "\t" << "CondCtxtSize\n";
//    SSdataL << "T" << "\t" << "Recover\n";
}


string SelectRandPwd();

//We note that the AE_CtxtSize =24 and the SizeShare = 28;
int testCondEncHamDist(int n_lambda, int Num_tests, size_t _len, int Threshold, size_t AE_CtxtSize, size_t SizeShare);

int testCondEncEDist(int n_lambda,  int Num_tests, size_t _len, int Threshold, size_t AE_CtxtSize, int NumOfErrs);
int testCondEncOR(int n_lambda, int Num_tests, size_t _len, int Threshold, size_t AE_CtxtSize, size_t SizeShare);

int testCondEncCAPSLOCK(int n_lambda, int Num_tests, size_t _len, int Threshold, size_t AE_CtxtSize, size_t SizeShare);

TEST_CASE("CAPSLOCK On Error")
{
//    testCondEncCAPSLOCK(1024, 200, 8, 6, 24, 28);
//    testCondEncCAPSLOCK(1024, 200, 16, 14, 24, 28);
//    testCondEncCAPSLOCK(1024, 200, 32, 30, 24, 28);
//    testCondEncCAPSLOCK(2048, 150, 64, 62, 24, 28);
    testCondEncCAPSLOCK(3072, 200, 128, 126, 24, 28);

}

TEST_CASE("Conditional Encryption: Hamming Distance: (n_lambda: 1024, 20, _len: 8, Threshold: 6, AE_CtxtSize 24, SizeShare: 28)  ")
{


//    testCondEncHamDist(1024, 60, 16, 16, 24, 28);
//    testCondEncHamDist(1024, 100, 16, 15, 24, 28);
//    testCondEncHamDist(1024, 100, 16, 14, 24, 28);
//    testCondEncHamDist(1024, 100, 16, 13, 24, 28);
//    testCondEncHamDist(1024, 100, 16, 12, 24, 28);
//
//
//    testCondEncHamDist(1024, 20, 32, 32, 24, 28);
//    testCondEncHamDist(1024, 200, 32, 31, 24, 28);
//    testCondEncHamDist(1024, 200, 32, 30, 24, 28);
//    testCondEncHamDist(1024, 200, 32, 29, 24, 28);
//    testCondEncHamDist(1024, 200, 32, 28, 24, 28);
//
//
//
//    testCondEncHamDist(2048, 10, 64, 64, 24, 28);
//    testCondEncHamDist(2048, 150, 64, 63, 24, 28);
//    testCondEncHamDist(2048, 150, 64, 62, 24, 28);
//    testCondEncHamDist(2048, 100, 64, 61, 24, 28);
//    testCondEncHamDist(2048, 50, 64, 60, 24, 28);
//
//
//    testCondEncHamDist(3072, 100, 128, 128, 24, 28);
//    testCondEncHamDist(3072, 100, 128, 127, 24, 28);
//    testCondEncHamDist(3072, 50, 128, 126, 24, 28);
//    testCondEncHamDist(3072, 50, 128, 125, 24, 28);
//    testCondEncHamDist(3072, 2, 128, 124, 24, 28);



}

TEST_CASE("Conditional Encryption: Edit Distance at most one: (n_lambda: 1024, 20, _len: 8, AE_CtxtSize 24, SizeShare: 28)  ")
{

//    std::ofstream EDOnedataL("EDOnedataL.dat", std::ios_base::app | std::ios_base::out);
//    EDOnedataL << "L" << "\t" << "Enc" << "\t" << "CondEnc"<< "\t" << "CondDec" << "\t" << "CtxtSize" << "\t" << "CondCtxtSize\n";


//    testCondEncEDist(1024, 200, 8, 1, 24, 28);
//    testCondEncEDist(1024, 200, 16, 1, 24, 28);
//    testCondEncEDist(1024, 200, 32, 1, 24, 28);
//    testCondEncEDist(2048, 200, 64, 1, 24, 28);
//    testCondEncEDist(3072, 200, 128, 1, 24, 28);
}

TEST_CASE("OR predicate" )
{
//    std::ofstream ORdataL("ORdataL.dat", std::ios_base::app | std::ios_base::out);
//    ORdataL << "L" << "\t" << "Enc" << "\t" << "CondEnc"<< "\t" << "CondDec" << "\t" << "CtxtSize" << "\t" << "CondCtxtSize\n";

//    testCondEncOR(1024, 200, 8, 6, 24, 28);
//    testCondEncOR(1024, 200, 16, 14, 24, 28);
//    testCondEncOR(1024, 200, 32, 30, 24, 28);
//    testCondEncOR(2048, 200, 64, 62, 24, 28);
//    testCondEncOR(3072, 50, 128, 126, 24, 28);
}

#endif //TYPTOP_TESTCONDENCEVALUATION_H
