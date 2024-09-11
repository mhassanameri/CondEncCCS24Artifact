//
// Created by hassan on 9/10/24.
//

#ifndef TEST_CONDTYPTOP_H
#define TEST_CONDTYPTOP_H

#include "condtyptop.h"
#define CATCH_CONFIG_MAIN // This should come **before** including the 'catch.hpp'.
#define MY_SIGSTKSZ 8192
#include "catch.hpp"

#include <iostream>
#include <fstream>
#include <chrono>

#include <random>
using namespace std::chrono;

#define DEBUG 1
#define times(n, code_block) {for(int _ti=0; _ti<n; _ti++) code_block;}

const string _db_fname = "./test_condtyptop_db";

bool MHF_ON;
string install_id; // get_install_id();
const int32_t infinity = INT_MAX;

class TypTopTest : public TypTop {
public:
    TypTopTest() : TypTop(_db_fname) {};
    using TypTop::add_to_waitlist;
    using TypTop::get_db;
    using TypTop::get_ench;
    using TypTop::get_pkobj;
    using TypTop::permute_typo_cache;
    using TypTop::initialize;
    using TypTop::reinitialize;
    using TypTop::MHF_Activation;
    using TypTop::ConDec32OPT_Activation;
};


int testCondTypTop_no_32_OPT(int NUM_ROUNDS, bool MHF_ON, bool OPT_32_HAMDist2_ON);


TEST_CASE("CondTypTopEval")
{

     std::string input[4];
     std::ifstream inputFile("input_condTypTopEval.txt"); // Open the file "input.txt"
     inputFile >> input[0]; //Number of Round tests (for how many pwd form the PWD DataSet the CondTypTop will be initialized

    std::ofstream TyptopCondOPT("CondTypTopEval.dat", std::ios_base::app | std::ios_base::out);
    TyptopCondOPT << "For simplicity in comparing the numbers, all numbers are in Micor Second.\n";
    TyptopCondOPT << "TypTopType" <<"\t" << "Init" << "\t" << "usrLoginNotif(Correct)" << "\t" << "usrLoginNotif(Incorrect)" <<"\t" << "TotalProcessingTime (Correct Login)"<< "\t" << "TotalProcessingTime (Incorrect Login)" << "\t" << "ProcessWaitListContainsValidTypo" << "\t" << "WaitListSize" <<"\n";

    bool MHF_ON= true;
    bool MHF_OFF = false;
    bool OPT_32_HAMDist2_ON =true;
    bool OPT_32_HAMDist2_OFF =false;
     int Num_Rounds =  std::stoi(input[0]);

    auto rslt1 =  testCondTypTop_no_32_OPT(Num_Rounds, MHF_OFF, OPT_32_HAMDist2_OFF);
    auto rslt2 =  testCondTypTop_no_32_OPT(Num_Rounds, MHF_ON, OPT_32_HAMDist2_OFF);
    auto rslt3 =  testCondTypTop_no_32_OPT(Num_Rounds, MHF_OFF, OPT_32_HAMDist2_ON);
    auto rslt4 =  testCondTypTop_no_32_OPT(Num_Rounds, MHF_ON, OPT_32_HAMDist2_ON);

}




#endif //TEST_CONDTYPTOP_H



