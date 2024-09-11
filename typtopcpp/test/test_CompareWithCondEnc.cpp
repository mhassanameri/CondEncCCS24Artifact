//
// Created by mameriek on 9/19/22.
//


#include "typtop.h"
#include "catch.hpp"

#include <iostream>
#include <fstream>
#include <chrono>

#include <random>
using namespace std::chrono;

#define DEBUG 1
#define times(n, code_block) {for(int _ti=0; _ti<n; _ti++) code_block;}

const string _db_fname = "./test_typtop_db";



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
};


int convertOpposite(string& str)
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
}




string SelectRandPwd()
{

    string pwd;
    std::random_device rd;

    /* Random number generator */
    std::default_random_engine generator(rd());

    /* Distribution on which to apply the generator */
    std::uniform_int_distribution<long long unsigned> distribution(0,0xFFFFFFFFF);
    long long int  index = distribution(generator) % 14344383;
    assert (index < 14344383); //14344383 is the number of passwords in Rockyou.txt. Here we just randomly select a random line in the rockyou.txt

    std::string line;
    std::ifstream myfile("/Users/mameriek/Downloads/rockyou.txt");
//    ifstream myfile ("/Users/mameriek/Documents/GitHub/ConditionalEncryptionTypTop/CondEncCPP/CMakeLists.txt1");
//    myfile.open("/Users/mameriek/Documents/GitHub/ConditionalEncryptionTypTop/CondEncCPP/rockyou.txt");
    if (myfile.is_open()) {
        for (int lineno = 0; getline(myfile, line) && lineno < index + 1; lineno++) {
            if (lineno == index) {
                pwd = line;
            }
        }
        myfile.close();
    }
    else cout << "rockyou.txt unable to be opened";
    return pwd;
}

/*
 * This function takes the password pwd and based on the distribution of typos descriped in the TypTop papaer, generates
 * a typo.
 * HD2 impleis probability of the error has hamming distance of two,
 * HD1 impleis probability of the error has hamming distance of one,
 * ED1 impleis probability of the error has edit distance of one,
 * CAPSLCK impleis probability of the error happens when the Capslck error was one.
 * The idea is that we select a random number and based on the weight of each random number we decide which one should
 * chosen.
 *
 * The idea is each typo type has a weight, which is its chance in being chosen. The weight
 * is chosen based on the data provided by Chatterjee et al in oroginal Tytpot paper. So, we
 * basically use this data for our emperical analysis and we consider Rockyou leaked password
 * in our impelementaiosn. So we select a random password among the leaked passwrod and generate
 * a typo out of it.
 *
 * */

string MakeTypo(string &pwd)
{
    string typo = pwd;
    int repeat = 1;
    int HD2 = 10;
    int HD1 = 31;
    int ED1 = 24;
    int CAPSLCK = 14;


    while (repeat ==1)
    {
        unsigned seed = time(NULL);
        srand(seed);
        int r =rand() % 100;

        if (0 < r && r < HD1)
        {
            unsigned seed= time(0);
            char err1;
            srand(seed);
            err1 = 32 + (rand() % 95);
            int ErrLction;
            ErrLction = rand() % (pwd.size());
            typo[ErrLction] = err1;
            repeat = 0;
        }
        else if (HD1 < r && r <= HD1 + HD2)
        {
            unsigned seed= time(NULL);
            char err1,err2;
            int ErrLction1, ErrLction2;
            srand(seed);
            ErrLction1 = rand() % (pwd.size());
            err1 = 32 + (rand() % 95);
            typo[ErrLction1] = err1;

            seed = time(0);
            ErrLction2 = rand() % (pwd.size());
            err2 = 32 + (rand() % 95);
            typo[ErrLction1] = err2;
            repeat = 0;
        }
        else if (HD1 + HD2 < r && r <= HD1 + HD2 + ED1)
        {
            int errType;
            unsigned seed = time(0);
            errType = rand() % 2;
            int ErrLction;
            if (errType == 0) //random deletion
            {
                ErrLction = rand() % (pwd.size());
                typo = pwd.substr(0, ErrLction) + pwd.substr(ErrLction+1, pwd.size());
            }
            else
            {
                unsigned seed = time(0);
                ErrLction = rand() % (pwd.size());
                char err = 32 + (rand() % 95);
                typo =  pwd.substr(0, ErrLction) + err + pwd.substr(ErrLction, pwd.size());
            }
            repeat = 0;
        }
        else if (HD1 + HD2 + ED1 < r && r <= HD1 + HD2 + ED1 + CAPSLCK)
        {
            typo = convertOpposite(pwd);
            repeat = 0;
        }
        else
        {
            unsigned seed = time(0);
            srand(seed);
//            int ErrLction1 = rand() % (pwd.size());
            char err1 = 32 + (rand() % 95);
            seed = time(0);
            srand(seed);
            char err2 = 32 + (rand() % 95);
            seed = time(0);
            srand(seed);
            char err3 = 32 + (rand() % 95);
            typo = pwd + err1 + err2 + err3;
            cout << " Edit distance more than 2";
            repeat = 0;
        }
        if(typo == pwd )
        {
            repeat =1;
        }
    }
    return typo;
}



//TEST_CASE("Generating Raw data files for storing the extracted data after testing")
//{
//
//    std::ofstream TyptopCondOPT("TypTopCondEval.dat", std::ios_base::app | std::ios_base::out);
//
//    TyptopCondOPT << "TypTopType" <<"\t" << "Init" << "\t" << "usrLoginNotif(Correct)" << "\t" << "usrLoginNotif(Incorrect)" <<"\t" << "TotalProcessingTimeCorrectLogin"<< "\t" << "TotalProcessingTimeIncorrectLogin" << "\t" << "ProcessWaitListContainsValidTypo" << "\t" << "WaitListSize" <<"\n";
//
//}


TEST_CASE("Timing") {
    std::ofstream TyptopCondOPT("TypTop.dat", std::ios_base::app | std::ios_base::out);
    TyptopCondOPT << "TypTopType" <<"\t" << "Init" << "\t" << "usrLoginNotif(Correct)" << "\t" << "usrLoginNotif(Incorrect)" <<"\t" << "TotalProcessingTimeCorrectLogin"<< "\t" << "TotalProcessingTimeIncorrectLogin" << "\t" << "ProcessWaitListContainsValidTypo" << "\t" << "WaitListSize" <<"\n";

    int NUM_ROUNDS = 20;
    double Sum_time_init =0;
    double Sum_time_UsrNotif_Correct_Lgin =0;
    double Sum_time_UsrNotif_incorrect_Lgin =0;
    double Sum_time_TotalProcessing_OrignPWD =0;
    double Sum_time_TotalProcessing_IncrctTypo =0;
    double Sum_time_Login_WaitListIncludeValidTypo =0;
    double SizeOfWaitingList =0;

    for (int round = 0; round <NUM_ROUNDS; round++) // number of passwords the the systm is initialized with.
    {
        install_id = get_install_id();
        remove(_db_fname.c_str());
        TypTopTest tp;
        vector<string> pws(2);

        const typoDB &db = tp.get_db();
        REQUIRE(db.h().sys_state() == SystemStatus::UNINITIALIZED);

        pws[0] = SelectRandPwd();
        pws[1] = MakeTypo(pws[0]);
        string sk_str;
        int i;


        auto start = high_resolution_clock::now();
        if (!tp.check(pws[0], SECOND_TIME, false))
        {
            cout <<  "password check with the original pwd was failed0 \n";
        }
//        tp.check(pws[0], SECOND_TIME, false);   // set the password
        auto stop = high_resolution_clock::now();
        auto time_init = duration_cast<milliseconds>(stop - start);/* Computes the execution time of initialization phase*/
        Sum_time_init += time_init.count();

        auto start_LginOrigPWD = high_resolution_clock::now();

        if (!tp.check(pws[0], FIRST_TIME, false))
        {
            cout <<  "password check with the original pwd was failed1 \n";
            tp.check(pws[0], FIRST_TIME, false);
        }
//        REQUIRE(tp.check(pws[0], FIRST_TIME, false));
//        tp.check(pws[0], FIRST_TIME, false);
        auto stop_LginOrigPWD = high_resolution_clock::now();
        auto time_TotalProcessing_OrignPWD = duration_cast<milliseconds>(stop_LginOrigPWD - start_LginOrigPWD);
//        double time_AveTotalProcessing_OrignPWD = time_TotalProcessing_OrignPWD.count();
        Sum_time_TotalProcessing_OrignPWD +=   time_TotalProcessing_OrignPWD.count();


        auto start_Correct_login = high_resolution_clock::now();
        i = tp.is_typo_present(pws[0], sk_str);
        auto stop_Correct_login = high_resolution_clock::now();
//        assert(i == 0);
        auto time_UsrNotif_Correct_Lgin = duration_cast<microseconds>(
                stop_Correct_login - start_Correct_login); //When we use MHF, sec is the orde of  computations.

        Sum_time_UsrNotif_Correct_Lgin += time_UsrNotif_Correct_Lgin.count();

        auto start_Incorrect_login = high_resolution_clock::now();
        i = tp.is_typo_present(pws[1], sk_str);
        auto stop_Incorrect_login = high_resolution_clock::now();
//        assert(i == T_size);

        auto time_UsrNotif_incorrect_Lgin = duration_cast<microseconds>(
                stop_Incorrect_login - start_Incorrect_login); //When we use MHF, sec is the orde of  computations.
        Sum_time_UsrNotif_incorrect_Lgin +=  time_UsrNotif_incorrect_Lgin.count();

        auto start_LginIncrctTypo = high_resolution_clock::now();
        times(W_size, CHECK_FALSE(tp.check(pws[1], FIRST_TIME, false)));
        auto stop_LginIncrctTypo = high_resolution_clock::now();

        auto time_TotalProcessing_IncrctTypo = duration_cast<milliseconds>(
                stop_LginIncrctTypo - start_LginIncrctTypo);
        Sum_time_TotalProcessing_IncrctTypo  +=  (time_TotalProcessing_IncrctTypo.count() / W_size);


        auto start_Login_WaitListIncludeValidTypo = high_resolution_clock::now();
        REQUIRE(tp.check(pws[0], FIRST_TIME, false));
        auto stop_Login_WaitListIncludeValidTypo = high_resolution_clock::now();
        auto time_Login_WaitListIncludeValidTypo = duration_cast<milliseconds>(
                stop_Login_WaitListIncludeValidTypo - start_Login_WaitListIncludeValidTypo);

        Sum_time_Login_WaitListIncludeValidTypo +=    time_Login_WaitListIncludeValidTypo.count();


        SizeOfWaitingList = ((db.w(1).size()) * W_size) / 1024;
//        double SizeOfWaitingList =  1028;


        TyptopCondOPT << "TypTop (mhf-2)" << "\t" << time_init.count() << "\t"
                      << time_UsrNotif_Correct_Lgin.count()  << "\t" << time_UsrNotif_incorrect_Lgin.count()
                      << "\t" << time_TotalProcessing_OrignPWD.count() << "\t" << time_TotalProcessing_IncrctTypo.count() / W_size
                      << "\t" << time_Login_WaitListIncludeValidTypo.count() << "\t" << SizeOfWaitingList << "\n";



        cout << "round #" << round << "\n";

    }

    double AVERAGE_time_init =Sum_time_init / NUM_ROUNDS;
    double AVERAGE_time_UsrNotif_Correct_Lgin  =            Sum_time_UsrNotif_Correct_Lgin    / NUM_ROUNDS;
    double AVERAGE_time_UsrNotif_incorrect_Lgin =           Sum_time_UsrNotif_incorrect_Lgin  / NUM_ROUNDS;
    double AVERAGE_time_TotalProcessing_OrignPWD =          Sum_time_TotalProcessing_OrignPWD /  NUM_ROUNDS;
    double AVERAGE_time_TotalProcessing_IncrctTypo =      Sum_time_TotalProcessing_IncrctTypo /  NUM_ROUNDS ;
    double AVERAGE_time_Login_WaitListIncludeValidTypo =  Sum_time_Login_WaitListIncludeValidTypo / NUM_ROUNDS;

    TyptopCondOPT << "Average: TypTop (mhf-2)" << "\t" << AVERAGE_time_init << "\t"
                  << AVERAGE_time_UsrNotif_Correct_Lgin << "\t" << AVERAGE_time_UsrNotif_incorrect_Lgin
                  << "\t" << AVERAGE_time_TotalProcessing_OrignPWD << "\t" << AVERAGE_time_TotalProcessing_IncrctTypo
                  << "\t" << AVERAGE_time_Login_WaitListIncludeValidTypo << "\t" << SizeOfWaitingList << "\n";

}




