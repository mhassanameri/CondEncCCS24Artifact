#include "pw_crypto.h"
//#include "CryptoSymWrapperFunctions.h"
#include "condtyptop.h"


int main(int argc) {
    for(std::string line; std::getline(std::cin, line);) {
        Logs lgs;
        // lgs.ParseFromString(b64decode(line));
        // cout << lgs.DebugString() << endl;
        string l = CryptoSymWrapperFunctions::Wrapper_b64decode(line);
        cout << l.size() << endl << CryptoSymWrapperFunctions::Wrapper_b64decode(line);
    }
    return 0;
}