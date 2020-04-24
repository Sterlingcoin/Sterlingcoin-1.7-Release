#define BOOST_TEST_MODULE Bitcoin Test Suite
#include <boost/test/unit_test.hpp>

#include "db.h"
#include "main.h"
#include "wallet.h"
#include "util.h"
#include "checkpoints.h"

/* All unresolved externs of init.cpp */
unsigned int nMinerSleep = 2000;
bool fEnforceCanonical = true;
bool fUseFastIndex = false;
enum Checkpoints::CPMode CheckpointsMode;
unsigned int nNodeLifespan = 7;
unsigned int nDerivationMethodIndex = 1;
bool fConfChange = false;

CWallet* pwalletMain;
CClientUIInterface uiInterface;

extern bool fPrintToConsole;
extern void noui_connect();

struct TestingSetup {
    TestingSetup() {
        fPrintToDebugger = true; // don't want to write to debug.log file
        noui_connect();
        bitdb.MakeMock();
        LoadBlockIndex(true);
        bool fFirstRun;
        pwalletMain = new CWallet("wallet.dat");
        pwalletMain->LoadWallet(fFirstRun);
        RegisterWallet(pwalletMain);
    }
    ~TestingSetup()
    {
        delete pwalletMain;
        pwalletMain = NULL;
        bitdb.Flush(true);
    }
};

BOOST_GLOBAL_FIXTURE(TestingSetup);

void Shutdown(void* parg)
{
  exit(0);
}

void StartShutdown()
{
  exit(0);
}

