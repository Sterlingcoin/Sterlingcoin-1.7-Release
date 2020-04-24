#include <boost/test/unit_test.hpp>

#include <string>
#include <iostream>
#include <vector>

#include "key.h"
#include "base58.h"
#include "uint256.h"
#include "util.h"

#define KEY_TESTS_DUMPINFO 1

using namespace std;

static const string strSecret1     ("7RjtfBG7CyxYW6bSB9v38ntheNr3zemn9sZLLR8DqJBd7WWxawZ");
static const string strSecret2     ("7S74kTyXtxGqRB7EkyFNuKBcfZAYZJ6ZfjykKzw92EWRbV2RNtw");
static const string strSecret1C    ("VHkEeULJDXWmv7DcPpgGndZFU7cMgyNB6wFwEJZmaEz7P6jyBsNP");
static const string strSecret2C    ("VPaV4ajusL5VyZzZ9XVsRjfKZvC537hXN82WXeSagG2tJuTGpzQ6");
static const CBitcoinAddress addr1 ("Sb6RkwzpNv9SpAiwfnqteUt8Cjv6NmsEvw");
static const CBitcoinAddress addr2 ("SRdvx8idw8ZsJRYGn3JimG6jJ6z2Cyugst");
static const CBitcoinAddress addr1C("Sfjhu5XqVgxz52DXdh2vRMijBydVp2UnGE");
static const CBitcoinAddress addr2C("Sfa8kGvBcjmossqtB8R7EcJvgEwSDXG4i6");


static const string strAddressBad("1HV9Lc3sNHZxwj4Zk6fB38tEmBryq2cBiF");


#ifdef KEY_TESTS_DUMPINFO


// void importprivkey(std::string secretkeybase58)
// {
//     string strSecret = params[0].get_str();
//     CBitcoinSecret vchSecret;
//     bool fGood = vchSecret.SetString(strSecret);
//     CKey key;
//     bool fCompressed;
//     CSecret secret = vchSecret.GetSecret(fCompressed);
//     key.SetSecret(secret, fCompressed);
//     CKeyID vchAddress = key.GetPubKey().GetID();
// }


void dumpKeyInfo(uint256 privkey)
{
    CSecret secret;
    secret.resize(32);
    memcpy(&secret[0], &privkey, 32);
    vector<unsigned char> sec;
    sec.resize(32);
    memcpy(&sec[0], &secret[0], 32);
    printf("  * secret (hex): %s\n", HexStr(sec).c_str());

    for (int nCompressed=0; nCompressed<2; nCompressed++)
    {
        bool fCompressed = nCompressed == 1;
        printf("  * %s:\n", fCompressed ? "compressed" : "uncompressed");
        CBitcoinSecret bsecret;
        bsecret.SetSecret(secret, fCompressed);
        printf("    * secret (base58): %s\n", bsecret.ToString().c_str());
        CKey key;
        key.SetSecret(secret, fCompressed);
        vector<unsigned char> vchPubKey = key.GetPubKey().Raw();
        printf("    * pubkey (hex): %s\n", HexStr(vchPubKey).c_str());
        printf("    * address (base58): %s\n", CBitcoinAddress(HexStr(vchPubKey)).ToString().c_str());
    }
}
#endif


BOOST_AUTO_TEST_SUITE(key_tests)

BOOST_AUTO_TEST_CASE(key_test1)
{
    CBitcoinSecret bsecret1, bsecret2, bsecret1C, bsecret2C, baddress1;
    BOOST_CHECK( bsecret1.SetString (strSecret1));
    BOOST_CHECK( bsecret2.SetString (strSecret2));
    BOOST_CHECK( bsecret1C.SetString(strSecret1C));
    BOOST_CHECK( bsecret2C.SetString(strSecret2C));
    BOOST_CHECK(!baddress1.SetString(strAddressBad));

    bool fCompressed;
    CSecret secret1  = bsecret1.GetSecret (fCompressed);
    BOOST_CHECK(fCompressed == false);
    CSecret secret2  = bsecret2.GetSecret (fCompressed);
    BOOST_CHECK(fCompressed == false);

    CSecret secret1C = bsecret1C.GetSecret(fCompressed);
    BOOST_CHECK(fCompressed == true);
    CSecret secret2C = bsecret2C.GetSecret(fCompressed);
    BOOST_CHECK(fCompressed == true);

    BOOST_CHECK(secret1 == secret1C);
    // std::string s(secret1, sizeof(secret1));
    // std::cout << "Secret:  " << std::hex << secret1 << std::endl;
    // dumpKeyInfo(secret1);
    // dumpKeyInfo(secret1C);
    BOOST_CHECK(secret2 == secret2C);
    // dumpKeyInfo(secret2);
    // dumpKeyInfo(secret2C);

    CKey key1, key2, key1C, key2C;
    key1.SetSecret(secret1, false);
    key2.SetSecret(secret2, false);
    key1C.SetSecret(secret1, true);
    key2C.SetSecret(secret2, true);

    BOOST_CHECK(addr1.Get()  == CTxDestination(key1.GetPubKey().GetID()));
    BOOST_CHECK(addr2.Get()  == CTxDestination(key2.GetPubKey().GetID()));
    BOOST_CHECK(addr1C.Get() == CTxDestination(key1C.GetPubKey().GetID()));
    BOOST_CHECK(addr2C.Get() == CTxDestination(key2C.GetPubKey().GetID()));

    for (int n=0; n<16; n++)
    {
        string strMsg = strprintf("Very secret message %i: 11", n);
        uint256 hashMsg = Hash(strMsg.begin(), strMsg.end());

        // normal signatures

        vector<unsigned char> sign1, sign2, sign1C, sign2C;

        BOOST_CHECK(key1.Sign (hashMsg, sign1));
        BOOST_CHECK(key2.Sign (hashMsg, sign2));
        BOOST_CHECK(key1C.Sign(hashMsg, sign1C));
        BOOST_CHECK(key2C.Sign(hashMsg, sign2C));

        BOOST_CHECK( key1.Verify(hashMsg, sign1));
        BOOST_CHECK(!key1.Verify(hashMsg, sign2));
        BOOST_CHECK( key1.Verify(hashMsg, sign1C));
        BOOST_CHECK(!key1.Verify(hashMsg, sign2C));

        BOOST_CHECK(!key2.Verify(hashMsg, sign1));
        BOOST_CHECK( key2.Verify(hashMsg, sign2));
        BOOST_CHECK(!key2.Verify(hashMsg, sign1C));
        BOOST_CHECK( key2.Verify(hashMsg, sign2C));

        BOOST_CHECK( key1C.Verify(hashMsg, sign1));
        BOOST_CHECK(!key1C.Verify(hashMsg, sign2));
        BOOST_CHECK( key1C.Verify(hashMsg, sign1C));
        BOOST_CHECK(!key1C.Verify(hashMsg, sign2C));

        BOOST_CHECK(!key2C.Verify(hashMsg, sign1));
        BOOST_CHECK( key2C.Verify(hashMsg, sign2));
        BOOST_CHECK(!key2C.Verify(hashMsg, sign1C));
        BOOST_CHECK( key2C.Verify(hashMsg, sign2C));

        // compact signatures (with key recovery)

        vector<unsigned char> csign1, csign2, csign1C, csign2C;

        BOOST_CHECK(key1.SignCompact (hashMsg, csign1));
        BOOST_CHECK(key2.SignCompact (hashMsg, csign2));
        BOOST_CHECK(key1C.SignCompact(hashMsg, csign1C));
        BOOST_CHECK(key2C.SignCompact(hashMsg, csign2C));

        CKey rkey1, rkey2, rkey1C, rkey2C;

        BOOST_CHECK(rkey1.SetCompactSignature (hashMsg, csign1));
        BOOST_CHECK(rkey2.SetCompactSignature (hashMsg, csign2));
        BOOST_CHECK(rkey1C.SetCompactSignature(hashMsg, csign1C));
        BOOST_CHECK(rkey2C.SetCompactSignature(hashMsg, csign2C));


        BOOST_CHECK(rkey1.GetPubKey()  == key1.GetPubKey());
        BOOST_CHECK(rkey2.GetPubKey()  == key2.GetPubKey());
        BOOST_CHECK(rkey1C.GetPubKey() == key1C.GetPubKey());
        BOOST_CHECK(rkey2C.GetPubKey() == key2C.GetPubKey());
    }
}

BOOST_AUTO_TEST_SUITE_END()
