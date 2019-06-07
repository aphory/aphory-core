#ifndef BITCOIN_CHAINPARAMSIMPORT_H
#define BITCOIN_CHAINPARAMSIMPORT_H


void AddImportHashesMain(std::vector<CImportedCoinbaseTxn> &vImportedCoinbaseTxns)
{
    vImportedCoinbaseTxns.push_back(CImportedCoinbaseTxn(1,   uint256S("d93003b3a774ff61c07be99bcbc7bf00705c16fa25a54294e89d163add16a6ce")));
    vImportedCoinbaseTxns.push_back(CImportedCoinbaseTxn(2,   uint256S("fd82e362f4bd45fe55f016f9bd2771b9c7dcad833b2e1e7fa2572a2d10a55ede")));
    vImportedCoinbaseTxns.push_back(CImportedCoinbaseTxn(3,   uint256S("9e92cda95cd32f646ebebf4badf08a5ec6e071488198223f0296a963b29c6d73")));
    vImportedCoinbaseTxns.push_back(CImportedCoinbaseTxn(4,   uint256S("1d46dbc76914ceb4695e1ed4a17762232348bea8db96acc552f10aefd9f2c4c4")));
    vImportedCoinbaseTxns.push_back(CImportedCoinbaseTxn(5,   uint256S("f443c815e7f55a0151dabec9e4272c07c6010535a40771a03a8340a1899edc74")));
    vImportedCoinbaseTxns.push_back(CImportedCoinbaseTxn(6,   uint256S("5ec8a6ac2c28a1f621a1104fa204e139d15c1e286ca3ff33df6a1e91b25cb35b")));
    vImportedCoinbaseTxns.push_back(CImportedCoinbaseTxn(7,   uint256S("6c31f642655442fa56d920ea7250187ff51770089c3df9e88d47b5d106df8a77")));
    vImportedCoinbaseTxns.push_back(CImportedCoinbaseTxn(8,   uint256S("f7c2f8d86fa579bb7596336c2e2c6fa2abeeb09f97326ef88dc888e89b66ba7c")));
    vImportedCoinbaseTxns.push_back(CImportedCoinbaseTxn(9,   uint256S("e50fd54936f6a987b82a25b025597dc6c36e2fb41a0fd56dae89ac74c6b57474")));
    vImportedCoinbaseTxns.push_back(CImportedCoinbaseTxn(10,  uint256S("6a968bbcb100bc1c11e882707e381ff8138b960063651b996bc31b924ff00855")));
    vImportedCoinbaseTxns.push_back(CImportedCoinbaseTxn(11,  uint256S("5dcf7c54ae2c898123ae9022d09ece2c15df69b02616bfae51e0e44444be39fb")));
    vImportedCoinbaseTxns.push_back(CImportedCoinbaseTxn(12,  uint256S("a8729b74cf903cfccba2dd007d5f059b8e99df0f04fa28594e4b5b337bd63c30")));
    vImportedCoinbaseTxns.push_back(CImportedCoinbaseTxn(13,  uint256S("b3e846412e72d90ad5278a7fa3f17c7696b220ffc629f272e2a919c21cc1bb27")));
    vImportedCoinbaseTxns.push_back(CImportedCoinbaseTxn(14,  uint256S("172b07d6f216be7fdeebbb30b53a76fd060da51b7b86fb8fc503b23d13f1ad7d")));
    vImportedCoinbaseTxns.push_back(CImportedCoinbaseTxn(15,  uint256S("b0b07611144e1afe4f8e0ff5103bd0c36bae63ee40213fbaa401092a95b3f898")));
};

void AddImportHashesTest(std::vector<CImportedCoinbaseTxn> &vImportedCoinbaseTxns)
{
    vImportedCoinbaseTxns.push_back(CImportedCoinbaseTxn(1,  uint256S("445a50bc149671b41c0cb5df46267d55250752c3cc537f7beffc0d3ac90000e6")));
};


#endif // BITCOIN_CHAINPARAMSIMPORT_H
