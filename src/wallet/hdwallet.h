// Copyright (c) 2017-2019 The Particl Core developers
// Copyright (c) 2019 The Aphory Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef APHORY_WALLET_HDWALLET_H
#define APHORY_WALLET_HDWALLET_H

#include <wallet/wallet.h>
#include <wallet/hdwalletdb.h>

#include <key_io.h>
#include <key/extkey.h>
#include <key/stealth.h>

typedef std::map<CKeyID, CStealthKeyMetadata> StealthKeyMetaMap;
typedef std::map<CKeyID, CExtKeyAccount*> ExtKeyAccountMap;
typedef std::map<CKeyID, CStoredExtKey*> ExtKeyMap;

typedef std::map<uint256, CWalletTx> MapWallet_t;
typedef std::map<uint256, CTransactionRecord> MapRecords_t;

typedef std::multimap<int64_t, std::map<uint256, CTransactionRecord>::iterator> RtxOrdered_t;

class UniValue;

struct CBlockTemplate;

const uint16_t OR_PLACEHOLDER_N = 0xFFFF; // index of a fake output to contain reconstructed amounts for txns with undecodeable outputs
enum OutputRecordFlags
{
    ORF_OWNED               = (1 << 0),
    ORF_FROM                = (1 << 1),
    ORF_CHANGE              = (1 << 2),
    ORF_SPENT               = (1 << 3),
    ORF_LOCKED              = (1 << 4), // Needs wallet to be unlocked for further processing
    ORF_STAKEONLY           = (1 << 5),
    ORF_WATCHONLY           = (1 << 6),
    ORF_HARDWARE_DEVICE     = (1 << 7),

    ORF_OWN_WATCH           = ORF_STAKEONLY | ORF_WATCHONLY,
    ORF_OWN_ANY             = ORF_OWNED | ORF_OWN_WATCH,

    ORF_BLIND_IN            = (1 << 14),
    ORF_ANON_IN             = (1 << 15),
};

enum OutputRecordAddressTypes
{
    ORA_EXTKEY       = 1,
    ORA_STEALTH      = 2,
    ORA_STANDARD     = 3,
};

class COutputRecord
{
public:
    COutputRecord() : nType(0), nFlags(0), n(0), nValue(-1) {};
    uint8_t nType;
    uint8_t nFlags;
    uint16_t n;
    CAmount nValue;
    CScript scriptPubKey;
    std::string sNarration;

    /*
    vPath 0 - ORA_EXTKEY
        1 - index to m
        2... path

    vPath 0 - ORA_STEALTH
        [1, 21] stealthkeyid
        [22, 55] pubkey (if not using ephemkey)

    vPath 0 - ORA_STANDARD
        [1, 34] pubkey
    */
    std::vector<uint8_t> vPath; // index to m is stored in first entry

    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action)
    {
        READWRITE(nType);
        READWRITE(nFlags);
        READWRITE(n);
        READWRITE(nValue);
        READWRITE(*(CScriptBase*)(&scriptPubKey));
        READWRITE(sNarration);
        READWRITE(vPath);
    };
};

enum RTxAddonValueTypes
{
    RTXVT_EPHEM_PATH            = 1, // path ephemeral keys are derived from packed 4bytes no separators

    RTXVT_REPLACES_TXID         = 2,
    RTXVT_REPLACED_BY_TXID      = 3,

    RTXVT_COMMENT               = 4,
    RTXVT_TO                    = 5,

    /*
    RTXVT_STEALTH_KEYID     = 2,
    RTXVT_STEALTH_KEYID_N   = 3, // n0:pk0:n1:pk1:...
    */
};

typedef std::map<uint8_t, std::vector<uint8_t> > mapRTxValue_t;
class CTransactionRecord
{
// Stored by uint256 txnHash;
public:
    // Conflicted state is marked by set blockHash and nIndex -1
    uint256 blockHash;
    int16_t nFlags = 0;
    int16_t nIndex = 0;

    int64_t nBlockTime = 0;
    int64_t nTimeReceived = 0;
    CAmount nFee = 0;
    mapRTxValue_t mapValue;

    std::vector<COutPoint> vin;
    std::vector<COutputRecord> vout;

    int InsertOutput(COutputRecord &r);
    bool EraseOutput(uint16_t n);

    COutputRecord *GetOutput(int n);
    const COutputRecord *GetOutput(int n) const;
    const COutputRecord *GetChangeOutput() const;

    void SetMerkleBranch(const uint256 &blockHash_, int posInBlock)
    {
        blockHash = blockHash_;
        nIndex = posInBlock;
    }

    bool IsAbandoned() const { return (blockHash == ABANDON_HASH); }
    bool HashUnset() const { return (blockHash.IsNull() || blockHash == ABANDON_HASH); }

    void SetAbandoned()
    {
        blockHash = ABANDON_HASH;
    }

    int64_t GetTxTime() const
    {
        if (HashUnset() || nIndex < 0) {
            return nTimeReceived;
        }
        return std::min(nTimeReceived, nBlockTime);
    }

    bool HaveChange() const
    {
        for (const auto &r : vout) {
            if (r.nFlags & ORF_CHANGE) {
                return true;
            }
        }
        return false;
    }

    CAmount TotalOutput()
    {
        CAmount nTotal = 0;
        for (const auto &r : vout) {
            nTotal += r.nValue;
        }
        return nTotal;
    }

    bool InMempool() const;
    bool IsCoinBase() const {return false;};
    bool IsCoinStake() const {return false;};

    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream &s, Operation ser_action)
    {
        READWRITE(blockHash);
        READWRITE(nFlags);
        READWRITE(nIndex);
        READWRITE(nBlockTime);
        READWRITE(nTimeReceived);
        READWRITE(mapValue);
        READWRITE(nFee);
        READWRITE(vin);
        READWRITE(vout);
    }
};


class CTempRecipient
{
public:
    CTempRecipient() : nType(0), nAmount(0), nAmountSelected(0), fSubtractFeeFromAmount(false) {SetNull();};
    CTempRecipient(CAmount nAmount_, bool fSubtractFeeFromAmount_, CScript scriptPubKey_)
        : nAmount(nAmount_), nAmountSelected(nAmount_), fSubtractFeeFromAmount(fSubtractFeeFromAmount_), scriptPubKey(scriptPubKey_) {SetNull();};

    void SetNull()
    {
        fScriptSet = false;
        fChange = false;
        fNonceSet = false; // if true use nonce and vData from CTempRecipient
        nChildKey = 0;
        nChildKeyColdStaking = 0;
        nStealthPrefix = 0;
        fSplitBlindOutput = false;
        fExemptFeeSub = false;
    }

    void SetAmount(CAmount nValue)
    {
        nAmount = nValue;
        nAmountSelected = nValue;
    }

    bool ApplySubFee(CAmount nFee, size_t nSubtractFeeFromAmount, bool &fFirst);

    uint8_t nType;
    CAmount nAmount;            // If fSubtractFeeFromAmount, nAmount = nAmountSelected - feeForOutput
    CAmount nAmountSelected;
    bool fSubtractFeeFromAmount;
    bool fSplitBlindOutput;
    bool fExemptFeeSub;         // Value too low to sub fee when blinded value split into two outputs
    CTxDestination address;
    CTxDestination addressColdStaking;
    CScript scriptPubKey;
    std::vector<uint8_t> vData;
    std::vector<uint8_t> vBlind;
    std::vector<uint8_t> vRangeproof;
    secp256k1_pedersen_commitment commitment;
    uint256 nonce;

    // TODO: range proof parameters, try to keep similar for fee
    // Allow an overwrite of the parameters.
    bool fOverwriteRangeProofParams = false;
    uint64_t min_value;
    int ct_exponent;
    int ct_bits;        // set to 0 to mark bulletproof

    CKey sEphem;
    CPubKey pkTo;
    int n;
    std::string sNarration;
    bool fScriptSet;
    bool fChange;
    bool fNonceSet;
    uint32_t nChildKey; // update later
    uint32_t nChildKeyColdStaking; // update later
    uint32_t nStealthPrefix;
};


class COutputR
{
public:
    COutputR() {};

    COutputR(const uint256 &txhash_, MapRecords_t::const_iterator rtx_, int i_, int nDepth_,
        bool fSpendable_, bool fSolvable_, bool fSafe_, bool fMature_, bool fNeedHardwareKey_)
        : txhash(txhash_), rtx(rtx_), i(i_), nDepth(nDepth_),
        fSpendable(fSpendable_), fSolvable(fSolvable_), fSafe(fSafe_), fMature(fMature_), fNeedHardwareKey(fNeedHardwareKey_) {};

    uint256 txhash;
    MapRecords_t::const_iterator rtx;
    int i;
    int nDepth;
    bool fSpendable;
    bool fSolvable;
    bool fSafe;
    bool fMature;
    bool fNeedHardwareKey;
};


class CStoredTransaction
{
public:
    CTransactionRef tx;
    std::vector<std::pair<int, uint256> > vBlinds;

    bool InsertBlind(int n, const uint8_t *p)
    {
        for (auto &bp : vBlinds) {
            if (bp.first == n) {
                memcpy(bp.second.begin(), p, 32);
                return true;
            }
        }
        uint256 insert;
        memcpy(insert.begin(), p, 32);
        vBlinds.push_back(std::make_pair(n, insert));
        return true;
    }

    bool GetBlind(int n, uint8_t *p) const
    {
        for (auto &bp : vBlinds) {
            if (bp.first == n) {
                memcpy(p, bp.second.begin(), 32);
                return true;
            }
        }
        return false;
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(tx);
        READWRITE(vBlinds);
    }
};

class CHDWalletBalances
{
public:
    void Clear()
    {
        nPart = 0;
        nPartUnconf = 0;
        nPartStaked = 0;
        nPartImmature = 0;
        nPartWatchOnly = 0;
        nPartWatchOnlyUnconf = 0;
        nPartWatchOnlyStaked = 0;

        nBlind = 0;
        nBlindUnconf = 0;

        nAnon = 0;
        nAnonUnconf = 0;
        nAnonImmature = 0;
    }

    CAmount nPart = 0;
    CAmount nPartUnconf = 0;
    CAmount nPartStaked = 0;
    CAmount nPartImmature = 0;
    CAmount nPartWatchOnly = 0;
    CAmount nPartWatchOnlyUnconf = 0;
    CAmount nPartWatchOnlyStaked = 0;

    CAmount nBlind = 0;
    CAmount nBlindUnconf = 0;

    CAmount nAnon = 0;
    CAmount nAnonUnconf = 0;
    CAmount nAnonImmature = 0;
};

class CHDWallet : public CWallet
{
public:
    CHDWallet(interfaces::Chain& chain, const WalletLocation& location, std::unique_ptr<WalletDatabase> dbw_in) : CWallet(chain, location, std::move(dbw_in)) {};

    ~CHDWallet()
    {
        Finalise();
    }

    int Finalise();
    int FreeExtKeyMaps();

    static void AddOptions();

    bool Initialise();

    bool ProcessStakingSettings(std::string &sError);
    bool ProcessWalletSettings(std::string &sError);

    /* Returns true if HD is enabled, and default account set */
    bool IsHDEnabled() const override;

    /** Unsets a single wallet flag, returns false on fail */
    bool UnsetWalletFlagRV(CHDWalletDB *pwdb, uint64_t flag);

    bool DumpJson(UniValue &rv, std::string &sError);
    bool LoadJson(const UniValue &inj, std::string &sError);

    bool LoadAddressBook(CHDWalletDB *pwdb);

    bool LoadVoteTokens(CHDWalletDB *pwdb);
    bool GetVote(int nHeight, uint32_t &token);

    bool LoadTxRecords(CHDWalletDB *pwdb);

    bool IsLocked() const override;
    bool EncryptWallet(const SecureString &strWalletPassphrase) override;
    bool Lock() override;
    bool Unlock(const SecureString &strWalletPassphrase, bool accept_no_keys = false) override;


    isminetype HaveAddress(const CTxDestination &dest);
    isminetype HaveKey(const CKeyID &address, const CEKAKey *&pak, const CEKASCKey *&pasc, CExtKeyAccount *&pa) const;
    isminetype IsMine(const CKeyID &address) const override;
    bool HaveKey(const CKeyID &address) const override;

    isminetype HaveExtKey(const CKeyID &keyID) const;
    bool GetExtKey(const CKeyID &keyID, CStoredExtKey &extKeyOut) const;

    bool HaveTransaction(const uint256 &txhash) const EXCLUSIVE_LOCKS_REQUIRED(cs_wallet);

    int GetKey(const CKeyID &address, CKey &keyOut, CExtKeyAccount *&pa, CEKAKey &ak, CKeyID &idStealth) const;
    bool GetKey(const CKeyID &address, CKey &keyOut) const override;

    bool GetPubKey(const CKeyID &address, CPubKey &pkOut) const override;

    bool GetKeyFromPool(CPubKey &key, bool internal = false) override;

    isminetype HaveStealthAddress(const CStealthAddress &sxAddr) const EXCLUSIVE_LOCKS_REQUIRED(cs_wallet);
    isminetype IsMine(const CStealthAddress &sxAddr, const CExtKeyAccount *&pa, const CEKAStealthKey *&pask) const EXCLUSIVE_LOCKS_REQUIRED(cs_wallet);
    bool GetStealthAddressScanKey(CStealthAddress &sxAddr) const;
    bool GetStealthAddressSpendKey(CStealthAddress &sxAddr, CKey &key) const;

    bool ImportStealthAddress(const CStealthAddress &sxAddr, const CKey &skSpend);

    DBErrors LoadWallet(bool& fFirstRunRet) override;

    bool AddressBookChangedNotify(const CTxDestination &address, ChangeType nMode);
    bool SetAddressBook(CHDWalletDB *pwdb, const CTxDestination &address, const std::string &strName,
        const std::string &purpose, const std::vector<uint32_t> &vPath, bool fNotifyChanged=true, bool fBech32=false);
    bool SetAddressBook(const CTxDestination &address, const std::string &strName, const std::string &strPurpose, bool fBech32=false) override;
    bool DelAddressBook(const CTxDestination &address) override;


    int64_t GetOldestActiveAccountTime();
    int64_t CountActiveAccountKeys();

    std::set< std::set<CTxDestination> > GetAddressGroupings() override EXCLUSIVE_LOCKS_REQUIRED(cs_wallet);
    std::map<CTxDestination, CAmount> GetAddressBalances(interfaces::Chain::Lock& locked_chain) override;

    isminetype IsMine(const CTxIn& txin) const override;
    isminetype IsMine(const CScript &scriptPubKey, CKeyID &keyID,
        const CEKAKey *&pak, const CEKASCKey *&pasc, CExtKeyAccount *&pa, bool &isInvalid, SigVersion = SigVersion::BASE) const;

    isminetype IsMine(const CTxOutBase *txout) const override;
    bool IsMine(const CTransaction& tx) const override;
    bool IsFromMe(const CTransaction& tx) const override;


    /**
     * Returns amount of debit if the input matches the
     * filter, otherwise returns 0
     */
    CAmount GetDebit(const CTxIn& txin, const isminefilter& filter) const override;
    CAmount GetDebit(const CTransaction& tx, const isminefilter& filter) const override;
    CAmount GetDebit(CHDWalletDB *pwdb, const CTransactionRecord &rtx, const isminefilter& filter) const;

    /** Returns whether all of the inputs match the filter */
    bool IsAllFromMe(const CTransaction& tx, const isminefilter& filter) const override;

    CAmount GetCredit(const CTxOutBase *txout, const isminefilter &filter) const override;
    CAmount GetCredit(const CTransaction &tx, const isminefilter &filter) const override;

    void GetCredit(const CTransaction &tx, CAmount &nSpendable, CAmount &nWatchOnly) const;

    CAmount GetOutputValue(const COutPoint &op, bool fAllowTXIndex) const EXCLUSIVE_LOCKS_REQUIRED(cs_wallet);
    CAmount GetOwnedOutputValue(const COutPoint &op, isminefilter filter) const EXCLUSIVE_LOCKS_REQUIRED(cs_wallet);

    int GetDepthInMainChain(interfaces::Chain::Lock& locked_chain, const uint256 &blockhash, int nIndex = 0) const;
    bool InMempool(const uint256 &hash) const;
    bool IsTrusted(interfaces::Chain::Lock& locked_chain, const uint256 &hash, const uint256 &blockhash, int nIndex = 0, int *depth_out = nullptr) const;

    CAmount GetBalance(const isminefilter& filter=ISMINE_SPENDABLE, const int min_depth=0) const override;
    CAmount GetSpendableBalance() const;        // Includes watch_only_cs balance
    CAmount GetUnconfirmedBalance() const override;
    CAmount GetBlindBalance();
    CAmount GetAnonBalance();
    CAmount GetStaked();
    CAmount GetLegacyBalance(const isminefilter& filter, int minDepth) const override;

    bool GetBalances(CHDWalletBalances &bal);
    CAmount GetAvailableBalance(const CCoinControl* coinControl = nullptr) const override;
    CAmount GetAvailableAnonBalance(const CCoinControl* coinControl = nullptr) const;
    CAmount GetAvailableBlindBalance(const CCoinControl* coinControl = nullptr) const;


    bool IsChange(const CTxOutBase *txout) const override;

    int GetChangeAddress(CPubKey &pk);

    void AddOutputRecordMetaData(CTransactionRecord &rtx, std::vector<CTempRecipient> &vecSend);
    int ExpandTempRecipients(std::vector<CTempRecipient> &vecSend, CStoredExtKey *pc, std::string &sError) EXCLUSIVE_LOCKS_REQUIRED(cs_main);

    int AddCTData(CTxOutBase *txout, CTempRecipient &r, std::string &sError) EXCLUSIVE_LOCKS_REQUIRED(cs_main, cs_wallet);

    bool SetChangeDest(const CCoinControl *coinControl, CTempRecipient &r, std::string &sError);

    /** Update wallet after successful transaction */
    int PostProcessTempRecipients(std::vector<CTempRecipient> &vecSend);

    int AddStandardInputs(CWalletTx &wtx, CTransactionRecord &rtx,
        std::vector<CTempRecipient> &vecSend,
        CExtKeyAccount *sea, CStoredExtKey *pc,
        bool sign, CAmount &nFeeRet, const CCoinControl *coinControl, std::string &sError) EXCLUSIVE_LOCKS_REQUIRED(cs_main);
    int AddStandardInputs(CWalletTx &wtx, CTransactionRecord &rtx,
        std::vector<CTempRecipient> &vecSend, bool sign, CAmount &nFeeRet, const CCoinControl *coinControl, std::string &sError) EXCLUSIVE_LOCKS_REQUIRED(cs_main);

    int AddBlindedInputs(CWalletTx &wtx, CTransactionRecord &rtx,
        std::vector<CTempRecipient> &vecSend,
        CExtKeyAccount *sea, CStoredExtKey *pc,
        bool sign, CAmount &nFeeRet, const CCoinControl *coinControl, std::string &sError) EXCLUSIVE_LOCKS_REQUIRED(cs_main);
    int AddBlindedInputs(CWalletTx &wtx, CTransactionRecord &rtx,
        std::vector<CTempRecipient> &vecSend, bool sign, CAmount &nFeeRet, const CCoinControl *coinControl, std::string &sError) EXCLUSIVE_LOCKS_REQUIRED(cs_main);


    int PlaceRealOutputs(std::vector<std::vector<int64_t> > &vMI, size_t &nSecretColumn, size_t nRingSize, std::set<int64_t> &setHave,
        const std::vector<std::pair<MapRecords_t::const_iterator,unsigned int> > &vCoins, std::vector<uint8_t> &vInputBlinds, std::string &sError);
    int PickHidingOutputs(std::vector<std::vector<int64_t> > &vMI, size_t nSecretColumn, size_t nRingSize, std::set<int64_t> &setHave,
        std::string &sError);

    int AddAnonInputs(CWalletTx &wtx, CTransactionRecord &rtx,
        std::vector<CTempRecipient> &vecSend,
        CExtKeyAccount *sea, CStoredExtKey *pc,
        bool sign, size_t nRingSize, size_t nInputsPerSig, CAmount &nFeeRet, const CCoinControl *coinControl, std::string &sError) EXCLUSIVE_LOCKS_REQUIRED(cs_main);
    int AddAnonInputs(CWalletTx &wtx, CTransactionRecord &rtx,
        std::vector<CTempRecipient> &vecSend, bool sign, size_t nRingSize, size_t nInputsPerSig, CAmount &nFeeRet, const CCoinControl *coinControl, std::string &sError) EXCLUSIVE_LOCKS_REQUIRED(cs_main);


    void ClearCachedBalances() override;
    void LoadToWallet(const CWalletTx& wtxIn) override EXCLUSIVE_LOCKS_REQUIRED(cs_wallet);
    void LoadToWallet(const uint256 &hash, const CTransactionRecord &rtx) EXCLUSIVE_LOCKS_REQUIRED(cs_wallet);

    /** Remove txn from mapwallet and TxSpends */
    void RemoveFromTxSpends(const uint256 &hash, const CTransactionRef pt) EXCLUSIVE_LOCKS_REQUIRED(cs_wallet);
    int UnloadTransaction(const uint256 &hash) EXCLUSIVE_LOCKS_REQUIRED(cs_wallet);

    int GetDefaultConfidentialChain(CHDWalletDB *pwdb, CExtKeyAccount *&sea, CStoredExtKey *&pc);

    int MakeDefaultAccount();

    int ExtKeyNew32(CExtKey &out);
    int ExtKeyNew32(CExtKey &out, const char *sPassPhrase, int32_t nHash, const char *sSeed);
    int ExtKeyNew32(CExtKey &out, uint8_t *data, uint32_t lenData);

    int ExtKeyImportLoose(CHDWalletDB *pwdb, CStoredExtKey &sekIn, CKeyID &idDerived, bool fBip44, bool fSaveBip44);
    int ExtKeyImportAccount(CHDWalletDB *pwdb, CStoredExtKey &sekIn, int64_t nCreatedAt, const std::string &sLabel);

    int ExtKeySetMaster(CHDWalletDB *pwdb, CKeyID &idMaster); // set master to existing key, remove master key tag from old key if exists
    int ExtKeyNewMaster(CHDWalletDB *pwdb, CKeyID &idMaster, bool fAutoGenerated = false); // make and save new root key to wallet

    int ExtKeyCreateAccount(CStoredExtKey *ekAccount, CKeyID &idMaster, CExtKeyAccount &ekaOut, const std::string &sLabel);
    int ExtKeyDeriveNewAccount(CHDWalletDB *pwdb, CExtKeyAccount *sea, const std::string &sLabel, const std::string &sPath=""); // derive a new account from the master key and save to wallet
    int ExtKeySetDefaultAccount(CHDWalletDB *pwdb, CKeyID &idNewDefault);

    int ExtKeyEncrypt(CStoredExtKey *sek, const CKeyingMaterial &vMKey, bool fLockKey);
    int ExtKeyEncrypt(CExtKeyAccount *sea, const CKeyingMaterial &vMKey, bool fLockKey);
    int ExtKeyEncryptAll(CHDWalletDB *pwdb, const CKeyingMaterial &vMKey);
    int ExtKeyLock();

    int ExtKeyUnlock(CExtKeyAccount *sea);
    int ExtKeyUnlock(CExtKeyAccount *sea, const CKeyingMaterial &vMKey);
    int ExtKeyUnlock(CStoredExtKey *sek);
    int ExtKeyUnlock(CStoredExtKey *sek, const CKeyingMaterial &vMKey);
    int ExtKeyUnlock(const CKeyingMaterial &vMKey) override;

    int ExtKeyCreateInitial(CHDWalletDB *pwdb);
    int ExtKeyLoadMaster();

    int ExtKeyLoadAccountKeys(CHDWalletDB *pwdb, CExtKeyAccount *sea);
    int ExtKeyLoadAccount(CHDWalletDB *pwdb, const CKeyID &idAccount);
    int ExtKeyLoadAccounts();

    int ExtKeySaveAccountToDB(CHDWalletDB *pwdb, const CKeyID &idAccount, CExtKeyAccount *sea);
    int ExtKeyAddAccountToMaps(const CKeyID &idAccount, CExtKeyAccount *sea, bool fAddToLookAhead = true);
    int ExtKeyRemoveAccountFromMapsAndFree(CExtKeyAccount *sea);
    int ExtKeyRemoveAccountFromMapsAndFree(const CKeyID &idAccount);
    int ExtKeyLoadAccountPacks();
    int PrepareLookahead();

    int ExtKeyAppendToPack(CHDWalletDB *pwdb, CExtKeyAccount *sea, const CKeyID &idKey, const CEKAKey &ak, bool &fUpdateAcc) const;
    int ExtKeyAppendToPack(CHDWalletDB *pwdb, CExtKeyAccount *sea, const CKeyID &idKey, const CEKASCKey &asck, bool &fUpdateAcc) const;

    int ExtKeySaveKey(CHDWalletDB *pwdb, CExtKeyAccount *sea, const CKeyID &keyId, const CEKAKey &ak) const;
    int ExtKeySaveKey(CExtKeyAccount *sea, const CKeyID &keyId, const CEKAKey &ak) const;

    int ExtKeySaveKey(CHDWalletDB *pwdb, CExtKeyAccount *sea, const CKeyID &keyId, const CEKASCKey &asck) const;
    int ExtKeySaveKey(CExtKeyAccount *sea, const CKeyID &keyId, const CEKASCKey &asck) const;

    int ExtKeyUpdateStealthAddress(CHDWalletDB *pwdb, CExtKeyAccount *sea, CKeyID &sxId, std::string &sLabel);

    /**
     * Create an index db record for idKey
     */
    int ExtKeyNewIndex(CHDWalletDB *pwdb, const CKeyID &idKey, uint32_t &index);
    int ExtKeyGetIndex(CHDWalletDB *pwdb, CExtKeyAccount *sea, uint32_t &index, bool &fUpdate);
    int ExtKeyGetIndex(CExtKeyAccount *sea, uint32_t &index);

    int NewKeyFromAccount(CHDWalletDB *pwdb, const CKeyID &idAccount, CPubKey &pkOut, bool fInternal, bool fHardened, bool f256bit=false, bool fBech32=false, const char *plabel=nullptr);
    int NewKeyFromAccount(CPubKey &pkOut, bool fInternal=false, bool fHardened=false, bool f256bit=false, bool fBech32=false, const char *plabel=nullptr); // wrapper - use default account

    int NewStealthKeyFromAccount(CHDWalletDB *pwdb, const CKeyID &idAccount, std::string &sLabel, CEKAStealthKey &akStealthOut, uint32_t nPrefixBits, const char *pPrefix, bool fBech32=false);
    int NewStealthKeyFromAccount(std::string &sLabel, CEKAStealthKey &akStealthOut, uint32_t nPrefixBits, const char *pPrefix, bool fBech32=false); // wrapper - use default account

    int InitAccountStealthV2Chains(CHDWalletDB *pwdb, CExtKeyAccount *sea);
    int SaveStealthAddress(CHDWalletDB *pwdb, CExtKeyAccount *sea, const CEKAStealthKey &akStealth, bool fBech32);
    int NewStealthKeyV2FromAccount(CHDWalletDB *pwdb, const CKeyID &idAccount, std::string &sLabel, CEKAStealthKey &akStealthOut, uint32_t nPrefixBits, const char *pPrefix, bool fBech32=false);
    int NewStealthKeyV2FromAccount(std::string &sLabel, CEKAStealthKey &akStealthOut, uint32_t nPrefixBits, const char *pPrefix, bool fBech32=false); // wrapper - use default account

    int NewExtKeyFromAccount(CHDWalletDB *pwdb, const CKeyID &idAccount, std::string &sLabel, CStoredExtKey *sekOut, const char *plabel=nullptr, const uint32_t *childNo=nullptr, bool fHardened=false, bool fBech32=false);
    int NewExtKeyFromAccount(std::string &sLabel, CStoredExtKey *sekOut, const char *plabel=nullptr, const uint32_t *childNo=nullptr, bool fHardened=false, bool fBech32=false); // wrapper - use default account

    int ExtKeyGetDestination(const CExtKeyPair &ek, CPubKey &pkDest, uint32_t &nKey);
    int ExtKeyUpdateLooseKey(const CExtKeyPair &ek, uint32_t nKey, bool fAddToAddressBook) EXCLUSIVE_LOCKS_REQUIRED(cs_wallet);

    bool GetFullChainPath(const CExtKeyAccount *pa, size_t nChain, std::vector<uint32_t> &vPath) const;

    /**
     * Insert additional inputs into the transaction by
     * calling CreateTransaction();
     */
    bool FundTransaction(CMutableTransaction& tx, CAmount& nFeeRet, int& nChangePosInOut, std::string& strFailReason, bool lockUnspents, const std::set<int>& setSubtractFeeFromOutputs, CCoinControl) override;
    bool SignTransaction(CMutableTransaction& tx) override EXCLUSIVE_LOCKS_REQUIRED(cs_wallet);

    bool CreateTransaction(interfaces::Chain::Lock& locked_chain, const std::vector<CRecipient>& vecSend, CTransactionRef& tx, CReserveKey& reservekey, CAmount& nFeeRet, int& nChangePosInOut,
                           std::string& strFailReason, const CCoinControl& coin_control, bool sign = true) override;
    bool CreateTransaction(interfaces::Chain::Lock& locked_chain, std::vector<CTempRecipient>& vecSend, CTransactionRef& tx, CReserveKey& reservekey, CAmount& nFeeRet, int& nChangePosInOut,
                           std::string& strFailReason, const CCoinControl& coin_control, bool sign = true);
    bool CommitTransaction(CTransactionRef tx, mapValue_t mapValue, std::vector<std::pair<std::string, std::string>> orderForm, CReserveKey& reservekey, CConnman* connman, CValidationState& state) override;
    bool CommitTransaction(CWalletTx &wtxNew, CTransactionRecord &rtx,
        CReserveKey &reservekey, CConnman *connman, CValidationState &state);

    bool DummySignInput(CTxIn &tx_in, const CTxOut &txout, bool use_max_sig = false) const override;

    bool DummySignInput(CTxIn &tx_in, const CTxOutBaseRef &txout) const;
    bool DummySignTx(CMutableTransaction &txNew, const std::vector<CTxOutBaseRef> &txouts) const;

    int LoadStealthAddresses();
    int LoadMasterKeys();
    bool IndexStealthKey(CHDWalletDB *pwdb, uint160 &hash, const CStealthAddressIndexed &sxi, uint32_t &id);
    bool GetStealthKeyIndex(const CStealthAddressIndexed &sxi, uint32_t &id);
    bool UpdateStealthAddressIndex(const CKeyID &idK, const CStealthAddressIndexed &sxi, uint32_t &id); // Get stealth index or create new index if none found
    bool GetStealthByIndex(uint32_t sxId, CStealthAddress &sx) const;
    bool GetStealthLinked(const CKeyID &idK, CStealthAddress &sx) const;
    bool ProcessLockedStealthOutputs();
    bool ProcessLockedBlindedOutputs();
    bool CountRecords(std::string sPrefix, int64_t rv);
    bool ProcessStealthOutput(const CTxDestination &address,
        std::vector<uint8_t> &vchEphemPK, uint32_t prefix, bool fHavePrefix, CKey &sShared, bool fNeedShared=false);

    int CheckForStealthAndNarration(const CTxOutBase *pb, const CTxOutData *pdata, std::string &sNarr);
    bool FindStealthTransactions(const CTransaction &tx, mapValue_t &mapNarr);

    bool ScanForOwnedOutputs(const CTransaction &tx, size_t &nCT, size_t &nRingCT, mapValue_t &mapNarr);

    int UnloadSpent(const uint256 &wtxid, int depth, const uint256 &wtxid_from);
    void PostProcessUnloadSpent();

    using CWallet::AddToSpends;
    void AddToSpends(const uint256& wtxid) override EXCLUSIVE_LOCKS_REQUIRED(cs_wallet);
    bool AddToWalletIfInvolvingMe(const CTransactionRef& ptx, const uint256& block_hash, int posInBlock, bool fUpdate) override EXCLUSIVE_LOCKS_REQUIRED(cs_wallet);

    CWalletTx *GetTempWalletTx(const uint256& hash);

    const CWalletTx *GetWalletTx(const uint256& hash) const override;
    CWalletTx *GetWalletTx(const uint256& hash);

    int InsertTempTxn(const uint256 &txid, const CTransactionRecord *rtx) const;
    const CWalletTx *GetWalletOrTempTx(const uint256& hash, const CTransactionRecord *rtx) const;

    int OwnStandardOut(const CTxOutStandard *pout, const CTxOutData *pdata, COutputRecord &rout, bool &fUpdated);
    int OwnBlindOut(CHDWalletDB *pwdb, const uint256 &txhash, const CTxOutCT *pout, const CStoredExtKey *pc, uint32_t &nLastChild,
        COutputRecord &rout, CStoredTransaction &stx, bool &fUpdated);
    int OwnAnonOut(CHDWalletDB *pwdb, const uint256 &txhash, const CTxOutRingCT *pout, const CStoredExtKey *pc, uint32_t &nLastChild,
        COutputRecord &rout, CStoredTransaction &stx, bool &fUpdated);

    bool AddTxinToSpends(const CTxIn &txin, const uint256 &txhash);

    bool ProcessPlaceholder(CHDWalletDB *pwdb, const CTransaction &tx, CTransactionRecord &rtx);
    bool AddToRecord(CTransactionRecord &rtxIn, const CTransaction &tx,
        const uint256& block_hash, int posInBlock, bool fFlushOnClose=true);

    std::vector<uint256> ResendRecordTransactionsBefore(interfaces::Chain::Lock& locked_chain, int64_t nTime, CConnman *connman);
    void ResendWalletTransactions(int64_t nBestBlockTime, CConnman *connman) override EXCLUSIVE_LOCKS_REQUIRED(cs_main);

    /**
     * populate vCoins with vector of available COutputs.
     */
    void AvailableCoins(interfaces::Chain::Lock& locked_chain, std::vector<COutput>& vCoins, bool fOnlySafe=true, const CCoinControl *coinControl = nullptr, const CAmount& nMinimumAmount = 1, const CAmount& nMaximumAmount = MAX_MONEY, const CAmount& nMinimumSumAmount = MAX_MONEY, const uint64_t nMaximumCount = 0, const int nMinDepth = 0, const int nMaxDepth = 0x7FFFFFFF, bool fIncludeImmature=false) const override EXCLUSIVE_LOCKS_REQUIRED(cs_wallet);
    bool SelectCoins(const std::vector<COutput>& vAvailableCoins, const CAmount& nTargetValue, std::set<CInputCoin>& setCoinsRet, CAmount& nValueRet,
        const CCoinControl& coin_control, CoinSelectionParams& coin_selection_params, bool& bnb_used) const override EXCLUSIVE_LOCKS_REQUIRED(cs_wallet);

    void AvailableBlindedCoins(interfaces::Chain::Lock& locked_chain, std::vector<COutputR>& vCoins, bool fOnlySafe=true, const CCoinControl *coinControl = nullptr, const CAmount& nMinimumAmount = 1, const CAmount& nMaximumAmount = MAX_MONEY, const CAmount& nMinimumSumAmount = MAX_MONEY, const uint64_t& nMaximumCount = 0, const int& nMinDepth = 0, const int& nMaxDepth = 0x7FFFFFFF, bool fIncludeImmature=false) const EXCLUSIVE_LOCKS_REQUIRED(cs_wallet);
    bool SelectBlindedCoins(const std::vector<COutputR>& vAvailableCoins, const CAmount& nTargetValue, std::vector<std::pair<MapRecords_t::const_iterator,unsigned int> > &setCoinsRet, CAmount &nValueRet, const CCoinControl *coinControl = nullptr, bool random_selection = false) const EXCLUSIVE_LOCKS_REQUIRED(cs_wallet);

    void AvailableAnonCoins(interfaces::Chain::Lock& locked_chain, std::vector<COutputR> &vCoins, bool fOnlySafe=true, const CCoinControl *coinControl = nullptr, const CAmount& nMinimumAmount = 1, const CAmount& nMaximumAmount = MAX_MONEY, const CAmount& nMinimumSumAmount = MAX_MONEY, const uint64_t& nMaximumCount = 0, const int& nMinDepth = 0, const int& nMaxDepth = 0x7FFFFFFF, bool fIncludeImmature=false) const EXCLUSIVE_LOCKS_REQUIRED(cs_wallet);

    /**
     * Return list of available coins and locked coins grouped by non-change output address.
     */
    const CTxOutBase* FindNonChangeParentOutput(const CTransaction& tx, int output) const EXCLUSIVE_LOCKS_REQUIRED(cs_wallet);
    std::map<CTxDestination, std::vector<COutput>> ListCoins(interfaces::Chain::Lock& locked_chain) const override EXCLUSIVE_LOCKS_REQUIRED(cs_wallet);
    std::map<CTxDestination, std::vector<COutputR>> ListCoins(interfaces::Chain::Lock& locked_chain, OutputTypes nType) const EXCLUSIVE_LOCKS_REQUIRED(cs_wallet);

    bool SelectCoinsMinConf(const CAmount& nTargetValue, const CoinEligibilityFilter& eligibility_filter, std::vector<COutputR> vCoins, std::vector<std::pair<MapRecords_t::const_iterator,unsigned int> > &setCoinsRet, CAmount &nValueRet) const;

    bool IsSpent(interfaces::Chain::Lock& locked_chain, const uint256& hash, unsigned int n) const override EXCLUSIVE_LOCKS_REQUIRED(cs_wallet);

    std::set<uint256> GetConflicts(const uint256 &txid) const;

    /* Mark a transaction (and it in-wallet descendants) as abandoned so its inputs may be respent. */
    bool AbandonTransaction(interfaces::Chain::Lock& locked_chain, const uint256 &hashTx) override;

    void MarkConflicted(const uint256 &hashBlock, const uint256 &hashTx) override;
    void SyncMetaData(std::pair<TxSpends::iterator, TxSpends::iterator>) override EXCLUSIVE_LOCKS_REQUIRED(cs_wallet);

    bool GetSetting(const std::string &setting, UniValue &json);
    bool SetSetting(const std::string &setting, const UniValue &json);
    bool EraseSetting(const std::string &setting);

    /* Return a prevout if it exists in the wallet. */
    bool GetPrevout(const COutPoint &prevout, CTxOutBaseRef &txout) EXCLUSIVE_LOCKS_REQUIRED(cs_wallet);

    size_t CountColdstakeOutputs();

    /* Return a script for a simple address type (normal/extended) */
    bool GetScriptForAddress(CScript &script, const CBitcoinAddress &addr, bool fUpdate = false, std::vector<uint8_t> *vData = NULL, bool allow_stakeonly = false);

    bool SetReserveBalance(CAmount nNewReserveBalance);
    uint64_t GetStakeWeight() const;
    void AvailableCoinsForStaking(std::vector<COutput> &vCoins, int64_t nTime, int nHeight) const;
    bool SelectCoinsForStaking(int64_t nTargetValue, int64_t nTime, int nHeight, std::set<std::pair<const CWalletTx*,unsigned int> >& setCoinsRet, int64_t& nValueRet) const;
    bool CreateCoinStake(unsigned int nBits, int64_t nTime, int nBlockHeight, int64_t nFees, CMutableTransaction &txNew, CKey &key);
    bool SignBlock(CBlockTemplate *pblocktemplate, int nHeight, int64_t nSearchTime);

    boost::signals2::signal<void (CAmount nReservedBalance)> NotifyReservedBalanceChanged;

    size_t CountTxSpends() EXCLUSIVE_LOCKS_REQUIRED(cs_wallet) { return mapTxSpends.size(); };

    int64_t nLastCoinStakeSearchTime = 0;
    uint32_t nStealth, nFoundStealth; // for reporting, zero before use
    int64_t nReserveBalance = 0;
    size_t nStakeThread = 9999999; // unset

    mutable int m_greatest_txn_depth = 0; // depth of most deep txn
    //mutable int m_least_txn_depth = 0; // depth of least deep txn
    mutable bool m_have_spendable_balance_cached = false;
    mutable CAmount m_spendable_balance_cached = 0;

    enum eStakingState {
        NOT_STAKING = 0,
        IS_STAKING = 1,
        NOT_STAKING_BALANCE = -1,
        NOT_STAKING_DEPTH = -2,
        NOT_STAKING_LOCKED = -3,
        NOT_STAKING_LIMITED = -4,
        NOT_STAKING_DISABLED = -5,
    };
    std::atomic<eStakingState> m_is_staking {NOT_STAKING};

    std::set<CStealthAddress> stealthAddresses;

    CStoredExtKey *pEKMaster = nullptr;
    CKeyID idDefaultAccount;
    ExtKeyAccountMap mapExtAccounts;
    ExtKeyMap mapExtKeys;

    mutable MapWallet_t mapTempWallet;

    MapRecords_t mapRecords;
    RtxOrdered_t rtxOrdered;
    mutable MapRecords_t mapTempRecords; // Hack for sending unmined inputs through fundrawtransactionfrom

    std::vector<CVoteToken> vVoteTokens;

    // Staking Settings
    std::atomic<bool> fStakingEnabled{false};
    CAmount nStakeCombineThreshold;
    CAmount nStakeSplitThreshold;
    size_t nMaxStakeCombine = 3;
    int nWalletDevFundCedePercent;
    CBitcoinAddress rewardAddress;
    int nStakeLimitHeight = 0; // for regtest, don't stake above nStakeLimitHeight

    mutable bool m_have_cached_stakeable_coins = false;
    mutable std::vector<COutput> m_cached_stakeable_coins;

    bool fUnlockForStakingOnly = false; // Use coldstaking instead

    int64_t nRCTOutSelectionGroup1 = 5000;
    int64_t nRCTOutSelectionGroup2 = 50000;
    size_t prefer_max_num_anon_inputs = 5; // if > x anon inputs are randomly selected attempt to reduce
    int m_mixin_selection_mode = 1;

    int m_collapse_spent_mode = 0;
    int m_min_collapse_depth = 3;
    std::map<uint256, std::set<uint256> > mapTxCollapsedSpends;
    std::set<uint256> m_collapsed_txns;
    std::set<COutPoint> m_collapsed_txn_inputs;

    int64_t m_smsg_fee_rate_target = 0;
    uint32_t m_smsg_difficulty_target = 0; // 0 = auto

private:
    void ParseAddressForMetaData(const CTxDestination &addr, COutputRecord &rec);

    template<typename... Params>
    bool werror(std::string fmt, Params... parameters) const {
        return error(("%s " + fmt).c_str(), GetDisplayName(), parameters...);
    }
    template<typename... Params>
    int werrorN(int rv, std::string fmt, Params... parameters) const {
        return errorN(rv, ("%s " + fmt).c_str(), GetDisplayName(), parameters...);
    }
    template<typename... Params>
    int wserrorN(int rv, std::string &s, const char *func, std::string fmt, Params... parameters) const {
        return errorN(rv, s, func, ("%s " + fmt).c_str(), GetDisplayName(), parameters...);
    }
};


class LoopExtKeyCallback
{
public:
    CHDWallet *pwallet = nullptr;

    // NOTE: the key and account instances passed to Process are temporary
    virtual int ProcessKey(CKeyID &id, CStoredExtKey &sek) {return 1;};
    virtual int ProcessAccount(CKeyID &id, CExtKeyAccount &sek) {return 1;};
};

int LoopExtKeysInDB(CHDWallet *pwallet, bool fInactive, bool fInAccount, LoopExtKeyCallback &callback);
int LoopExtAccountsInDB(CHDWallet *pwallet, bool fInactive, LoopExtKeyCallback &callback);

bool CheckOutputValue(const CTempRecipient &r, const CTxOutBase *txbout, CAmount nFeeRet, std::string sError);
int CreateOutput(OUTPUT_PTR<CTxOutBase> &txbout, CTempRecipient &r, std::string &sError);
void ExtractNarration(const uint256 &nonce, const std::vector<uint8_t> &vData, std::string &sNarr);

// Calculate the size of the transaction assuming all signatures are max size
// Use DummySignatureCreator, which inserts 72 byte signatures everywhere.
// NOTE: this requires that all inputs must be in mapWallet (eg the tx should
// be IsAllFromMe).
int64_t CalculateMaximumSignedTxSize(const CTransaction &tx, const CHDWallet *wallet) EXCLUSIVE_LOCKS_REQUIRED(wallet->cs_wallet);
int64_t CalculateMaximumSignedTxSize(const CTransaction &tx, const CHDWallet *wallet, const std::vector<CTxOutBaseRef>& txouts);

void RestartStakingThreads();

bool IsAphoryWallet(const CKeyStore *win);
CHDWallet *GetAphoryWallet(CKeyStore *win);
const CHDWallet *GetAphoryWallet(const CKeyStore *win);


#endif // APHORY_WALLET_HDWALLET_H

