// Copyright (c) 2017-2019 The Particl Core developers
// Copyright (c) 2019 The Aphory Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef APHORY_POS_MINER_H
#define APHORY_POS_MINER_H

#include <thread>
#include <condition_variable>
#include <atomic>
#include <vector>
#include <string>

class CBlockTemplate;
class CHDWallet;
class CWallet;
class CBlock;

// enable this to generate airdrop hashes
// #define GENERATE_AIRDROP_HASHES

class StakeThread
{
public:
    void condWaitFor(int ms);

    StakeThread() {};
    std::thread thread;
    std::condition_variable condMinerProc;
    std::mutex mtxMinerProc;
    std::string sName;
    bool fWakeMinerProc = false;
};

extern std::vector<StakeThread*> vStakeThreads;

extern std::atomic<bool> fIsStaking;

extern int nMinStakeInterval;
extern int nMinerSleep;

double GetPoSKernelPS();

#ifdef GENERATE_AIRDROP_HASHES
void GenerateAirdropHashes();
#endif
bool ImportOutputs(CBlockTemplate *pblocktemplate, int nHeight, bool fGenerateHashFile);

bool CheckStake(CBlock *pblock);

void StartThreadStakeMiner();
void StopThreadStakeMiner();
void WakeThreadStakeMiner(CHDWallet *pwallet);
bool ThreadStakeMinerStopped(); // replace interruption_point

void ThreadStakeMiner(size_t nThreadID, std::vector<std::shared_ptr<CWallet>> &vpwallets, size_t nStart, size_t nEnd);

#endif // APHORY_POS_MINER_H

