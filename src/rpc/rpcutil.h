// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2017 The Particl Core developers
// Copyright (c) 2019 The Aphory Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef APHORY_RPC_RPCUTIL_H
#define APHORY_RPC_RPCUTIL_H

#include <univalue.h>
#include <string>

class JSONRPCRequest;

void CallRPCVoid(std::string args, std::string wallet="");
void CallRPCVoidRv(std::string args, std::string wallet, bool *passed, UniValue *rv);
UniValue CallRPC(std::string args, std::string wallet="");

void AddUri(JSONRPCRequest &request, std::string wallet);
void CallRPC(UniValue &rv, const JSONRPCRequest &request);

#endif // APHORY_RPC_RPCUTIL_H

