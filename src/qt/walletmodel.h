// Copyright (c) 2011-2019 The Bitcoin Core developers
// Copyright (c) 2019 The Aphory Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_WALLETMODEL_H
#define BITCOIN_QT_WALLETMODEL_H

#include <key.h>
#include <serialize.h>
#include <script/standard.h>

#if defined(HAVE_CONFIG_H)
#include <config/bitcoin-config.h>
#endif

#ifdef ENABLE_BIP70
#include <qt/paymentrequestplus.h>
#endif
#include <qt/walletmodeltransaction.h>
#include <amount.h>

#include <interfaces/wallet.h>
#include <support/allocators/secure.h>


#include <map>
#include <vector>

#include <QObject>
#include <QMessageBox>

enum class OutputType;

class AddressTableModel;
class OptionsModel;
class PlatformStyle;
class RecentRequestsTableModel;
class TransactionTableModel;
class WalletModelTransaction;

class CCoinControl;
class CKeyID;
class COutPoint;
class COutput;
class CCoinControlEntry;
class CPubKey;
class uint256;
class CHDWallet;
class UniValue;

namespace interfaces {
class Node;
} // namespace interfaces

QT_BEGIN_NAMESPACE
class QTimer;
QT_END_NAMESPACE

class SendCoinsRecipient
{
public:
    explicit SendCoinsRecipient() : amount(0), fSubtractFeeFromAmount(false), nVersion(SendCoinsRecipient::CURRENT_VERSION) { }
    explicit SendCoinsRecipient(const QString &addr, const QString &_label, const CAmount& _amount, const QString &_message):
        address(addr), label(_label), amount(_amount), message(_message), fSubtractFeeFromAmount(false), nVersion(SendCoinsRecipient::CURRENT_VERSION) {}

    // If from an unauthenticated payment request, this is used for storing
    // the addresses, e.g. address-A<br />address-B<br />address-C.
    // Info: As we don't need to process addresses in here when using
    // payment requests, we can abuse it for displaying an address list.
    // Todo: This is a hack, should be replaced with a cleaner solution!
    QString address;
    QString label;
    CAmount amount;
    // If from a payment request, this is used for storing the memo
    QString message;
    QString narration;

#ifdef ENABLE_BIP70
    // If from a payment request, paymentRequest.IsInitialized() will be true
    PaymentRequestPlus paymentRequest;
#else
    // If building with BIP70 is disabled, keep the payment request around as
    // serialized string to ensure load/store is lossless
    std::string sPaymentRequest;
#endif
    // Empty if no authentication or invalid signature/cert/etc.
    QString authenticatedMerchant;

    bool fSubtractFeeFromAmount; // memory only

    static const int CURRENT_VERSION = 1;
    int nVersion;

    bool m_coldstake = false;
    QString stake_address, spend_address;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        std::string sAddress = address.toStdString();
        std::string sLabel = label.toStdString();
        std::string sMessage = message.toStdString();
#ifdef ENABLE_BIP70
        std::string sPaymentRequest;
        if (!ser_action.ForRead() && paymentRequest.IsInitialized())
            paymentRequest.SerializeToString(&sPaymentRequest);
#endif
        std::string sAuthenticatedMerchant = authenticatedMerchant.toStdString();

        READWRITE(this->nVersion);
        READWRITE(sAddress);
        READWRITE(sLabel);
        READWRITE(amount);
        READWRITE(sMessage);
        READWRITE(sPaymentRequest);
        READWRITE(sAuthenticatedMerchant);

        if (ser_action.ForRead())
        {
            address = QString::fromStdString(sAddress);
            label = QString::fromStdString(sLabel);
            message = QString::fromStdString(sMessage);
#ifdef ENABLE_BIP70
            if (!sPaymentRequest.empty())
                paymentRequest.parse(QByteArray::fromRawData(sPaymentRequest.data(), sPaymentRequest.size()));
#endif
            authenticatedMerchant = QString::fromStdString(sAuthenticatedMerchant);
        }
    }
};

/** Interface to Bitcoin wallet from Qt view code. */
class WalletModel : public QObject
{
    Q_OBJECT

public:
    explicit WalletModel(std::unique_ptr<interfaces::Wallet> wallet, interfaces::Node& node, const PlatformStyle *platformStyle, OptionsModel *optionsModel, QObject *parent = nullptr);
    ~WalletModel();

    enum StatusCode // Returned by sendCoins
    {
        OK,
        InvalidAmount,
        InvalidAddress,
        AmountExceedsBalance,
        AmountWithFeeExceedsBalance,
        DuplicateAddress,
        TransactionCreationFailed, // Error returned when wallet is still locked
        TransactionCommitFailed,
        AbsurdFee,
        PaymentRequestExpired
    };

    enum EncryptionStatus
    {
        Unencrypted,  // !wallet->IsCrypted()
        Locked,       // wallet->IsCrypted() && wallet->IsLocked()
        Unlocked,     // wallet->IsCrypted() && !wallet->IsLocked()
        UnlockedForStaking
    };

    OptionsModel *getOptionsModel();
    AddressTableModel *getAddressTableModel();
    TransactionTableModel *getTransactionTableModel();
    RecentRequestsTableModel *getRecentRequestsTableModel();

    EncryptionStatus getEncryptionStatus() const;

    // Check address for validity
    bool validateAddress(const QString &address, bool allow_stakeonly=false);

    // Return status record for SendCoins, contains error id + information
    struct SendCoinsReturn
    {
        SendCoinsReturn(StatusCode _status = OK, QString _reasonCommitFailed = "")
            : status(_status),
              reasonCommitFailed(_reasonCommitFailed)
        {
        }
        StatusCode status;
        QString reasonCommitFailed;
    };

    // prepare transaction for getting txfee before sending coins
    SendCoinsReturn prepareTransaction(WalletModelTransaction &transaction, const CCoinControl& coinControl);

    // Send coins to a list of recipients
    SendCoinsReturn sendCoins(WalletModelTransaction &transaction);

    // Wallet encryption
    bool setWalletEncrypted(bool encrypted, const SecureString &passphrase);
    // Passphrase only needed when unlocking
    bool setWalletLocked(bool locked, const SecureString &passPhrase=SecureString(), bool stakingOnly=false);
    bool setUnlockedForStaking();
    bool changePassphrase(const SecureString &oldPass, const SecureString &newPass);

    // RAI object for unlocking wallet, returned by requestUnlock()
    class UnlockContext
    {
    public:
        UnlockContext(WalletModel *wallet, bool valid, bool relock, bool was_unlocked_for_staking);
        ~UnlockContext();

        bool isValid() const { return valid; }

        // Copy operator and constructor transfer the context
        UnlockContext(const UnlockContext& obj) { CopyFrom(obj); }
        UnlockContext& operator=(const UnlockContext& rhs) { CopyFrom(rhs); return *this; }
    private:
        WalletModel *wallet;
        bool valid;
        mutable bool relock; // mutable, as it can be set to false by copying
        bool was_unlocked_for_staking;

        void CopyFrom(const UnlockContext& rhs);
    };

    UnlockContext requestUnlock();


    void loadReceiveRequests(std::vector<std::string>& vReceiveRequests);
    bool saveReceiveRequest(const std::string &sAddress, const int64_t nId, const std::string &sRequest);

    bool bumpFee(uint256 hash, uint256& new_hash);

    static bool isWalletEnabled();
    bool privateKeysDisabled() const;
    bool canGetAddresses() const;

    void lockWallet();
    interfaces::Node& node() const { return m_node; }
    interfaces::Wallet& wallet() const { return *m_wallet; }

    QString getWalletName() const;
    QString getDisplayName() const;

    bool isMultiwallet();

    AddressTableModel* getAddressTableModel() const { return addressTableModel; }

    bool tryCallRpc(const QString &sCommand, UniValue &rv, bool returnError=false) const;
    void warningBox(QString heading, QString msg) const;

private:
    std::unique_ptr<interfaces::Wallet> m_wallet;
    std::unique_ptr<interfaces::Handler> m_handler_unload;
    std::unique_ptr<interfaces::Handler> m_handler_status_changed;
    std::unique_ptr<interfaces::Handler> m_handler_address_book_changed;
    std::unique_ptr<interfaces::Handler> m_handler_transaction_changed;
    std::unique_ptr<interfaces::Handler> m_handler_show_progress;
    std::unique_ptr<interfaces::Handler> m_handler_watch_only_changed;
    std::unique_ptr<interfaces::Handler> m_handler_can_get_addrs_changed;
    interfaces::Node& m_node;

    std::unique_ptr<interfaces::Handler> m_handler_reserved_balance_changed;

    bool fHaveWatchOnly;
    bool fForceCheckBalanceChanged{false};

    // Wallet has an options model for wallet-specific options
    // (transaction fee, for example)
    OptionsModel *optionsModel;

    AddressTableModel *addressTableModel;
    TransactionTableModel *transactionTableModel;
    RecentRequestsTableModel *recentRequestsTableModel;

    // Cache some values to be able to detect changes
    interfaces::WalletBalances m_cached_balances;
    EncryptionStatus cachedEncryptionStatus;
    int cachedNumBlocks;

    QTimer *pollTimer;

    void subscribeToCoreSignals();
    void unsubscribeFromCoreSignals();

    void checkBalanceChanged(const interfaces::WalletBalances& new_balances);

Q_SIGNALS:
    // Signal that balance in wallet changed
    void balanceChanged(const interfaces::WalletBalances& balances);

    // Encryption status of wallet changed
    void encryptionStatusChanged();

    // Signal emitted when wallet needs to be unlocked
    // It is valid behaviour for listeners to keep the wallet locked after this signal;
    // this means that the unlocking failed or was cancelled.
    void requireUnlock();

    // Fired when a message should be reported to the user
    void message(const QString &title, const QString &message, unsigned int style) const;

    // Coins sent: from wallet, to recipient, in (serialized) transaction:
    void coinsSent(WalletModel* wallet, SendCoinsRecipient recipient, QByteArray transaction);

    // Show progress dialog e.g. for rescan
    void showProgress(const QString &title, int nProgress);

    // Watch-only address added
    void notifyWatchonlyChanged(bool fHaveWatchonly);

    // Signal that wallet is about to be removed
    void unload();

    // Notify that there are now keys in the keypool
    void canGetAddressesChanged();

    // Signal that reserved balance in wallet changed
    void notifyReservedBalanceChanged(CAmount nValue);

public Q_SLOTS:
    /* Wallet status might have changed */
    void updateStatus();
    /* New transaction, or transaction changed status */
    void updateTransaction();
    /* New, updated or removed address book entry */
    void updateAddressBook(const QString &address, const QString &label, bool isMine, const QString &purpose, int status);
    /* Watch-only added */
    void updateWatchOnlyFlag(bool fHaveWatchonly);
    /* Current, immature or unconfirmed balance might have changed - emit 'balanceChanged' if so */
    void pollBalanceChanged();

    // Reserved balance changed
    void setReserveBalance(CAmount nReserveBalanceNew);

    // Reserved balance in wallet changed
    void updateReservedBalanceChanged(CAmount nValue);

    // Rescan blockchain for transactions
    void startRescan();
};

#endif // BITCOIN_QT_WALLETMODEL_H
