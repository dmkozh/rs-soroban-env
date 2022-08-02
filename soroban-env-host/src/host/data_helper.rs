use crate::xdr::{
    ContractDataEntry, HashIdPreimage, HashIdPreimageContractId, HashIdPreimageEd25519ContractId,
    LedgerEntry, LedgerEntryData, LedgerEntryExt, LedgerKey, LedgerKeyAccount,
    LedgerKeyContractData, ScHostStorageErrorCode, ScHostValErrorCode, ScObject, ScStatic, ScVal,
    VecM,
};
use crate::{Host, HostError, Object};
use soroban_env_common::xdr::{AccountEntry, AccountId, Hash, PublicKey, Uint256, WriteXdr};
use soroban_env_common::RawVal;

impl Host {
    pub fn contract_code_ledger_key(&self, contract_id: Hash) -> LedgerKey {
        LedgerKey::ContractData(LedgerKeyContractData {
            contract_id,
            key: ScVal::Static(ScStatic::LedgerKeyContractCodeWasm),
        })
    }

    pub fn retrieve_contract_code_from_storage(
        &self,
        key: &LedgerKey,
    ) -> Result<VecM<u8, 256000>, HostError> {
        let scval = match self.0.storage.borrow_mut().get(key)?.data {
            LedgerEntryData::ContractData(ContractDataEntry { val, .. }) => Ok(val),
            _ => Err(self.err_status(ScHostStorageErrorCode::ExpectContractData)),
        }?;
        match scval {
            ScVal::Object(Some(ScObject::Binary(b))) => Ok(b),
            _ => {
                return Err(self.err_status_msg(
                    ScHostValErrorCode::UnexpectedValType,
                    "ledger entry for contract code is not a binary object",
                ))
            }
        }
    }

    pub fn store_contract_code(
        &self,
        contract: Object,
        contract_id: Hash,
        key: &LedgerKey,
    ) -> Result<(), HostError> {
        let val = self.from_host_obj(contract)?;
        let data = LedgerEntryData::ContractData(ContractDataEntry {
            contract_id,
            key: ScVal::Static(ScStatic::LedgerKeyContractCodeWasm),
            val: ScVal::Object(Some(val)),
        });
        let val = LedgerEntry {
            last_modified_ledger_seq: 0,
            data,
            ext: LedgerEntryExt::V0,
        };
        self.0.storage.borrow_mut().put(&key, &val)?;
        Ok(())
    }

    pub fn id_preimage_from_ed25519(
        &self,
        key: Uint256,
        salt: Uint256,
    ) -> Result<Vec<u8>, HostError> {
        //Create contract and contractID
        let pre_image = HashIdPreimage::ContractIdFromEd25519(HashIdPreimageEd25519ContractId {
            ed25519: key,
            salt,
        });
        let mut buf = Vec::new();
        pre_image
            .write_xdr(&mut buf)
            .map_err(|_| self.err_general("invalid hash"))?;
        Ok(buf)
    }

    pub fn id_preimage_from_contract(
        &self,
        contract_id: Hash,
        salt: Uint256,
    ) -> Result<Vec<u8>, HostError> {
        let pre_image =
            HashIdPreimage::ContractIdFromContract(HashIdPreimageContractId { contract_id, salt });
        let mut buf = Vec::new();
        pre_image
            .write_xdr(&mut buf)
            .map_err(|_| self.err_general("invalid hash"))?;
        Ok(buf)
    }

    pub fn load_account(&self, a: Object) -> Result<AccountEntry, HostError> {
        let acc = LedgerKey::Account(LedgerKeyAccount {
            account_id: AccountId(PublicKey::PublicKeyTypeEd25519(self.to_u256(a)?)),
        });
        self.visit_storage(|storage| match storage.get(&acc)?.data {
            LedgerEntryData::Account(ae) => Ok(ae),
            _ => Err(self.err_general("not account")),
        })
    }

    /// Converts a [`RawVal`] to an [`ScVal`] and combines it with the currently-executing
    /// [`ContractID`] to produce a [`Key`], that can be used to access ledger [`Storage`].
    pub fn to_storage_key(&self, k: RawVal) -> Result<LedgerKey, HostError> {
        Ok(LedgerKey::ContractData(LedgerKeyContractData {
            contract_id: self.get_current_contract_id()?,
            key: self.from_host_val(k)?,
        }))
    }
}
