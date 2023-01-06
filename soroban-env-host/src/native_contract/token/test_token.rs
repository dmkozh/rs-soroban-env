use crate::{
    host_vec,
    native_contract::testutils::{AccountAuthBuilder, HostVec, TestSigner},
    test::util::{generate_account_id, generate_bytes_array},
    Host, HostError,
};
use soroban_env_common::{
    xdr::{
        Asset, ContractId, CreateContractArgs, HostFunction, ScAddress, ScContractCode, Uint256,
    },
    CheckedEnv, RawVal,
};
use soroban_env_common::{Symbol, TryFromVal, TryIntoVal};

use crate::native_contract::base_types::{Bytes, BytesN};

pub(crate) struct TestToken<'a> {
    pub(crate) id: BytesN<32>,
    host: &'a Host,
}

impl<'a> TestToken<'a> {
    pub(crate) fn new_from_asset(host: &'a Host, asset: Asset) -> Self {
        let id_obj: RawVal = host
            .invoke_function(HostFunction::CreateContract(CreateContractArgs {
                contract_id: ContractId::Asset(asset),
                source: ScContractCode::Token,
            }))
            .unwrap()
            .try_into_val(host)
            .unwrap();
        Self {
            id: BytesN::<32>::try_from_val(host, id_obj).unwrap(),
            host,
        }
    }

    pub(crate) fn allowance(&self, from: ScAddress, spender: ScAddress) -> Result<i128, HostError> {
        Ok(self
            .host
            .call(
                self.id.clone().into(),
                Symbol::from_str("allowance"),
                host_vec![self.host, from, spender].into(),
            )?
            .try_into_val(self.host)?)
    }

    pub(crate) fn incr_allow(
        &self,
        from: &TestSigner,
        spender: ScAddress,
        amount: i128,
    ) -> Result<(), HostError> {
        let from_acc = AccountAuthBuilder::new(self.host, from)
            .add_invocation(
                &self.id,
                "incr_allow",
                host_vec![self.host, spender.clone(), amount.clone()],
            )
            .build();

        Ok(self
            .host
            .call(
                self.id.clone().into(),
                Symbol::from_str("incr_allow"),
                host_vec![self.host, from_acc, spender, amount].into(),
            )?
            .try_into()?)
    }

    pub(crate) fn decr_allow(
        &self,
        from: &TestSigner,
        spender: ScAddress,
        amount: i128,
    ) -> Result<(), HostError> {
        let from_acc = AccountAuthBuilder::new(self.host, from)
            .add_invocation(
                &self.id,
                "decr_allow",
                host_vec![self.host, spender.clone(), amount.clone()],
            )
            .build();

        Ok(self
            .host
            .call(
                self.id.clone().into(),
                Symbol::from_str("decr_allow"),
                host_vec![self.host, from_acc, spender, amount].into(),
            )?
            .try_into()?)
    }

    pub(crate) fn balance(&self, addr: ScAddress) -> Result<i128, HostError> {
        Ok(self
            .host
            .call(
                self.id.clone().into(),
                Symbol::from_str("balance"),
                host_vec![self.host, addr].into(),
            )?
            .try_into_val(self.host)?)
    }

    pub(crate) fn spendable(&self, addr: ScAddress) -> Result<i128, HostError> {
        Ok(self
            .host
            .call(
                self.id.clone().into(),
                Symbol::from_str("spendable"),
                host_vec![self.host, addr].into(),
            )?
            .try_into_val(self.host)?)
    }

    pub(crate) fn authorized(&self, addr: ScAddress) -> Result<bool, HostError> {
        Ok(self
            .host
            .call(
                self.id.clone().into(),
                Symbol::from_str("authorized"),
                host_vec![self.host, addr].into(),
            )?
            .try_into_val(self.host)?)
    }

    pub(crate) fn xfer(
        &self,
        from: &TestSigner,
        to: ScAddress,
        amount: i128,
    ) -> Result<(), HostError> {
        let from_acc = AccountAuthBuilder::new(self.host, from)
            .add_invocation(
                &self.id,
                "xfer",
                host_vec![self.host, to.clone(), amount.clone()],
            )
            .build();

        Ok(self
            .host
            .call(
                self.id.clone().into(),
                Symbol::from_str("xfer"),
                host_vec![self.host, from_acc, to, amount].into(),
            )?
            .try_into()?)
    }

    pub(crate) fn xfer_from(
        &self,
        spender: &TestSigner,
        from: ScAddress,
        to: ScAddress,
        amount: i128,
    ) -> Result<(), HostError> {
        let spender_acc = AccountAuthBuilder::new(self.host, spender)
            .add_invocation(
                &self.id,
                "xfer_from",
                host_vec![self.host, from.clone(), to.clone(), amount.clone()],
            )
            .build();

        Ok(self
            .host
            .call(
                self.id.clone().into(),
                Symbol::from_str("xfer_from"),
                host_vec![self.host, spender_acc, from, to, amount].into(),
            )?
            .try_into()?)
    }

    pub(crate) fn burn(&self, from: &TestSigner, amount: i128) -> Result<(), HostError> {
        let from_acc = AccountAuthBuilder::new(self.host, from)
            .add_invocation(&self.id, "burn", host_vec![self.host, amount.clone()])
            .build();

        Ok(self
            .host
            .call(
                self.id.clone().into(),
                Symbol::from_str("burn"),
                host_vec![self.host, from_acc, amount].into(),
            )?
            .try_into()?)
    }

    pub(crate) fn burn_from(
        &self,
        spender: &TestSigner,
        from: ScAddress,
        amount: i128,
    ) -> Result<(), HostError> {
        let spender_acc = AccountAuthBuilder::new(self.host, spender)
            .add_invocation(
                &self.id,
                "burn_from",
                host_vec![self.host, from.clone(), amount.clone()],
            )
            .build();

        Ok(self
            .host
            .call(
                self.id.clone().into(),
                Symbol::from_str("burn_from"),
                host_vec![self.host, spender_acc, from, amount].into(),
            )?
            .try_into()?)
    }

    pub(crate) fn set_auth(
        &self,
        admin: &TestSigner,
        addr: ScAddress,
        authorize: bool,
    ) -> Result<(), HostError> {
        let admin_acc = AccountAuthBuilder::new(self.host, admin)
            .add_invocation(
                &self.id,
                "set_auth",
                host_vec![self.host, addr.clone(), authorize],
            )
            .build();
        Ok(self
            .host
            .call(
                self.id.clone().into(),
                Symbol::from_str("set_auth"),
                host_vec![self.host, admin_acc, addr, authorize].into(),
            )?
            .try_into()?)
    }

    pub(crate) fn mint(
        &self,
        admin: &TestSigner,
        to: ScAddress,
        amount: i128,
    ) -> Result<(), HostError> {
        let admin_acc = AccountAuthBuilder::new(self.host, admin)
            .add_invocation(
                &self.id,
                "mint",
                host_vec![self.host, to.clone(), amount.clone()],
            )
            .build();

        Ok(self
            .host
            .call(
                self.id.clone().into(),
                Symbol::from_str("mint"),
                host_vec![self.host, admin_acc, to, amount].into(),
            )?
            .try_into()?)
    }

    pub(crate) fn clawback(
        &self,
        admin: &TestSigner,
        from: ScAddress,
        amount: i128,
    ) -> Result<(), HostError> {
        let admin_acc = AccountAuthBuilder::new(self.host, admin)
            .add_invocation(
                &self.id,
                "clawback",
                host_vec![self.host, from.clone(), amount.clone()],
            )
            .build();

        Ok(self
            .host
            .call(
                self.id.clone().into(),
                Symbol::from_str("clawback"),
                host_vec![self.host, admin_acc, from, amount].into(),
            )?
            .try_into()?)
    }

    pub(crate) fn set_admin(
        &self,
        admin: &TestSigner,
        new_admin: ScAddress,
    ) -> Result<(), HostError> {
        let admin_acc = AccountAuthBuilder::new(self.host, admin)
            .add_invocation(
                &self.id,
                "set_admin",
                host_vec![self.host, new_admin.clone()],
            )
            .build();

        Ok(self
            .host
            .call(
                self.id.clone().into(),
                Symbol::from_str("set_admin"),
                host_vec![self.host, admin_acc, new_admin].into(),
            )?
            .try_into()?)
    }

    pub(crate) fn decimals(&self) -> Result<u32, HostError> {
        Ok(self
            .host
            .call(
                self.id.clone().into(),
                Symbol::from_str("decimals"),
                host_vec![self.host].into(),
            )?
            .try_into()?)
    }

    pub(crate) fn name(&self) -> Result<Bytes, HostError> {
        Ok(self
            .host
            .call(
                self.id.clone().into(),
                Symbol::from_str("name"),
                host_vec![self.host].into(),
            )?
            .try_into_val(self.host)?)
    }

    pub(crate) fn symbol(&self) -> Result<Bytes, HostError> {
        Ok(self
            .host
            .call(
                self.id.clone().into(),
                Symbol::from_str("symbol"),
                host_vec![self.host].into(),
            )?
            .try_into_val(self.host)?)
    }
}
