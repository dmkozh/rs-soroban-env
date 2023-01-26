use std::collections::HashMap;

use soroban_env_common::xdr::{
    ContractAuth, ContractDataEntry, HashIdPreimage, HashIdPreimageContractAuth, LedgerEntry,
    LedgerEntryData, LedgerEntryExt, ScAddress, ScObject, ScVal,
};
use soroban_env_common::{RawVal, Symbol};

use crate::budget::Budget;
use crate::host::metered_clone::MeteredClone;
use crate::host::Frame;
use crate::native_contract::account_contract::{
    check_classic_account_authentication, check_generic_account_auth,
};
use crate::{Host, HostError};

use super::xdr;
use super::xdr::{Hash, ScUnknownErrorCode, ScVec};

#[derive(Clone)]
struct AuthorizationTracker {
    address: Option<ScAddress>,
    authorized_invocation_root: AuthorizedInvocation,
    invocation_id_in_call_stack: Vec<Option<usize>>,
    signature_args: Vec<RawVal>,
    is_valid: bool,
    is_invoker: bool,
    authenticated: bool,
    need_nonce: bool,
    nonce: Option<u64>,
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct ContractInvocation {
    pub(crate) contract_id: Hash,
    pub(crate) function_name: Symbol,
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct AuthorizedInvocation {
    pub(crate) contract_id: Hash,
    pub(crate) function_name: Symbol,
    pub(crate) args: ScVec,
    pub(crate) sub_invocations: Vec<AuthorizedInvocation>,
    is_exhausted: bool,
}

#[derive(Eq, PartialEq, Debug)]
pub struct RecordedSignaturePayload {
    pub address: Option<ScAddress>,
    pub nonce: Option<u64>,
    pub invocation: xdr::AuthorizedInvocation,
}

#[derive(Clone)]
pub struct AuthorizationManagerSnapshot {
    // AuthorizationTracker has some immutable parts, but it is safer to just
    // rollback everything. If this is an issue, then the AuthorizationTracker should
    // probably be separated into 'mutable' and 'immutable' parts.
    trackers: Vec<AuthorizationTracker>,
}

#[derive(Clone)]
struct RecordingAuthInfo {
    tracker_by_address_handle: HashMap<u32, usize>,
    #[cfg(any(test, feature = "testutils"))]
    last_recorded_trackers: Vec<AuthorizationTracker>,
}

#[derive(Clone)]
enum AuthorizationMode {
    Enforcing,
    Recording(RecordingAuthInfo),
}

#[derive(Clone)]
pub(crate) struct AuthorizationManager {
    mode: AuthorizationMode,
    trackers: Vec<AuthorizationTracker>,
    call_stack: Vec<ContractInvocation>,
    budget: Budget,
}

impl Default for AuthorizationManager {
    fn default() -> Self {
        Self::new_enforcing_without_authorizations(Budget::default())
    }
}

// impl ContractInvocation {
//     fn from_xdr(xdr_invocation: xdr::ContractInvocation) -> Result<Self, HostError> {
//         Ok(Self {
//             contract_id: xdr_invocation.contract_id,
//             function_name: Symbol::try_from(xdr_invocation.function_name)?,
//         })
//     }

//     fn to_xdr(&self, budget: &Budget) -> Result<xdr::ContractInvocation, HostError> {
//         Ok(xdr::ContractInvocation {
//             contract_id: self.contract_id.metered_clone(budget)?,
//             function_name: self
//                 .function_name
//                 .to_string()
//                 .try_into()
//                 .map_err(|_| HostError::from(ScUnknownErrorCode::General))?,
//         })
//     }

//     // Non-metered conversion should only be used for the recording preflight
//     // runs.
//     fn to_xdr_non_metered(&self) -> Result<xdr::ContractInvocation, HostError> {
//         Ok(xdr::ContractInvocation {
//             contract_id: self.contract_id.clone(),
//             // This ideally should be infallible
//             function_name: self
//                 .function_name
//                 .to_string()
//                 .try_into()
//                 .map_err(|_| HostError::from(ScUnknownErrorCode::General))?,
//         })
//     }
// }

impl AuthorizedInvocation {
    fn from_xdr(xdr_invocation: xdr::AuthorizedInvocation) -> Result<Self, HostError> {
        let sub_invocations_xdr = xdr_invocation.sub_invocations.to_vec();
        let sub_invocations = sub_invocations_xdr
            .into_iter()
            .map(|i| AuthorizedInvocation::from_xdr(i))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            contract_id: xdr_invocation.contract_id.clone(),
            function_name: Symbol::try_from(xdr_invocation.function_name)?,
            args: xdr_invocation.args.clone(),
            sub_invocations,
            is_exhausted: false,
        })
    }

    fn new(contract_id: &Hash, function_name: Symbol, args: ScVec) -> Self {
        Self {
            contract_id: contract_id.clone(),
            function_name,
            args,
            sub_invocations: vec![],
            is_exhausted: true,
        }
    }

    fn to_xdr(&self, budget: &Budget) -> Result<xdr::AuthorizedInvocation, HostError> {
        Ok(xdr::AuthorizedInvocation {
            contract_id: self.contract_id.metered_clone(budget)?,
            // This ideally should be infallible
            function_name: self
                .function_name
                .to_string()
                .try_into()
                .map_err(|_| HostError::from(ScUnknownErrorCode::General))?,
            args: self.args.metered_clone(budget)?,
            sub_invocations: self
                .sub_invocations
                .iter()
                .map(|i| i.to_xdr(budget))
                .collect::<Result<Vec<xdr::AuthorizedInvocation>, HostError>>()?
                .try_into()
                .map_err(|_| HostError::from(ScUnknownErrorCode::General))?,
        })
    }

    // Non-metered conversion should only be used for the recording preflight
    // runs.
    fn to_xdr_non_metered(&self) -> Result<xdr::AuthorizedInvocation, HostError> {
        Ok(xdr::AuthorizedInvocation {
            contract_id: self.contract_id.clone(),
            // This ideally should be infallible
            function_name: self
                .function_name
                .to_string()
                .try_into()
                .map_err(|_| HostError::from(ScUnknownErrorCode::General))?,
            args: self.args.clone(),
            sub_invocations: self
                .sub_invocations
                .iter()
                .map(|i| i.to_xdr_non_metered())
                .collect::<Result<Vec<xdr::AuthorizedInvocation>, HostError>>()?
                .try_into()
                .map_err(|_| HostError::from(ScUnknownErrorCode::General))?,
        })
    }

    fn last_authorized_invocation_mut(
        &mut self,
        invocation_id_in_call_stack: &Vec<Option<usize>>,
        call_stack_id: usize,
    ) -> Option<&mut AuthorizedInvocation> {
        for i in call_stack_id..invocation_id_in_call_stack.len() {
            if let Some(id) = invocation_id_in_call_stack[i] {
                return self.sub_invocations[id]
                    .last_authorized_invocation_mut(invocation_id_in_call_stack, i + 1);
            }
        }
        Some(self)
    }
}

impl AuthorizationManager {
    pub(crate) fn new_enforcing_without_authorizations(budget: Budget) -> Self {
        Self {
            mode: AuthorizationMode::Enforcing,
            call_stack: vec![],
            budget,
            trackers: vec![],
        }
    }

    pub(crate) fn new_recording(budget: Budget) -> Self {
        Self {
            mode: AuthorizationMode::Recording(RecordingAuthInfo {
                tracker_by_address_handle: Default::default(),
                #[cfg(any(test, feature = "testutils"))]
                last_recorded_trackers: vec![],
            }),
            call_stack: vec![],
            budget,
            trackers: vec![],
        }
    }

    pub(crate) fn new_enforcing(
        host: &Host,
        auth_entries: Vec<ContractAuth>,
    ) -> Result<Self, HostError> {
        let mut trackers = vec![];
        for auth_entry in auth_entries {
            trackers.push(AuthorizationTracker::from_authorization_entry(
                host, auth_entry,
            )?);
        }
        Ok(Self {
            mode: AuthorizationMode::Enforcing,
            call_stack: vec![],
            budget: host.budget_cloned(),
            trackers,
        })
    }

    pub(crate) fn snapshot(&self) -> AuthorizationManagerSnapshot {
        AuthorizationManagerSnapshot {
            trackers: self.trackers.clone(),
        }
    }

    pub(crate) fn rollback(&mut self, snapshot: AuthorizationManagerSnapshot) {
        self.trackers = snapshot.trackers;
    }

    #[cfg(any(test, feature = "testutils"))]
    pub(crate) fn reset(&mut self) {
        if let AuthorizationMode::Recording(recording_info) = &mut self.mode {
            std::mem::swap(
                &mut self.trackers,
                &mut recording_info.last_recorded_trackers,
            );
        }
        // In enforcing mode reset would basically deny all the authorizations
        // after reset, but this should be fine since the intended use case for
        // it is testing testing should use the recording mode most of the time
        // (and re-create AuthorizationManager using `new_enforcing` in the
        // enforcing mode tests).
        self.trackers.clear();
        self.call_stack.clear();
    }

    pub(crate) fn push_frame(&mut self, frame: &Frame) -> Result<(), HostError> {
        let (contract_id, function_name) = match frame {
            #[cfg(feature = "vm")]
            Frame::ContractVM(vm, fn_name) => {
                (vm.contract_id.metered_clone(&self.budget)?, fn_name.clone())
            }
            // TODO: we could also make this included into the stack to generalize
            // auth to host fn invocations too; not sure how to properly identify
            // them though
            Frame::HostFunction(_) => return Ok(()),
            Frame::Token(id, fn_name) => (id.metered_clone(&self.budget)?, fn_name.clone()),
            #[cfg(any(test, feature = "testutils"))]
            Frame::TestContract(tc) => (tc.id.clone(), tc.func.clone()),
        };
        self.call_stack.push(ContractInvocation {
            contract_id,
            function_name,
        });
        for account in &mut self.trackers {
            account.push_frame();
        }
        Ok(())
    }

    pub(crate) fn pop_frame(&mut self) {
        // Currently we don't push host function call frames, hence this may be
        // called with empty stack. We trust the Host to keep things correct,
        // i.e. that only host function frames are ignored this way.
        // Eventually we may want to also authorize host fns via this, so this
        // won't be needed.
        if self.call_stack.is_empty() {
            return;
        }
        self.call_stack.pop();
        for account in &mut self.trackers {
            account.pop_frame();
        }
    }

    pub(crate) fn get_recorded_signature_payloads(
        &self,
    ) -> Result<Vec<RecordedSignaturePayload>, HostError> {
        match &self.mode {
            AuthorizationMode::Enforcing => return Err(ScUnknownErrorCode::General.into()),
            AuthorizationMode::Recording(recording_info) => {
                #[cfg(any(test, feature = "testutils"))]
                {
                    Ok(recording_info
                        .last_recorded_trackers
                        .iter()
                        .map(|tracker| tracker.get_recorded_signature_payload())
                        .collect::<Result<Vec<RecordedSignaturePayload>, HostError>>()?)
                }
                #[cfg(not(any(test, feature = "testutils")))]
                {
                    Ok(self
                        .trackers
                        .iter()
                        .map(|tracker| tracker.get_recorded_signature_payload())
                        .collect::<Result<Vec<RecordedSignaturePayload>, HostError>>()?)
                }
            }
        }
    }

    pub(crate) fn require_auth(
        &mut self,
        host: &Host,
        address_obj_handle: u32,
        address: ScAddress,
        args: ScVec,
    ) -> Result<(), HostError> {
        if let ScAddress::Contract(contract_addr) = &address {
            // For now we give a blanket approval of the invoker contract to any
            // calls it made, but never to the deeper calls. It's possible
            // to eventually add a capability to pre-authorize arbitrary call
            // stacks on behalf of the contract.
            if let Ok(invoker_contract) = host.get_invoking_contract_internal() {
                if &invoker_contract == contract_addr {
                    return Ok(());
                }
            }
        }
        if let Some(curr_invocation) = self.call_stack.last() {
            match &mut self.mode {
                AuthorizationMode::Enforcing => {
                    for tracker in &mut self.trackers {
                        let address_matches = if let Some(addr) = &tracker.address {
                            addr == &address
                        } else {
                            // Lazily fill the address for the invoker trackers,
                            // so that it's possible to create the auth manager
                            // without knowing the invoker.
                            let source_addr = ScAddress::ClassicAccount(host.source_account()?);
                            let source_matches = source_addr == address;
                            tracker.address = Some(source_addr);
                            source_matches
                        };
                        if address_matches {
                            match tracker.maybe_authorize_invocation(
                                host,
                                &curr_invocation.contract_id,
                                curr_invocation.function_name,
                                &args,
                            ) {
                                Ok(false) => continue,
                                Ok(true) => return Ok(()),
                                Err(e) => return Err(e),
                            }
                        }
                    }
                    Err(host.err_general("TODO"))
                }
                AuthorizationMode::Recording(recording_info) => {
                    if let Some(tracker_id) = recording_info
                        .tracker_by_address_handle
                        .get(&address_obj_handle)
                    {
                        self.trackers[*tracker_id].record_invocation(
                            host,
                            &curr_invocation.contract_id,
                            curr_invocation.function_name,
                            args,
                        )
                    } else {
                        self.trackers.push(AuthorizationTracker::new_recording(
                            host,
                            address,
                            &curr_invocation.contract_id,
                            curr_invocation.function_name,
                            args,
                            self.call_stack.len(),
                        )?);
                        recording_info
                            .tracker_by_address_handle
                            .insert(address_obj_handle, self.trackers.len() - 1);
                        Ok(())
                    }
                }
            }
        } else {
            // This would be a bug
            Err(ScUnknownErrorCode::General.into())
        }
    }

    #[cfg(any(test, feature = "testutils"))]
    pub(crate) fn verify_top_authorization(
        &mut self,
        address: &ScAddress,
        contract_id: &Hash,
        function_name: &Symbol,
        args: &ScVec,
    ) -> bool {
        match self.mode {
            AuthorizationMode::Enforcing => {
                panic!("verifying the authorization is only available for recording-mode auth")
            }
            AuthorizationMode::Recording(_) => {
                for tracker in &mut self.trackers {
                    if tracker.verify_top_authorization(address, contract_id, function_name, args) {
                        return true;
                    }
                }
                return false;
            }
        }
    }
}

impl AuthorizationTracker {
    fn from_authorization_entry(host: &Host, auth_entry: ContractAuth) -> Result<Self, HostError> {
        let is_invoker = auth_entry.address.is_none();
        Ok(Self {
            address: auth_entry.address,
            authorized_invocation_root: AuthorizedInvocation::from_xdr(auth_entry.invocation)?,
            signature_args: host.scvals_to_rawvals(auth_entry.signature_args.0.as_slice())?,
            authenticated: false,
            need_nonce: !is_invoker,
            is_invoker,
            nonce: auth_entry.nonce,
            invocation_id_in_call_stack: vec![],
            is_valid: true,
        })
    }

    fn new_recording(
        host: &Host,
        address: ScAddress,
        contract_id: &Hash,
        function_name: Symbol,
        args: ScVec,
        current_stack_len: usize,
    ) -> Result<Self, HostError> {
        let source_address = ScAddress::ClassicAccount(host.source_account()?);
        let mut nonce = None;
        let address = if source_address == address {
            None
        } else {
            nonce = Some(host.read_and_consume_nonce(&contract_id, &address)?);
            Some(address)
        };
        let is_invoker = address.is_none();
        Ok(Self {
            address,
            authorized_invocation_root: AuthorizedInvocation::new(contract_id, function_name, args),
            invocation_id_in_call_stack: vec![None; current_stack_len],
            signature_args: Default::default(),
            is_valid: true,
            authenticated: true,
            need_nonce: !is_invoker,
            is_invoker,
            nonce,
        })
    }

    fn get_recorded_signature_payload(&self) -> Result<RecordedSignaturePayload, HostError> {
        Ok(RecordedSignaturePayload {
            address: self.address.clone(),
            invocation: self.authorized_invocation_root.to_xdr_non_metered()?,
            nonce: self.nonce,
        })
    }

    fn invocation_to_xdr(&self, budget: &Budget) -> Result<xdr::AuthorizedInvocation, HostError> {
        self.authorized_invocation_root.to_xdr(budget)
    }

    fn push_frame(&mut self) {
        self.invocation_id_in_call_stack.push(None);
    }

    fn pop_frame(&mut self) {
        self.invocation_id_in_call_stack.pop();
    }

    fn maybe_consume_nonce(&mut self, host: &Host) -> Result<Option<u64>, HostError> {
        if !self.need_nonce {
            return Ok(None);
        }
        self.need_nonce = false;
        if let Some(addr) = &self.address {
            Ok(Some(host.read_and_consume_nonce(
                &self.authorized_invocation_root.contract_id,
                addr,
            )?))
        } else {
            Ok(None)
        }
    }

    // fn last_authorized_invocation_mut(&mut self) -> Option<&mut AuthorizedInvocation> {
    //     let mut res: Option<&mut AuthorizedInvocation> = None;
    //     for authorized_id in &self.invocation_id_in_call_stack {
    //         if let Some(id) = authorized_id {
    //             if let Some(curr_invocation) = {res} {
    //                 res = Some(&mut {curr_invocation}.sub_invocations[*id]);
    //             } else {
    //                 res = Some(&mut self.authorized_invocation_root);
    //             }
    //         }
    //     }
    //     res
    // }

    fn last_authorized_invocation_mut(&mut self) -> Option<&mut AuthorizedInvocation> {
        for i in 0..self.invocation_id_in_call_stack.len() {
            if self.invocation_id_in_call_stack[i].is_some() {
                return self
                    .authorized_invocation_root
                    .last_authorized_invocation_mut(&self.invocation_id_in_call_stack, i + 1);
            }
        }
        None
    }

    fn push_matching_invocation_frame(
        &mut self,
        contract_id: &Hash,
        function_name: Symbol,
        args: &ScVec,
    ) -> bool {
        let mut frame_index = None;
        if let Some(curr_invocation) = self.last_authorized_invocation_mut() {
            for i in 0..curr_invocation.sub_invocations.len() {
                let sub_invocation = &mut curr_invocation.sub_invocations[i];
                if !sub_invocation.is_exhausted
                    && &sub_invocation.contract_id == contract_id
                    && sub_invocation.function_name == function_name
                    && &sub_invocation.args == args
                {
                    frame_index = Some(i);
                    sub_invocation.is_exhausted = true;
                }
            }
        } else {
            if !self.authorized_invocation_root.is_exhausted
                && &self.authorized_invocation_root.contract_id == contract_id
                && self.authorized_invocation_root.function_name == function_name
                && &self.authorized_invocation_root.args == args
            {
                frame_index = Some(0);
                self.authorized_invocation_root.is_exhausted = true;
            }
        }
        if frame_index.is_some() {
            *self.invocation_id_in_call_stack.last_mut().unwrap() = frame_index;
        }
        frame_index.is_some()
    }

    fn verify_nonce(&mut self, host: &Host) -> Result<(), HostError> {
        let nonce_is_correct = if let Some(nonce) = self.maybe_consume_nonce(host)? {
            if let Some(tracker_nonce) = self.nonce {
                tracker_nonce == nonce
            } else {
                // If the nonce isn't set in the tracker, but is required, then
                // it's incorrect.
                false
            }
        } else {
            // Nonce is either already checked or not needed
            true
        };
        if nonce_is_correct {
            Ok(())
        } else {
            Err(ScUnknownErrorCode::General.into())
        }
    }

    fn maybe_authorize_invocation(
        &mut self,
        host: &Host,
        contract_id: &Hash,
        function_name: Symbol,
        args: &ScVec,
    ) -> Result<bool, HostError> {
        if !self.is_valid {
            return Ok(false);
        }
        let frame_is_already_authorized =
            // matches!(Some(Some(_)), self.invocation_id_in_call_stack.last());
            match self.invocation_id_in_call_stack.last() {
                Some(Some(_)) => true,
                _ => false,
            };
        if frame_is_already_authorized
            || !self.push_matching_invocation_frame(contract_id, function_name, args)
        {
            // The call isn't found in the currently tracked tree or is already authorized in it.
            // That doesn't necessarily mean it's unauthorized (it can be
            // authorized in a different tracker).
            return Ok(false);
        }
        if !self.authenticated {
            let authenticate_res = self
                .authenticate(host)
                .and_then(|_| self.verify_nonce(host));
            if let Some(err) = authenticate_res.err() {
                self.is_valid = false;
                return Err(err);
            }
        }
        Ok(true)
    }

    fn record_invocation(
        &mut self,
        host: &Host,
        contract_id: &Hash,
        function_name: Symbol,
        args: ScVec,
    ) -> Result<(), HostError> {
        let frame_is_already_authorized =
            // matches!(Some(Some(_)), self.invocation_id_in_call_stack.last());
            match self.invocation_id_in_call_stack.last() {
                Some(Some(_)) => true,
                _ => false,
            };
        if frame_is_already_authorized {
            return Err(host.err_general("TODO"));
        }
        if let Some(curr_invocation) = self.last_authorized_invocation_mut() {
            curr_invocation
                .sub_invocations
                .push(AuthorizedInvocation::new(contract_id, function_name, args));
            *self.invocation_id_in_call_stack.last_mut().unwrap() =
                Some(curr_invocation.sub_invocations.len() - 1);
        } else {
            // This would be a bug
            return Err(host.err_general("TODO"));
        }
        Ok(())
    }

    #[cfg(any(test, feature = "testutils"))]
    fn verify_top_authorization(
        &mut self,
        address: &ScAddress,
        contract_id: &Hash,
        function_name: &Symbol,
        args: &ScVec,
    ) -> bool {
        if self.authorized_invocation_root.is_exhausted {
            return false;
        }
        let is_matching = self.address.as_ref().unwrap() == address
            && &self.authorized_invocation_root.contract_id == contract_id
            && &self.authorized_invocation_root.function_name == function_name
            && &self.authorized_invocation_root.args == args;
        if is_matching {
            self.authorized_invocation_root.is_exhausted = true;
        }
        is_matching
    }

    fn get_signature_payload(&self, host: &Host) -> Result<[u8; 32], HostError> {
        let payload_preimage = HashIdPreimage::ContractAuth(HashIdPreimageContractAuth {
            network_id: Hash(
                host.with_ledger_info(|li| li.network_id.metered_clone(host.budget_ref()))?,
            ),
            invocation: self.invocation_to_xdr(host.budget_ref())?,
        });

        host.metered_hash_xdr(&payload_preimage)
    }

    fn authenticate(&self, host: &Host) -> Result<(), HostError> {
        if self.is_invoker {
            return Ok(());
        }
        if let Some(address) = &self.address {
            // TODO: there should also be a mode where a dummy payload is used instead
            // (for preflight with auth enforced).
            let payload = self.get_signature_payload(host)?;
            match address {
                ScAddress::ClassicAccount(acc) => {
                    check_classic_account_authentication(
                        host,
                        &acc,
                        &payload,
                        &self.signature_args,
                    )?;
                }
                ScAddress::Contract(generic_acc) => {
                    check_generic_account_auth(
                        host,
                        generic_acc,
                        &payload,
                        &self.signature_args,
                        &self.authorized_invocation_root,
                    )?;
                }
            }
        } else {
            return Err(host.err_general("missing address to authenticate"));
        }
        Ok(())
    }
}

impl Host {
    pub(crate) fn read_nonce(
        &self,
        contract_id: &Hash,
        address: &ScAddress,
    ) -> Result<u64, HostError> {
        let nonce_key_scval = ScVal::Object(Some(ScObject::NonceKey(
            address.metered_clone(self.budget_ref())?,
        )));
        let nonce_key = self.storage_key_for_contract(
            contract_id.metered_clone(self.budget_ref())?,
            nonce_key_scval,
        );
        let curr_nonce: u64 =
            if self.with_mut_storage(|storage| storage.has(&nonce_key, self.budget_ref()))? {
                let sc_val = self.with_mut_storage(|storage| {
                    match storage.get(&nonce_key, self.budget_ref())?.data {
                        LedgerEntryData::ContractData(ContractDataEntry { val, .. }) => Ok(val),
                        _ => Err(self.err_general("")),
                    }
                })?;
                match sc_val {
                    ScVal::Object(Some(ScObject::U64(val))) => val,
                    _ => {
                        return Err(self.err_general(""));
                    }
                }
            } else {
                0
            };
        Ok(curr_nonce)
    }

    fn read_and_consume_nonce(
        &self,
        contract_id: &Hash,
        address: &ScAddress,
    ) -> Result<u64, HostError> {
        let nonce_key_scval = ScVal::Object(Some(ScObject::NonceKey(
            address.metered_clone(self.budget_ref())?,
        )));
        let nonce_key = self.storage_key_for_contract(
            contract_id.metered_clone(self.budget_ref())?,
            nonce_key_scval.clone(),
        );
        let curr_nonce: u64 =
            if self.with_mut_storage(|storage| storage.has(&nonce_key, self.budget_ref()))? {
                let sc_val = self.with_mut_storage(|storage| {
                    match storage.get(&nonce_key, self.budget_ref())?.data {
                        LedgerEntryData::ContractData(ContractDataEntry { val, .. }) => Ok(val),
                        _ => Err(self.err_general("")),
                    }
                })?;
                match sc_val {
                    ScVal::Object(Some(ScObject::U64(val))) => val,
                    _ => {
                        return Err(self.err_general(""));
                    }
                }
            } else {
                0
            };
        let data = LedgerEntryData::ContractData(ContractDataEntry {
            contract_id: contract_id.metered_clone(self.budget_ref())?,
            key: nonce_key_scval,
            val: ScVal::Object(Some(ScObject::U64(curr_nonce + 1))),
        });
        let entry = LedgerEntry {
            last_modified_ledger_seq: 0,
            data,
            ext: LedgerEntryExt::V0,
        };
        self.with_mut_storage(|storage| storage.put(&nonce_key, &entry, self.budget_ref()))?;
        Ok(curr_nonce)
    }
}
