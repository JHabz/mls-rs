use crate::credential::CredentialError;
use crate::group::framing::{Content, MLSPlaintext, Sender, WireFormat};
use crate::group::{AddProposal, GroupContext, Proposal};
use crate::tree_kem::{RatchetTreeError, TreeKemPublic};
use ferriscrypt::asym::ec_key::{EcKeyError, SecretKey};
use ferriscrypt::{Signer, Verifier};
use std::ops::Deref;
use thiserror::Error;
use tls_codec::Serialize;
use tls_codec_derive::{TlsDeserialize, TlsSerialize, TlsSize};

#[derive(Error, Debug)]
pub enum MessageSignatureError {
    #[error(transparent)]
    SignatureError(#[from] EcKeyError),
    #[error(transparent)]
    RatchetTreeError(#[from] RatchetTreeError),
    #[error(transparent)]
    SerializationError(#[from] tls_codec::Error),
    #[error(transparent)]
    CredentialError(#[from] CredentialError),
    #[error("New members can only propose adding themselves")]
    NewMembersCanOnlyProposeAddingThemselves,
}

#[derive(Clone, Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
pub(crate) struct MLSPlaintextTBS {
    context: Option<GroupContext>,
    wire_format: WireFormat,
    #[tls_codec(with = "crate::tls::ByteVec::<u32>")]
    group_id: Vec<u8>,
    epoch: u64,
    sender: Sender,
    #[tls_codec(with = "crate::tls::ByteVec::<u32>")]
    authenticated_data: Vec<u8>,
    content: Content,
}

impl MLSPlaintextTBS {
    pub(crate) fn from_plaintext(
        plaintext: &MLSPlaintext,
        group_context: &GroupContext,
        wire_format: WireFormat,
    ) -> Self {
        let context = match plaintext.sender {
            Sender::Member(_) => Some(group_context.clone()),
            _ => None,
        };

        MLSPlaintextTBS {
            context,
            wire_format,
            group_id: plaintext.group_id.clone(),
            epoch: plaintext.epoch,
            sender: plaintext.sender.clone(),
            authenticated_data: plaintext.authenticated_data.clone(),
            content: plaintext.content.clone(),
        }
    }
}

impl MLSPlaintext {
    pub(crate) fn sign(
        &mut self,
        signer: &SecretKey,
        group_context: &GroupContext,
        wire_format: WireFormat,
    ) -> Result<(), MessageSignatureError> {
        self.signature = MessageSignature::create(signer, self, group_context, wire_format)?;
        Ok(())
    }

    pub(crate) fn verify_signature(
        &self,
        tree: &TreeKemPublic,
        group_context: &GroupContext,
        wire_format: WireFormat,
    ) -> Result<bool, MessageSignatureError> {
        self.signature
            .is_valid(self, tree, group_context, wire_format)
    }
}

#[derive(Clone, Debug, PartialEq, TlsDeserialize, TlsSerialize, TlsSize)]
pub struct MessageSignature(#[tls_codec(with = "crate::tls::ByteVec::<u32>")] Vec<u8>);

impl MessageSignature {
    pub(crate) fn empty() -> Self {
        MessageSignature(vec![])
    }

    fn create(
        signer: &SecretKey,
        plaintext: &MLSPlaintext,
        group_context: &GroupContext,
        wire_format: WireFormat,
    ) -> Result<Self, MessageSignatureError> {
        let to_be_signed = MLSPlaintextTBS::from_plaintext(plaintext, group_context, wire_format);
        let signature_data = signer.sign(&to_be_signed.tls_serialize_detached()?)?;

        Ok(MessageSignature(signature_data))
    }

    fn is_valid(
        &self,
        plaintext: &MLSPlaintext,
        tree: &TreeKemPublic,
        group_context: &GroupContext,
        wire_format: WireFormat,
    ) -> Result<bool, MessageSignatureError> {
        //Verify that the signature on the MLSPlaintext message verifies using the public key
        // from the credential stored at the leaf in the tree indicated by the sender field.
        let sender_cred = match &plaintext.sender {
            Sender::Member(sender) => Ok(&tree.get_key_package(sender)?.credential),
            Sender::Preconfigured(_) => todo!(),
            Sender::NewMember => match &plaintext.content {
                Content::Proposal(Proposal::Add(AddProposal { key_package })) => {
                    Ok(&key_package.credential)
                }
                _ => Err(MessageSignatureError::NewMembersCanOnlyProposeAddingThemselves),
            },
        }?;

        let to_be_verified = MLSPlaintextTBS::from_plaintext(plaintext, group_context, wire_format);

        let is_signature_valid = sender_cred.verify(
            &plaintext.signature,
            &to_be_verified.tls_serialize_detached()?,
        )?;

        Ok(is_signature_valid)
    }
}

impl Deref for MessageSignature {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<Vec<u8>> for MessageSignature {
    fn from(v: Vec<u8>) -> Self {
        MessageSignature(v)
    }
}
