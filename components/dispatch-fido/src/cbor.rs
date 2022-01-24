use core::convert::From;
use core::convert::TryFrom;
use ctap_types::{
    authenticator::{Error as AuthenticatorError, Request},
    operation::Operation,
    serde::{cbor_deserialize, error::Error as SerdeError},
};

pub enum CtapMappingError {
    InvalidCommand(u8),
    ParsingError(SerdeError),
    Custom(AuthenticatorError),
}

impl From<CtapMappingError> for AuthenticatorError {
    fn from(mapping_error: CtapMappingError) -> AuthenticatorError {
        match mapping_error {
            CtapMappingError::InvalidCommand(_cmd) => AuthenticatorError::InvalidCommand,
            CtapMappingError::ParsingError(cbor_error) => match cbor_error {
                SerdeError::SerdeMissingField => AuthenticatorError::MissingParameter,
                _ => AuthenticatorError::InvalidCbor,
            },
            CtapMappingError::Custom(err) => err,
        }
    }
}

pub fn parse_cbor(data: &[u8]) -> core::result::Result<Request, CtapMappingError> {
    if data.len() < 1 {
        return Err(CtapMappingError::ParsingError(
            SerdeError::DeserializeUnexpectedEnd,
        ));
    }

    let operation_u8: u8 = data[0];

    let operation = match Operation::try_from(operation_u8) {
        Ok(operation) => operation,
        _ => {
            return Err(CtapMappingError::InvalidCommand(operation_u8));
        }
    };

    // use ctap_types::ctap2::*;
    use ctap_types::authenticator::*;

    match operation {
        Operation::MakeCredential => {
            info!("authenticatorMakeCredential");
            match cbor_deserialize(&data[1..]) {
                Ok(params) => Ok(Request::Ctap2(ctap2::Request::MakeCredential(params))),
                Err(error) => Err(CtapMappingError::ParsingError(error)),
            }
            // TODO: ensure earlier that RPC send queue is empty
        }

        Operation::GetAssertion => {
            info!("authenticatorGetAssertion");

            match cbor_deserialize(&data[1..]) {
                Ok(params) => Ok(Request::Ctap2(ctap2::Request::GetAssertion(params))),
                Err(error) => Err(CtapMappingError::ParsingError(error)),
            }
            // TODO: ensure earlier that RPC send queue is empty
        }

        Operation::GetNextAssertion => {
            info!("authenticatorGetNextAssertion");

            // TODO: ensure earlier that RPC send queue is empty
            Ok(Request::Ctap2(ctap2::Request::GetNextAssertion))
        }

        Operation::CredentialManagement => {
            info!("authenticatorCredentialManagement");

            match cbor_deserialize(&data[1..]) {
                Ok(params) => Ok(Request::Ctap2(ctap2::Request::CredentialManagement(params))),
                Err(error) => Err(CtapMappingError::ParsingError(error)),
            }
            // TODO: ensure earlier that RPC send queue is empty
        }

        Operation::Reset => {
            info!("authenticatorReset");

            // TODO: ensure earlier that RPC send queue is empty
            Ok(Request::Ctap2(ctap2::Request::Reset))
        }

        Operation::GetInfo => {
            info!("authenticatorGetInfo");
            // TODO: ensure earlier that RPC send queue is empty
            Ok(Request::Ctap2(ctap2::Request::GetInfo))
        }

        Operation::ClientPin => {
            info!("authenticatorClientPin");
            match cbor_deserialize(&data[1..]) {
                Ok(params) => Ok(Request::Ctap2(ctap2::Request::ClientPin(params))),
                Err(error) => Err(CtapMappingError::ParsingError(error)),
            }
            // TODO: ensure earlier that RPC send queue is empty
        }

        #[cfg(feature = "enable-fido-2-1")]
        Operation::LargeBlobs => {
            info!("largeBlobs");
            match cbor_deserialize(&data[1..]) {
                Ok(params) => Ok(Request::Ctap2(ctap2::Request::LargeBlobs(params))),
                Err(error) => match error {
                    // As all fields are optional, except offset, only offset can be the culprit here.
                    // In that case, the standard requires us to return "InvalidParameter".
                    SerdeError::SerdeMissingField => Err(CtapMappingError::Custom(
                        AuthenticatorError::InvalidParameter,
                    )),
                    _ => Err(CtapMappingError::ParsingError(error)),
                },
            }
            // TODO: ensure earlier that RPC send queue is empty
        }

        Operation::Vendor(vendor_operation) => {
            info!("authenticatorVendor({:?})", &vendor_operation);

            let vo_u8: u8 = vendor_operation.into();
            if vo_u8 == 0x41 {
                // copy-pasta for now
                match cbor_deserialize(&data[1..]) {
                    Ok(params) => Ok(Request::Ctap2(ctap2::Request::CredentialManagement(params))),
                    Err(error) => Err(CtapMappingError::ParsingError(error)),
                }
                // TODO: ensure earlier that RPC send queue is empty
            } else {
                // TODO: ensure earlier that RPC send queue is empty
                Ok(Request::Ctap2(ctap2::Request::Vendor(vendor_operation)))
            }
        }
        _ => Err(CtapMappingError::InvalidCommand(operation_u8)),
    }
}
