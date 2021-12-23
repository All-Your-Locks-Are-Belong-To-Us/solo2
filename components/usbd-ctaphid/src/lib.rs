#![no_std]

/*!
usbd-ctaphid

See "proposed standard":
https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#usb

*/

#[macro_use]
extern crate delog;
generate_macros!();

// use heapless_bytes as bytes;

// pub mod authenticator;

pub mod class;
pub mod constants;
pub use class::CtapHid;
pub mod pipe;
pub mod types;
