//! At rest encryption of sensitive data.
//!
//! This implementation is based heavily on sequoia's implementation of protected memory. See
//! [here](https://gitlab.com/sequoia-pgp/sequoia/openpgp/src/crypto/mem.rs).

use std::cmp::min;
use std::fmt;
use std::ops::{Deref, DerefMut};
use crate::error::Error;

pub struct Protected {
    data: *mut [u8]
}

unsafe impl Send for Protected {}
unsafe impl Sync for Protected {}

impl Clone for Protected {
    fn clone (&self) -> Protected {
	self.as_ref().to_vec().into()
    }
}

impl Deref for Protected {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
	unsafe { &*self.data }
    }
}


impl DerefMut for Protected {
    fn deref_mut(&mut self) -> &mut Self::Target {
	unsafe { &mut *self.data }
    }
}

impl<T> From<T> for Protected
where
    T: AsMut<[u8]>
{
    fn from(mut source: T) -> Protected {
	let data: Vec<u8> = source.as_mut().to_vec();

	unsafe {
	    memsec::memzero(source.as_mut().as_mut_ptr(), source.as_mut().len())
	}
	
	Protected {
	    data: Box::leak(data.into_boxed_slice())
	}
    }
}

impl Drop for Protected {
    fn drop(&mut self) {
	let len = self.len();
	unsafe {
	    memsec::memzero(self.as_mut().as_mut_ptr(), len);
	    Box::from_raw(self.data);
	}
    }
}

impl PartialEq for Protected {
    fn eq(&self, other: &Protected) -> bool {
	unsafe {
	    memsec::memcmp(self.as_ptr(), other.as_ptr(), min(self.len(), other.len())) == 0
	}
    }
}

impl Eq for Protected {}

impl fmt::Debug for Protected {
    #[cfg(debug_assertions)]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
	write!(f, "{:?}", self.as_ref())
    }
    
    #[cfg(not(debug_assertions))]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
	write!(f, "[REDACTED]", self.as_ref())
    }
}

#[derive(Debug)]
#[derive(Clone)]
pub struct Encrypted {
    data: Protected,
    salt: Protected
}

const ENCRYPTED_MEMORY_PREKEY_PAGES: usize = 4;
const ENCRYPTED_MEMORY_PAGE_SIZE: usize = 4096;

lazy_static::lazy_static! {
    static ref PREKEY: Box<[Box<[u8]>]> = {
        let mut pages = Vec::new();
        for _ in 0..ENCRYPTED_MEMORY_PREKEY_PAGES {
	    let mut page = vec![0; ENCRYPTED_MEMORY_PAGE_SIZE];
	    openssl::rand::rand_bytes(&mut page).unwrap();
	    pages.push(page.into());
        }
        pages.into()
    };
}

impl Encrypted {
    pub fn new<T, U>(plaintext: T, salt: U) -> Encrypted
    where
	T: Into<Protected>,
	U: Into<Protected>
    {
	let plaintext = plaintext.into();
	let salt = salt.into();
	
	let mut auth_tag: Protected = [0; 16].into();
	
	let mut data = openssl::symm::encrypt_aead(
	    openssl::symm::Cipher::aes_256_gcm(),
	    &derive_private_key(&salt),
	    Some(&salt),
	    &[],
	    &plaintext,
	    &mut auth_tag
	).unwrap();
	
	data.extend_from_slice(&mut auth_tag);
	
	Encrypted {
	    data: data.into(),
	    salt
	}
    }

    pub fn map_cipher<F, R>(&self, mut f: F) -> R
    where
	F: FnMut(&[u8]) -> R
    {
	f(&self.data)
    }

    pub fn map<F, R> (&self, mut f: F) -> Result<R, Error>
    where
	F: FnMut(&[u8]) -> R
    {
	let plaintext: Protected = openssl::symm::decrypt_aead(
	    openssl::symm::Cipher::aes_256_gcm(),
	    &derive_private_key(&self.salt),
	    Some(&self.salt),
	    &[],
	    &self.data[..self.data.len()-16],
	    &self.data[self.data.len()-16..]
	)
	    .map_err(|e| Error::Crypto(e.to_string()))?
	    .into();
	
	Ok(f(&plaintext))
    }
}

impl PartialEq for Encrypted {
    fn eq(&self, other: &Encrypted) -> bool {
	self.data == other.data
    }
}

fn derive_private_key(salt: &[u8]) -> Protected {
    let mut hasher = openssl::sha::Sha256::new();
    hasher.update(&salt[..]);
    PREKEY.iter().for_each(|block| hasher.update(&block[..]));
    hasher.finish().into()
}


fn random_salt() -> [u8; 32] {
    let mut salt = [0; 32];
    openssl::rand::rand_bytes(&mut salt).unwrap();
    salt
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn comparison_of_protected_data () {
	assert_eq!(Protected::from([1,2,3]),
		   Protected::from([1,2,3]));
	assert_ne!(Protected::from([4,5,6]),
		   Protected::from([7,8,9]));
    }

    #[test]
    fn encryption_and_decryption_work () {
	let encrypted = Encrypted::new([1,2,3], random_salt());
	println!("Encrypted data: {:?}", encrypted);
	encrypted.map_cipher(|ciphertext| assert_ne!(ciphertext, [1,2,3]));
	encrypted.map(|plaintext| assert_eq!(plaintext, [1,2,3]))
	    .expect("Failed to decrypt data");
    }
}
