use dusk_bls12_381::{BlsScalar, GENERATOR};
use dusk_bytes::{Error as DuskBytesError, Serializable};
use ff::Field;
use rand_core::{CryptoRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

#[cfg(feature = "rkyv-impl")]
use rkyv::{Archive, Deserialize, Serialize};

#[derive(Default, Clone, Debug, Eq, PartialEq, Zeroize)]
#[cfg_attr(
    feature = "rkyv-impl",
    derive(Archive, Deserialize, Serialize),
    archive_attr(derive(bytecheck::CheckBytes))
)]
pub struct SecretKey(pub(crate) BlsScalar);

impl From<BlsScalar> for SecretKey {
    fn from(s: BlsScalar) -> SecretKey {
        SecretKey(s)
    }
}

impl From<&BlsScalar> for SecretKey {
    fn from(s: &BlsScalar) -> SecretKey {
        SecretKey(*s)
    }
}

impl AsRef<SecretKey> for SecretKey {
    fn as_ref(&self) -> &SecretKey {
        &self
    }
}

impl SecretKey {
    /// Generates a new random [`SecretKey`] from a [`BlsScalar].
    pub fn random<T>(rand: &mut T) -> Self
    where
        T: RngCore + CryptoRng,
    {
        Self(BlsScalar::random(&mut *rand))
    }
}

impl Serializable<32> for SecretKey {
    type Error = DuskBytesError;

    fn to_bytes(&self) -> [u8; Self::SIZE] {
        self.0.to_bytes()
    }

    fn from_bytes(bytes: &[u8; Self::SIZE]) -> Result<Self, Self::Error> {
        let secret_key = match BlsScalar::from_bytes(bytes).into() {
            Some(sk) => sk,
            None => return Err(DuskBytesError::InvalidData),
        };
        Ok(Self(secret_key))
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        unsafe {
            println!(
                "before {:?} {:?}",
                core::ptr::addr_of!(self),
                *core::ptr::addr_of!(self)
            );
        }

        println!("calling zeroize in drop");
        let r = self.zeroize();
        //self.0 = BlsScalar::from(GENERATOR);
        unsafe {
            println!(
                "{:?} {:?}",
                core::ptr::addr_of!(self),
                *core::ptr::addr_of!(self)
            );
        }

        println!("{:?}", self.0);
    }
}

fn bls_scalar_42() -> [u64; 4] {
    [
        395136991140,
        16706400699492528220,
        10895998725622488597,
        6239700025071827469,
    ]
}

#[test]
fn f_empty_test() {
    struct Empty;

    impl Drop for Empty {
        fn drop(&mut self) {
            println!("drop {:?}", core::ptr::addr_of!(self));
        }
    }

    let empty = Empty;
    let ptr = core::ptr::addr_of!(empty);
    drop(empty);
    println!("after drop {:?}", ptr);
}

#[test]
//cargo test zeroize_drop_test -- --show-output
fn f_zeroize_drop_test() {
    // Let's try again and don't call drop or zeroize
    let ptr;
    {
        let mut sk = SecretKey::from(BlsScalar::from(42));

        ptr = &sk as *const SecretKey;
        sk.zeroize();
        // drop(sk);
        unsafe {
            println!(
                "sK = {:?} \n ptr[{:?}] = {:?}",
                /* sk */ 1, ptr, *ptr
            );
        }
        println!("exiting scope");
    }

    // now the memory is zeroed
    /*unsafe {
        println!("ptr = {:?}", *ptr);
        assert_eq!(
            core::slice::from_raw_parts(ptr, 4),
            [0; 4],
            "We expect the memory to be zeroed"
        );
    };*/
}

/*
#[test]
fn a_zeroize_drop_test() {
    let ptr;

    {
        let sk = SecretKey::from(BlsScalar::from(42));
        // create raw pointer to sk in memory
        let ptr = sk.as_ref().0.as_ptr();
        println!("case 1");
        drop(sk);

        // The memory is still there
        assert_eq!(
            unsafe { core::slice::from_raw_parts(ptr, 4) },
            bls_scalar_42()
        );
    }

    // We would expect that the memory is erased during `drop` but it is
    // still there.
    // Even after going out of scope, the memory is still there.
    unsafe {
        assert_eq!(core::slice::from_raw_parts(ptr, 4), BlsScalar::from(42).0);
    };
}

#[test]
fn b_zeroize_drop_test() {
    // Let's try again and call zeroize explicitly but not drop
    let ptr;
    {
        let mut sk = SecretKey::from(BlsScalar::from(42));
        let ptr = sk.as_ref().0.as_ptr();
        sk.zeroize();
    }

    // now the memory is zeroed
    unsafe {
        assert_eq!(core::slice::from_raw_parts(ptr, 4), [0; 4]);
    };
}
*/
