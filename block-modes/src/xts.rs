extern crate byteorder;

use core::marker::PhantomData;

use self::byteorder::{LE, ByteOrder};
use traits::{BlockMode, BlockModeError};
use block_padding::Padding;
use block_cipher_trait::BlockCipher;
use block_cipher_trait::generic_array::{GenericArray, ArrayLength};
use block_cipher_trait::generic_array::typenum::U16;
use utils::xor;

fn align_down(a: usize, align: usize) -> usize {
     a & !(align - 1)
}

pub struct Xts128<C, P>
where
    C: BlockCipher<BlockSize = U16>,
    P: Padding,
    C::ParBlocks: ArrayLength<GenericArray<u8, U16>>,
{
    cipher1: C,
    cipher2: C,
    tweak: GenericArray<u8, C::BlockSize>,
    _p: PhantomData<P>
}

impl<C, P> Xts128<C, P>
where
    C: BlockCipher<BlockSize = U16>,
    P: Padding,
    C::ParBlocks: ArrayLength<GenericArray<u8, U16>>,
{
    pub fn new(cipher1: C, cipher2: C, nonce: &GenericArray<u8, C::BlockSize>) -> Self {
        Self {
            cipher1,
            cipher2,
            tweak: nonce.clone(),
            _p: PhantomData
        }
    }

    fn gf128mul_x_ble(&mut self) {
        let a = LE::read_u64(&self.tweak[0..8]);
        let b = LE::read_u64(&self.tweak[8..16]);
        let ra = (a << 1) ^ 0x0087 >> (8 - ( ( b >> 63 ) << 3 ) );
        let rb = (a >> 63) | (b << 1);
        LE::write_u64(&mut self.tweak[0..8], ra);
        LE::write_u64(&mut self.tweak[8..16], rb);
    }


    fn process(&mut self, buffer: &mut [u8], enc: bool) -> Result<(), BlockModeError> {
        assert!(buffer.len() >= 16, "XTS mode needs at least a single full block");

        let mut scratch = GenericArray::clone_from_slice(&[0; 16]);
        let mut prev_tweak = None;

        // First, compute the tweak.
        self.cipher2.encrypt_block(&mut self.tweak);

        for i in (0..buffer.len()).step_by(16) {
            if i == align_down(buffer.len(), 16) && !enc && buffer.len() % 16 != 0 {
                // We are on the last block in a decrypt operation that has
                // leftover bytes, so we need to use the next tweak for this
                // block, and this tweak for the leftover bytes. Save the current
                // tweak for the leftovers and then update the current tweak for
                // use on this, the last full block.
                prev_tweak = Some(self.tweak);
                self.gf128mul_x_ble();
            }

            scratch.copy_from_slice(&buffer[i..i + 16]);
            xor(&mut scratch, &self.tweak);

            if enc {
                self.cipher1.encrypt_block(&mut scratch);
            } else {
                self.cipher1.decrypt_block(&mut scratch);
            }

            xor(&mut scratch, &self.tweak);
            buffer[i..i + 16].copy_from_slice(&scratch);

            /* Update tweak for next block */
            self.gf128mul_x_ble();
        }

        if buffer.len() % 16 != 0 {
            // Leftover handling.
            // If we are on the leftover bytes in a decrypt operation, we need to
            // use the previous tweak for these bytes (as saved in prev_tweak).
            let tweak = if enc {
                self.tweak
            } else {
                prev_tweak.expect("Previous tweak to be saved for leftover decryption")
            };

            // We are now on the final part of the data unit, which doesn't
            // divide evenly by 16. It's time for ciphertext stealing.
            let leftovers = buffer.len() % 16;
            let prev_output = align_down(buffer.len(), 16) - 16;
            let cur_output = align_down(buffer.len(), 16);

            // Copy ciphertext bytes from the previous block to our output for
            // each byte of ciphertext we won't steal. At the same time, copy the
            // remainder of the input for this final round (since the loop bounds
            // are the same).
            scratch[..leftovers].copy_from_slice(&buffer[cur_output..]);
            xor(&mut scratch[..leftovers], &tweak);
            for i in 0..leftovers {
                buffer[cur_output + i] = buffer[prev_output + i];
            }

            // Copy ciphertext bytes from the previous block for input in this
            // round.
            for i in leftovers..16 {
                scratch[i] = buffer[prev_output + i] ^ tweak[i];
            }

            if enc {
                self.cipher1.encrypt_block(&mut scratch);
            } else {
                self.cipher1.decrypt_block(&mut scratch);
            }

            // Write the result back to the previous block, overriding the
            // previous output we copied.
            buffer[prev_output..prev_output + 16].copy_from_slice(&scratch);
            xor(&mut buffer[prev_output..prev_output + 16], &tweak);
        }

        Ok(())
    }
}

impl<C, P> BlockMode<C, P> for Xts128<C, P>
where
    C: BlockCipher<BlockSize = U16>,
    P: Padding,
    C::ParBlocks: ArrayLength<GenericArray<u8, U16>>
{
    fn encrypt_nopad(&mut self, buffer: &mut [u8]) -> Result<(), BlockModeError> {
        self.process(buffer, true)
    }

    fn decrypt_nopad(&mut self, buffer: &mut [u8]) -> Result<(), BlockModeError> {
        self.process(buffer, false)
    }
}
