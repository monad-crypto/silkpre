// use std::{io::{repeat, Read},};
use std::{io::{Read},};
use bn::{AffineG1, AffineG2, Fq, Fq2, Group, G1, G2, Fr, Gt, pairing};

fn parse_bn_point(r: &mut impl Read) -> Option<G1> {
            let mut buf = [0; 32];

                r.read_exact(&mut buf).unwrap();
                    let x = Fq::from_slice(&buf[..]).ok()?;

                        r.read_exact(&mut buf).unwrap();
                            let y = Fq::from_slice(&buf[..]).ok()?;

                                Some({
                                            if x.is_zero() && y.is_zero() {
                                                            G1::zero()
                                                                        } else {
   AffineG1::new(x, y).ok()?.into()
               }
                                                })
}

#[unsafe(no_mangle)] pub extern "C" fn bn_mul_run(inp: *const u8, outp: *mut u8) -> u32 {
    unsafe {
        let inp = std::slice::from_raw_parts(inp, 96);
// println!("{:?}", inp);
        // let mut input = Read::chain(inp, repeat(0));
        let mut input = inp;
        let fr = Fr::from_slice(&input[64..96]).unwrap();
        match parse_bn_point(&mut input) {
                None => 2,
                Some(p) => 
                {
                    let out = std::slice::from_raw_parts_mut(outp, 64);
                    match AffineG1::from_jacobian(p * fr) {
                        None => 3,
                        Some(mul) => {
                                    mul.x().to_big_endian(&mut out[..32]).unwrap();
                                    mul.y().to_big_endian(&mut out[32..]).unwrap();
                           // Some(out.to_vec().into()) // BAL: not needed(?)
                                    0
                        }
                    }
                }
        }
    }
}
#[unsafe(no_mangle)] pub extern "C" fn bn_add_run(inp: *const u8, outp: *mut u8) -> u32 {
    unsafe {
        let inp = std::slice::from_raw_parts(inp, 128);
// println!("{:?}", inp);
        // let mut input = Read::chain(inp, repeat(0));
        let mut input = inp;
        match parse_bn_point(&mut input) {
            None => 1,
            Some(a) => match parse_bn_point(&mut input) {
                None => 2,
                Some(b) => 
                {
                    let out = std::slice::from_raw_parts_mut(outp, 64);
                    match AffineG1::from_jacobian(a + b) {
                        None => 3,
                        Some(sum) => {
                                    sum.x().to_big_endian(&mut out[..32]).unwrap();
                                    sum.y().to_big_endian(&mut out[32..]).unwrap();
                           // Some(out.to_vec().into()) // BAL: not needed(?)
                                    0
                        }
                    }
                }
            }
        }
    }
}
pub const SNARKV_STRIDE: usize = 64 + 128;

fn opt_bn_snarkv_run(inp: *const u8) -> Option<u32> {

    unsafe {
        let inp = std::slice::from_raw_parts(inp, 384);
        let input = inp;
    let k = 384 / usize::from(SNARKV_STRIDE);
        let mut mul = Gt::one();
        for i in 0..k {
            let a_x = Fq::from_slice(&input[i * 192..i * 192 + 32]).ok()?;
            let a_y = Fq::from_slice(&input[i * 192 + 32..i * 192 + 64]).ok()?;
            let b_a_y = Fq::from_slice(&input[i * 192 + 64..i * 192 + 96]).ok()?;
            let b_a_x = Fq::from_slice(&input[i * 192 + 96..i * 192 + 128]).ok()?;
            let b_b_y = Fq::from_slice(&input[i * 192 + 128..i * 192 + 160]).ok()?;
            let b_b_x = Fq::from_slice(&input[i * 192 + 160..i * 192 + 192]).ok()?;
            let b_a = Fq2::new(b_a_x, b_a_y);
            let b_b = Fq2::new(b_b_x, b_b_y);
            let b = if b_a.is_zero() && b_b.is_zero() {
                G2::zero()
            } else {
                G2::from(AffineG2::new(b_a, b_b).ok()?)
            };
            let a = if a_x.is_zero() && a_y.is_zero() {
                G1::zero()
            } else {
                G1::from(AffineG1::new(a_x, a_y).ok()?)
            };
            mul = mul * pairing(a, b);
        }
        if mul == Gt::one() { Some(1) } else { Some(0) }
//    Some(ret_val.to_be_bytes().to_vec().into())
    }
}

// #[unsafe(no_mangle)] pub extern "C" fn bn_snarkv_run(inp: *const u8, outp: *mut u8) -> u32 {
#[unsafe(no_mangle)] pub extern "C" fn bn_snarkv_run(inp: *const u8) -> u32 {
    match opt_bn_snarkv_run(inp) {
        None => 2,
        Some(x) => x
//     {
//                     let out = std::slice::from_raw_parts_mut(outp, 32);
// //    out = U256::as_I256(x); // as U256;
//                                     x().to_big_endian(&mut out[..32]).unwrap();
//         0
//     }
     }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}
