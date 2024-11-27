use std::{io::{repeat, Read},};
use bn::{AffineG1, Fq, Group, G1};

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

#[unsafe(no_mangle)] pub extern "C" fn bn_add_run(inp: *const u8, outp: *mut u8) -> u32 {
    unsafe {
        let inp = std::slice::from_raw_parts(inp, 128);
// println!("{:?}", inp);
        let mut input = Read::chain(inp, repeat(0));
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


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}
