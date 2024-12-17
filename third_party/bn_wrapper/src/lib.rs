// use std::{io::{repeat, Read},};
use std::{io::{Read},};
use bn::{AffineG1, AffineG2, Fq, Fq2, Group, G1, G2, Fr, Gt, pairing};


use ark_bn254::{G1Projective, G1Affine, Fr as Frr, Fq as Fqq};
use ark_std::{UniformRand,vec::Vec};

use ark_ff::{biginteger::BigInt,PrimeField}; // Import BigInt explicitly

use hex::decode;
use std::io::Cursor;

use ark_ff::BigInteger;
use ark_ec::AffineRepr;
// zk sync - ec_mul values

use revm::precompile::bn128::read_point;


fn parse_bn_point(r: &mut impl Read) -> Option<G1> {
    let mut buf = [0; 32];

    r.read_exact(&mut buf).unwrap();
    let x = Fq::from_slice(&buf[..]).ok()?;            
    
    r.read_exact(&mut buf).unwrap();
    let y = Fq::from_slice(&buf[..]).ok()?;
    Some({
        if x.is_zero() && y.is_zero() {
            G1::zero()
        } 
        else {
            AffineG1::new(x, y).ok()?.into()
        }
    })
}

fn parse_point(r: &mut impl Read) -> Option<G1Affine> {
    let mut buf = [0; 32];

    // Convert the bytes to Fq field elements
    r.read_exact(&mut buf).unwrap();
    let x = Fqq::from_be_bytes_mod_order(&buf[..]);

    r.read_exact(&mut buf).unwrap();
    let y = Fqq::from_be_bytes_mod_order(&buf[..]);

    Some(G1Affine::new(x, y))
}

#[unsafe(no_mangle)] pub extern "C" fn bn_mul_run(inp: *const u8, outp: *mut u8) -> u32 {
    unsafe {
        let inp = std::slice::from_raw_parts(inp, 96);
        let mut input = inp;
        let fr = Fr::from_slice(&input[64..96]).unwrap();
        match parse_bn_point(&mut input) {
            None => 2,
            Some(p) => {
                let out = std::slice::from_raw_parts_mut(outp, 64);
                match AffineG1::from_jacobian(p * fr) {
                    None => {
                        out.fill(0);
                        0
                    }
                    Some(mul) => {
                        mul.x().to_big_endian(&mut out[..32]).unwrap();
                        mul.y().to_big_endian(&mut out[32..]).unwrap();
                        0
                    }
                }
            }
        }
    }
}

#[unsafe(no_mangle)] pub extern "C" fn mul_run(inp: *const u8, outp: *mut u8) -> u32 {
    unsafe {
        let inp = std::slice::from_raw_parts(inp, 96);
        let mut input = inp;
        let fr = Frr::from_be_bytes_mod_order(&input[64..96]);

        match parse_point(&mut input) {
            None => 2,
            Some(p) => {
                let out = std::slice::from_raw_parts_mut(outp, 64);
                
                let result = G1Affine::from(p * fr);
                let x_bytes = result.x.into_bigint().to_bytes_be();
                let y_bytes = result.y.into_bigint().to_bytes_be();

                out[0..32].copy_from_slice(&x_bytes); 
                out[32..64].copy_from_slice(&y_bytes); 
                
                0
            }
        }
    }
}

#[unsafe(no_mangle)] pub extern "C" fn bn_add_run(inp: *const u8, outp: *mut u8) -> u32 {
    unsafe {
        let inp = std::slice::from_raw_parts(inp, 128);
        let mut input = inp;
        match parse_bn_point(&mut input) {
            None => 1,
            Some(a) => match parse_bn_point(&mut input) {
                None => 2,
                Some(b) => {
                    let out = std::slice::from_raw_parts_mut(outp, 64);
                    match AffineG1::from_jacobian(a + b) {
                        None => {
                            out.fill(0);
                            0
                        },
                        Some(sum) => {
                            sum.x().to_big_endian(&mut out[..32]).unwrap();
                            sum.y().to_big_endian(&mut out[32..]).unwrap();
                            0
                        }
                    }
                }
            }
        }
    }
}


#[unsafe(no_mangle)] pub extern "C" fn add_run(inp: *const u8, outp: *mut u8) -> u32 {
    unsafe {
        let inp = std::slice::from_raw_parts(inp, 128);
        let mut input = inp;
        match parse_point(&mut input) {
            None => 1,
            Some(a) => match parse_point(&mut input) {
                None => 2,
                Some(b) => {
                    let out = std::slice::from_raw_parts_mut(outp, 64);
                    let result = G1Affine::from(a + b);
                    let x_bytes = result.x.into_bigint().to_bytes_be();
                    let y_bytes = result.y.into_bigint().to_bytes_be();
    
                    out[0..32].copy_from_slice(&x_bytes); 
                    out[32..64].copy_from_slice(&y_bytes); 
                    
                    0
                }
            }
        }
    }
}

pub const SNARKV_STRIDE: usize = 64 + 128;

fn opt_bn_snarkv_run(inp: *const u8, len:usize) -> Option<u32> {

    unsafe {
        let inp = std::slice::from_raw_parts(inp, len);
        let input = inp;
    let k = len / usize::from(SNARKV_STRIDE);
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
#[unsafe(no_mangle)] pub extern "C" fn bn_snarkv_run(inp: *const u8, len:usize) -> u32 {
    match opt_bn_snarkv_run(inp,len) {
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
    use ark_bn254::{G1Projective, G1Affine, Fr as Frr, Fq as Fqq};
    use ark_std::{UniformRand,vec::Vec};

    use ark_ff::{biginteger::BigInt,PrimeField}; // Import BigInt explicitly

    use hex::decode;
    use std::io::Cursor;

    use ark_ff::BigInteger;
    
    // zk sync - ec_mul values

    use revm::precompile::bn128::read_point;


// Function to convert field element to big-endian bytes
fn to_be_bytes_mod_order(field_element: &Fqq)  {

    // Accessing the internal representation of the field element
    let repr = field_element.into_bigint(); // Returns the internal representation
    println!("From the sould yall{:?}",repr.to_bytes_be());
}

    
    
    #[test]
    fn test_G1_affine(){
        // This is a big endian hex slice
        let hex_input = "2cdddce3dbb7a8e7206c2b56b1f0891cdea5dbec8ac4946a015b1cd22e03a1f3270eb5d3ff58cf311016b96a51422004d77f16cea71157a72ee9505e8cf9eff2216b3618ff117720c9eb701ca2547eef411de4cd47115dcde2ce5e0686ac50dc";
        let bytes = decode(hex_input).expect("Invalid hex string");

        // Split into X and Y coordinates (each 32 bytes)
        let x_bytes = &bytes[0..32]; // First 32 bytes
        let y_bytes = &bytes[32..64]; // Next 32 bytes
    
        // Convert the bytes to Fq field elements
        let x = Fqq::from_be_bytes_mod_order(x_bytes);
        let y = Fqq::from_be_bytes_mod_order(y_bytes);
    
        // Create a G1Affine point
        let g1_point = G1Affine::new(x, y); // `false` means the point is not infinity.
        let affine_g1 = G1Affine::from(g1_point + g1_point);

        print!("Dont tell me how{:?}", affine_g1);

        let scalar_bytes = &bytes[64..96]; // Bytes 64-96 for the scalar
        // Convert the scalar bytes to Fr (field element)
        let scalar = Frr::from_be_bytes_mod_order(scalar_bytes);

            // Perform the scalar multiplication (g1_point * scalar)
        let result = g1_point * scalar;
        let affine_g1 = G1Affine::from(result);

        // Print the result of the scalar multiplication in projective
        println!("Result of scalar multiplication: {:?}", affine_g1);

        to_be_bytes_mod_order(&affine_g1.x);
        to_be_bytes_mod_order(&affine_g1.y);

    

    }

    // Check diff between REVM and Brent Implementation 
    #[test]
    fn test_parse_bn_point(){
        
        // This is a big endian hex slice
        let hex_input = "2cdddce3dbb7a8e7206c2b56b1f0891cdea5dbec8ac4946a015b1cd22e03a1f3270eb5d3ff58cf311016b96a51422004d77f16cea71157a72ee9505e8cf9eff2216b3618ff117720c9eb701ca2547eef411de4cd47115dcde2ce5e0686ac50dc";

        let data = hex::decode(hex_input).expect("Failed to decode hex input");
        let sliced_data = &data[..64];
        let mut cursor = Cursor::new(sliced_data);

        // Call Brett Function and get Jacobian Representation 
        let result = parse_bn_point(&mut cursor);
        println!("Jacobian Representation {:?}", result.expect("REASON"));

        let data = hex::decode(hex_input).expect("Failed to decode hex input");
        let sliced_data = &data[..64];
        let mut cursor = Cursor::new(sliced_data);

        // Call Brett function and get Affine Representation 
        let result = parse_bn_point(&mut cursor);
        println!("Affine RRepresentation{:?}", AffineG1::from_jacobian(result.unwrap()));

        // Call REVM function and get Projective Representation 
        let bytes = hex::decode(hex_input).expect("Invalid hex input");
        let point = read_point(&bytes);
        println!("Whats the point {:?}", point);

    }

    #[test]
    fn test_mul_run(){
    // Can call with smaller than 96 wierd yo

    // This is a big endian hex slice
    let mut input = "2cdddce3dbb7a8e7206c2b56b1f0891cdea5dbec8ac4946a015b1cd22e03a1f3270eb5d3ff58cf311016b96a51422004d77f16cea71157a72ee9505e8cf9eff2216b3618ff117720c9eb701ca2547eef411de4cd47115dcde2ce5e0686ac50dc";

    let mut bn_output = [0u8; 64];
    let bn_input_bytes = decode(input.clone()).expect("Invalid hex string");
    let bn_input_ptr = bn_input_bytes.as_ptr();
    let bn_output_ptr = bn_output.as_mut_ptr();

    let mut arc_output = [0u8; 64];
    let arc_input_bytes = decode(input).expect("Invalid hex string");
    let arc_input_ptr = arc_input_bytes.as_ptr();
    let arc_output_ptr = arc_output.as_mut_ptr();

    
    let bn_result = unsafe {
        bn_mul_run(bn_input_ptr, bn_output_ptr)
    };

    let arc_result = unsafe {
        bn_mul_run(arc_input_ptr, arc_output_ptr)
    };

    // 5. Validate the result
    assert_eq!(&arc_output, &bn_output, "Function should return Identical computation");
    }

    #[test]
    fn test_add_run(){

    // This is a big endian hex slice
    let mut input = "0000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000002";

    let mut bn_output = [0u8; 64];
    let bn_input_bytes = decode(input.clone()).expect("Invalid hex string");
    let bn_input_ptr = bn_input_bytes[..64].as_ptr();
    let bn_output_ptr = bn_output.as_mut_ptr();

    let mut arc_output = [0u8; 64];
    let arc_input_bytes = decode(input).expect("Invalid hex string");
    let arc_input_ptr = arc_input_bytes[..64].as_ptr();
    let arc_output_ptr = arc_output.as_mut_ptr();

    
    let bn_result = unsafe {
        bn_add_run(bn_input_ptr, bn_output_ptr)
    };

    let arc_result = unsafe {
        add_run(arc_input_ptr, arc_output_ptr)
    };

    // 5. Validate the result
    assert_eq!(&arc_output, &bn_output, "Function should return Identical computation");

    }   



    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }

    #[test]
    fn bn254_mul() {
        let mut rng = ark_std::test_rng();

        let s = Frr::rand(&mut rng);
        let g = G1Affine::rand(&mut rng);

        let one = BigInt([1, 0, 0, 0]);
        let two = BigInt([2, 0, 0, 0]);
        let one_field_element = Fqq::new(one);
        let two_field_element = Fqq::new(two);
        let affine_example = G1Affine::new(one_field_element, two_field_element); 


        println!("{:?}", s);
        println!("{:?}", g);
        println!("{:?}", g * s);
        println!("field pt x (1,2):{:?}", one_field_element);
        println!("fielid pt y (1,2):{:?}", two_field_element);

        println!("the affine pt (1,2):{:?}", affine_example);
        println!("the curve group rep (1,2):{:?}", G1Projective::from(affine_example));


    }



}
