
use std::{io::{Read},};
use bn::{AffineG1, AffineG2, Fq, Fq2, Group, G1, G2, Fr, Gt, pairing};
use ark_bn254::{G1Projective, G2Projective, G1Affine, G2Affine, Fr as Frr, Fq as Fqq, Fq2 as Fqq2, Bn254, Fq12};
use ark_ff::{biginteger::BigInt,PrimeField}; 
use hex::decode;
use std::io::Cursor;
use ark_ff::BigInteger;
use ark_ec::AffineRepr;
use ark_ec::{pairing::Pairing};
use ark_std::One;
use ark_std::Zero;
use revm::precompile::bn128::read_point;
use ark_ec::pairing::MillerLoopOutput;
use ark_std::ops::Mul;
use ark_bn254::Fq12Config;
use ark_ff::QuadExtField;
use ark_ff::Fp12ConfigWrapper;

// BN version of parsing point
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
// Arkworks version of parsing point
fn parse_point(r: &mut impl Read) -> Option<G1Affine> {
    let mut buf = [0; 32];

    // Convert the bytes to Fq field elements
    r.read_exact(&mut buf).unwrap();
    let x = Fqq::from_be_bytes_mod_order(&buf[..]);

    r.read_exact(&mut buf).unwrap();
    let y = Fqq::from_be_bytes_mod_order(&buf[..]);

    Some({
        if x.is_zero() && y.is_zero() {
            G1Affine::zero()
        } 
        else {
            G1Affine::new(x, y)
        }
    })

}

// BN scalar multiplication 
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

// arkworks scalar multiplication
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
// bn addition
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
// arkworks addition
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

//bn pairing operation
pub const SNARKV_STRIDE: usize = 64 + 128;
fn opt_bn_snarkv_run(inp: *const u8, len:usize) -> Option<u32> {

    unsafe {
        let inp = std::slice::from_raw_parts(inp, len);
        let input = inp;
        let k = len / usize::from(SNARKV_STRIDE);
        
        let mut points = Vec::with_capacity(k);
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
            points.push((a, b))
        }
        let mul = bn::pairing_batch(&points);
        if mul == Gt::one() { Some(1) } else { Some(0) }
//    Some(ret_val.to_be_bytes().to_vec().into())
    }
}

// arkworks pairing
fn opt_snarkv_run(inp: *const u8, len:usize) -> Option<u32> {
    unsafe {
        let inp = std::slice::from_raw_parts(inp, len);
        let input = inp;
        let k = len / usize::from(SNARKV_STRIDE);
       
        //find this
        //let mut mul = Gt::one();
        let mut mul = Fq12::one();
        for i in 0..k {
            let a_x = Fqq::from_be_bytes_mod_order(&input[i * 192..i * 192 + 32]);
            let a_y = Fqq::from_be_bytes_mod_order(&input[i * 192 + 32..i * 192 + 64]);
           
            //elements in Fq2
            // In the form C_1 + C_2 * X
            let b_a_y = Fqq::from_be_bytes_mod_order(&input[i * 192 + 64..i * 192 + 96]);
            let b_a_x = Fqq::from_be_bytes_mod_order(&input[i * 192 + 96..i * 192 + 128]);
           
            // In the form C_1 + C_2 * X
            let b_b_y = Fqq::from_be_bytes_mod_order(&input[i * 192 + 128..i * 192 + 160]);
            let b_b_x = Fqq::from_be_bytes_mod_order(&input[i * 192 + 160..i * 192 + 192]);
           
            //find this
            let b_a = Fqq2::new(b_a_x,b_a_y);
            let b_b = Fqq2::new(b_b_x,b_b_y);
           
            let b = if b_a.is_zero() && b_b.is_zero() {
                G2Projective::zero()
            } else {
                G2Projective::from(G2Affine::new(b_a, b_b))
            };
 
 
            let a = if a_x.is_zero() && a_y.is_zero() {
                G1Projective::zero()
            } else {
                G1Projective::from(G1Affine::new(a_x, a_y))
            };
           
                mul = mul * Bn254::pairing(a,b).0;
           
        }
        if mul == Fq12::one() { Some(1) } else { Some(0) }
    }
 }
 
 // arkworks batched pairing algo
 fn opt_optimize_snarkv_run(inp: *const u8, len:usize) -> Option<u32> {
    unsafe {
        let inp = std::slice::from_raw_parts(inp, len);
        let input = inp;
        let k = len / usize::from(SNARKV_STRIDE);
        //let mut target_group_elements = Vec::with_capacity(k);

        let mut g1_points = Vec::with_capacity(k);
        let mut g2_points = Vec::with_capacity(k);

        for i in 0..k {
            let a_x = Fqq::from_be_bytes_mod_order(&input[i * 192..i * 192 + 32]);
            let a_y = Fqq::from_be_bytes_mod_order(&input[i * 192 + 32..i * 192 + 64]);
           
            //elements in Fq2
            // In the form C_1 + C_2 * X
            let b_a_y = Fqq::from_be_bytes_mod_order(&input[i * 192 + 64..i * 192 + 96]);
            let b_a_x = Fqq::from_be_bytes_mod_order(&input[i * 192 + 96..i * 192 + 128]);
           
            // In the form C_1 + C_2 * X
            let b_b_y = Fqq::from_be_bytes_mod_order(&input[i * 192 + 128..i * 192 + 160]);
            let b_b_x = Fqq::from_be_bytes_mod_order(&input[i * 192 + 160..i * 192 + 192]);
           
            //find this
            let b_a = Fqq2::new(b_a_x,b_a_y);
            let b_b = Fqq2::new(b_b_x,b_b_y);
           
            let b = if b_a.is_zero() && b_b.is_zero() {
                G2Projective::zero()
            } else {
                G2Projective::from(G2Affine::new(b_a, b_b))
            };
 
 
            let a = if a_x.is_zero() && a_y.is_zero() {
                G1Projective::zero()
            } else {
                G1Projective::from(G1Affine::new(a_x, a_y))
            };
           
            g1_points.push(a);
            g2_points.push(b);

        }
        
        let result = Bn254::multi_pairing(g1_points,g2_points);
        if result.0 == Fq12::one() { Some(1) } else { Some(0) }
    }
 }
 
// bn pairing interface
#[unsafe(no_mangle)] pub extern "C" fn bn_snarkv_run(inp: *const u8, len:usize) -> u32 {
    match opt_bn_snarkv_run(inp,len) {
        None => 2,
        Some(x) => x

     }
}
// arkworks pairing interface
#[unsafe(no_mangle)] pub extern "C" fn snarkv_run(inp: *const u8, len:usize) -> u32 {
    match opt_snarkv_run(inp,len) {
        None => 2,
        Some(x) => x

     }
}
// arkworks batched pairing interface
#[unsafe(no_mangle)] pub extern "C" fn batch_snarkv_run(inp: *const u8, len:usize) -> u32 {
    match opt_optimize_snarkv_run(inp,len) {
        None => 2,
        Some(x) => x

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
    use revm::precompile::bn128::read_point;
    use revm::precompile::bn128::run_pair;



// Function to convert field element to big-endian bytes
fn to_be_bytes_mod_order(field_element: &Fqq)  {

    // Accessing the internal representation of the field element
    let repr = field_element.into_bigint(); // Returns the internal representation
    //println!("From the sould yall{:?}",repr.to_bytes_be());
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

        //print!("Dont tell me how{:?}", affine_g1);

        let scalar_bytes = &bytes[64..96]; // Bytes 64-96 for the scalar
        // Convert the scalar bytes to Fr (field element)
        let scalar = Frr::from_be_bytes_mod_order(scalar_bytes);

            // Perform the scalar multiplication (g1_point * scalar)
        let result = g1_point * scalar;
        let affine_g1 = G1Affine::from(result);

        // Print the result of the scalar multiplication in projective
        //println!("Result of scalar multiplication: {:?}", affine_g1);

        //to_be_bytes_mod_order(&affine_g1.x);
        //to_be_bytes_mod_order(&affine_g1.y);

    

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
        //println!("Jacobian Representation {:?}", result.expect("REASON"));

        let data = hex::decode(hex_input).expect("Failed to decode hex input");
        let sliced_data = &data[..64];
        let mut cursor = Cursor::new(sliced_data);

        // Call Brett function and get Affine Representation 
        let result = parse_bn_point(&mut cursor);
        //println!("Affine RRepresentation{:?}", AffineG1::from_jacobian(result.unwrap()));

        // Call REVM function and get Projective Representation 
        let bytes = hex::decode(hex_input).expect("Invalid hex input");
        let point = read_point(&bytes);
        //println!("Whats the point {:?}", point);

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
   fn test_pairing_run(){


   // This is a big endian hex slice
   let input = concat!(
    "0f25929bcb43d5a57391564615c9e70a992b10eafa4db109709649cf48c50dd216da2f5cb6be7a0aa72c440c53c9",
    "bbdfec6c36c7d515536431b3a865468acbba2e89718ad33c8bed92e210e81d1853435399a271913a6520736a4729",
    "cf0d51eb01a9e2ffa2e92599b68e44de5bcf354fa2642bd4f26b259daa6f7ce3ed57aeb314a9a87b789a58af499b",
    "314e13c3d65bede56c07ea2d418d6874857b70763713178fb49a2d6cd347dc58973ff49613a20757d0fcc22079f9",
    "abd10c3baee245901b9e027bd5cfc2cb5db82d4dc9677ac795ec500ecd47deee3b5da006d6d049b811d7511c7815",
    "8de484232fc68daf8a45cf217d1c2fae693ff5871e8752d73b21198e9393920d483a7260bfb731fb5d25f1aa4933",
    "35a9e71297e485b7aef312c21800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed0906",
    "89d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b12c85ea5db8c6deb4aab71808dcb408f",
    "e3d1e7690c43d37b4ce6cc0166fa7daa"
    );
    let input = concat!(
        "00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000",
        "000000000000000000000000000000000002198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7",
        "aef312c21800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed090689d0585ff075ec9e",
        "99ad690c3395bc4b313370b38ef355acdadcd122975b12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b",
        "4ce6cc0166fa7daa"
    );
   let mut bn_output = [0u8; 64];
   let bn_input_bytes = decode(input).expect("Invalid hex string");
   let bn_input_ptr = bn_input_bytes.as_ptr();
   let bn_output_ptr = bn_output.as_mut_ptr();


   let mut ark_output = [0u8; 64];
   let ark_input_bytes = decode(input).expect("Invalid hex string");
   let ark_input_ptr = ark_input_bytes.as_ptr();
   let ark_output_ptr = ark_output.as_mut_ptr();

   let mut output = [0u8; 64];
   let bytes = hex::decode(input).expect("Invalid hex input");
   let results = run_pair(&bytes,1000,10000,1000000000);
      
   let bn_result = opt_bn_snarkv_run(bn_input_ptr, bn_input_bytes.len());
   let ac_result = opt_snarkv_run(ark_input_ptr, ark_input_bytes.len());
   let ac_result = opt_optimize_snarkv_run(ark_input_ptr, ark_input_bytes.len());



   println!("BN Pairing{:?}",&bn_output);
   println!("Arc Pairing{:?}",&ark_output);

   println!("BN Pairing Result {:?}",&ac_result);
   println!("Arc Pairing Result {:?}",&bn_result);
   println!("REVM Pairing Result {:?}",&results);


   // 5. Validate the result
   assert_eq!(&ark_output, &bn_output, "Function should return Identical computation");


   }





}
