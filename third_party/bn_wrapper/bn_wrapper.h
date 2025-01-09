#ifndef BN_WRAPPER
#define BN_WRAPPER

extern "C" {

// These calls are dependent on Parity's BN lib. ~30 percent faster than libff
uint32_t bn_add_run(const uint8_t *inp, uint8_t *outp);
uint32_t bn_mul_run(const uint8_t *inp, uint8_t *outp);
uint32_t bn_snarkv_run(const uint8_t *inp, const size_t len);

// These calls are dependent on arkworks's lib BN implementation. ~70 percent faster than libff
uint32_t add_run(const uint8_t *inp, uint8_t *outp);
uint32_t mul_run(const uint8_t *inp, uint8_t *outp);
uint32_t snarkv_run(const uint8_t *inp, const size_t len);
uint32_t batch_snarkv_run(const uint8_t *inp, const size_t len);


}  // extern "C"

#endif
