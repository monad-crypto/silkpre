#ifndef BN_WRAPPER
#define BN_WRAPPER

extern "C" {

uint32_t bn_add_run(const uint8_t *inp, uint8_t *outp);
uint32_t bn_mul_run(const uint8_t *inp, uint8_t *outp);
uint32_t bn_snarkv_run(const uint8_t *inp, const size_t len);

}  // extern "C"

#endif
