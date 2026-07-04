//! Galois Field GF(2^8) Reed-Solomon (16, 10) Erasure Coding & Asymmetric Symbol Alignment.
//! CHRONOS-SPEC-v7.0 Section 1.4 & 2.2

pub const PRIMITIVE_POLYNOMIAL_MASK_0X1D: u8 = 0x1D;

/// Galois Field GF(2^8) multiplication enforcing primitive reduction mask 0x1D.
#[inline(always)]
pub fn gf_mul_0x1d(mut a: u8, mut b: u8) -> u8 {
    let mut res = 0;
    for _ in 0..8 {
        if (b & 1) != 0 {
            res ^= a;
        }
        let high_bit_set = (a & 0x80) != 0;
        a = (a << 1) & 0xFF;
        if high_bit_set {
            a ^= PRIMITIVE_POLYNOMIAL_MASK_0X1D;
        }
        b >>= 1;
    }
    res
}

/// Galois Field GF(2^8) multiplicative inverse via Fermat's Little Theorem (a^254 in GF(2^8)).
#[inline(always)]
pub fn gf_inv_0x1d(mut a: u8) -> u8 {
    if a == 0 { return 0; }
    let mut res = 1u8;
    let mut exp = 254u32;
    while exp > 0 {
        if (exp & 1) != 0 {
            res = gf_mul_0x1d(res, a);
        }
        a = gf_mul_0x1d(a, a);
        exp >>= 1;
    }
    res
}

/// In-place mathematical zero-padding for asymmetric symbol slices (Pad-to-Max contiguous SIMD alignment).
#[inline(always)]
pub fn align_simd_symbol_slice(slice: &mut [u8], actual_len: usize, max_len: usize) {
    if actual_len < max_len && slice.len() >= max_len {
        let padding_slice = &mut slice[actual_len..max_len];
        padding_slice.fill(0x00);
    }
}

/// Reed-Solomon (16, 10) Galois Field Erasure Encoder & Decoder over GF(2^8).
pub struct ReedSolomon16_10 {
    pub k: usize, // Data shards (10)
    pub n: usize, // Total shards (16)
    pub gen_matrix: Vec<Vec<u8>>,
}

impl ReedSolomon16_10 {
    pub fn new() -> Self {
        let k = 10;
        let n = 16;
        let mut gen_matrix = Vec::with_capacity(n);

        // Build Vandermonde generator matrix over GF(2^8)
        for row in 0..n {
            let mut matrix_row = Vec::with_capacity(k);
            for col in 0..k {
                // Alpha = row + 1, exponent = col
                let mut val = 1u8;
                for _ in 0..col {
                    val = gf_mul_0x1d(val, (row + 1) as u8);
                }
                matrix_row.push(val);
            }
            gen_matrix.push(matrix_row);
        }

        Self { k, n, gen_matrix }
    }

    /// Encode 10 data shards into 16 total shards (10 data + 6 parity).
    pub fn encode(&self, data_shards: &[&[u8]]) -> Result<Vec<Vec<u8>>, String> {
        if data_shards.len() != self.k {
            return Err(format!("Expected {} data shards, got {}", self.k, data_shards.len()));
        }
        let chunk_len = data_shards[0].len();
        for s in data_shards {
            if s.len() != chunk_len {
                return Err("All data shards must have identical byte length".to_string());
            }
        }

        let mut all_shards = Vec::with_capacity(self.n);
        for row in 0..self.n {
            let mut shard = vec![0u8; chunk_len];
            for col in 0..self.k {
                let coef = self.gen_matrix[row][col];
                let d_chunk = data_shards[col];
                for (b_idx, &byte) in d_chunk.iter().enumerate() {
                    shard[b_idx] ^= gf_mul_0x1d(coef, byte);
                }
            }
            all_shards.push(shard);
        }
        Ok(all_shards)
    }

    /// Decode and reconstruct 10 original data shards from any 10 surviving shards out of 16.
    pub fn decode(&self, surviving_shards: &[Option<Vec<u8>>]) -> Result<Vec<Vec<u8>>, String> {
        if surviving_shards.len() != self.n {
            return Err(format!("Expected {} shard options, got {}", self.n, surviving_shards.len()));
        }

        let mut available_indices = Vec::new();
        for (idx, shard) in surviving_shards.iter().enumerate() {
            if shard.is_some() {
                available_indices.push(idx);
                if available_indices.len() == self.k {
                    break;
                }
            }
        }

        if available_indices.len() < self.k {
            return Err(format!("Insufficient shards for reconstruction: found {}, needed {}", available_indices.len(), self.k));
        }

        let chunk_len = surviving_shards[available_indices[0]].as_ref().unwrap().len();

        // Check if we already have the first 10 data shards directly
        if available_indices == (0..self.k).collect::<Vec<_>>() {
            let mut result = Vec::with_capacity(self.k);
            for i in 0..self.k {
                result.push(surviving_shards[i].as_ref().unwrap().clone());
            }
            return Ok(result);
        }

        // Build k x k submatrix for surviving shards and invert via Gaussian elimination over GF(2^8)
        let mut submatrix = Vec::with_capacity(self.k);
        for &row_idx in &available_indices {
            submatrix.push(self.gen_matrix[row_idx].clone());
        }

        let mut inv_matrix = vec![vec![0u8; self.k]; self.k];
        for i in 0..self.k {
            inv_matrix[i][i] = 1;
        }

        for i in 0..self.k {
            let mut pivot_row = i;
            while pivot_row < self.k && submatrix[pivot_row][i] == 0 {
                pivot_row += 1;
            }
            if pivot_row == self.k {
                return Err("Galois submatrix is singular; reconstruction failed".to_string());
            }
            if pivot_row != i {
                submatrix.swap(i, pivot_row);
                inv_matrix.swap(i, pivot_row);
            }

            let pivot = submatrix[i][i];
            let inv_p = gf_inv_0x1d(pivot);
            for j in 0..self.k {
                submatrix[i][j] = gf_mul_0x1d(submatrix[i][j], inv_p);
                inv_matrix[i][j] = gf_mul_0x1d(inv_matrix[i][j], inv_p);
            }

            for r in 0..self.k {
                if r != i && submatrix[r][i] != 0 {
                    let factor = submatrix[r][i];
                    for j in 0..self.k {
                        submatrix[r][j] ^= gf_mul_0x1d(factor, submatrix[i][j]);
                        inv_matrix[r][j] ^= gf_mul_0x1d(factor, inv_matrix[i][j]);
                    }
                }
            }
        }

        // Multiply inverted matrix by surviving shard vectors
        let mut reconstructed = Vec::with_capacity(self.k);
        for row_idx in 0..self.k {
            let mut rec_bytes = vec![0u8; chunk_len];
            for col_idx in 0..self.k {
                let coef = inv_matrix[row_idx][col_idx];
                let s_chunk = surviving_shards[available_indices[col_idx]].as_ref().unwrap();
                for (b_idx, &byte) in s_chunk.iter().enumerate() {
                    rec_bytes[b_idx] ^= gf_mul_0x1d(coef, byte);
                }
            }
            reconstructed.push(rec_bytes);
        }

        Ok(reconstructed)
    }
}

impl Default for ReedSolomon16_10 {
    fn default() -> Self {
        Self::new()
    }
}
