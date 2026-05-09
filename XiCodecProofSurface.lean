import Std

/-
Xi Codec v0 proof surface.
This attacks the byte-level reconstruction laws used by xi_codec_v0.py.
No external compression theorem is claimed here; zlib is treated as a lossless
payload container outside this Lean surface.
-/

namespace XiCodecV0

abbrev Byte := BitVec 8

def xorResidual (x p : Byte) : Byte := x ^^^ p

def xorRecover (r p : Byte) : Byte := r ^^^ p

def subResidual (x p : Byte) : Byte := x - p

def subRecover (r p : Byte) : Byte := r + p

-- Mode 1: residual = x XOR projection; recover = residual XOR projection.
theorem xor_roundtrip (x p : Byte) : xorRecover (xorResidual x p) p = x := by
  bv_decide

-- Mode 2: residual = x - projection mod 256; recover = residual + projection mod 256.
theorem sub_roundtrip (x p : Byte) : subRecover (subResidual x p) p = x := by
  bv_decide

-- Mode 3: direct projection stores no payload; reconstruction is the projection itself.
theorem direct_projection_roundtrip (p : Byte) : p = p := by
  rfl

-- Per-byte equality implies a block-level pointwise roundtrip for the transformed byte at any index.
theorem xor_block_pointwise (x p : Nat → Byte) (i : Nat) :
    xorRecover (xorResidual (x i) (p i)) (p i) = x i := by
  exact xor_roundtrip (x i) (p i)

theorem sub_block_pointwise (x p : Nat → Byte) (i : Nat) :
    subRecover (subResidual (x i) (p i)) (p i) = x i := by
  exact sub_roundtrip (x i) (p i)

end XiCodecV0
