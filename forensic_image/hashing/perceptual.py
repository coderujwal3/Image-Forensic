"""Perceptual hashing implementations for visual similarity fingerprinting.

IMPORTANT FORENSIC DISTINCTION:
Cryptographic hashes (SHA-256) prove EXACT BYTE IDENTITY.
Perceptual hashes (aHash, dHash, pHash, wHash) assess VISUAL SIMILARITY.
They tolerate re-encoding, minor compression, or metadata removal.
They must NEVER be used as proof that two files are byte-for-byte identical.
"""

from typing import Dict, Optional, Tuple, Union
import numpy as np
from PIL import Image
from pydantic import BaseModel, Field
from scipy.fftpack import dct


class PerceptualHashes(BaseModel):
    """Collection of perceptual fingerprints representing visual characteristics."""
    ahash: Optional[str] = Field(default=None, description="Average Hash (64-bit hex)")
    dhash: Optional[str] = Field(default=None, description="Difference Hash (64-bit hex)")
    phash: Optional[str] = Field(default=None, description="DCT Perceptual Hash (64-bit hex)")
    whash: Optional[str] = Field(default=None, description="Wavelet / Gradient Hash (64-bit hex)")

    def to_dict(self) -> Dict[str, Optional[str]]:
        return {
            "ahash": self.ahash,
            "dhash": self.dhash,
            "phash": self.phash,
            "whash": self.whash,
        }


def _binary_array_to_hex(arr: np.ndarray) -> str:
    """Converts a 1D boolean numpy array to a hexadecimal string."""
    bit_str = "".join(["1" if b else "0" for b in arr.flatten()])
    # Convert to hex string padded to full length
    hex_len = len(bit_str) // 4
    num = int(bit_str, 2)
    return f"{num:0{hex_len}x}"


def compute_ahash(image: Image.Image, hash_size: int = 8) -> str:
    """Average Hash (aHash).
    
    1. Reduce size to hash_size x hash_size (default 8x8)
    2. Convert to grayscale
    3. Compute mean luminance
    4. Set bit to 1 if pixel >= mean, else 0
    """
    img = image.convert("L").resize((hash_size, hash_size), Image.Resampling.LANCZOS)
    pixels = np.asarray(img, dtype=np.float32)
    avg = np.mean(pixels)
    diff = pixels >= avg
    return _binary_array_to_hex(diff)


def compute_dhash(image: Image.Image, hash_size: int = 8) -> str:
    """Difference Hash (dHash).
    
    1. Reduce size to (hash_size + 1) x hash_size (e.g. 9x8)
    2. Convert to grayscale
    3. Compare adjacent horizontal pixels (P[x] > P[x+1])
    """
    img = image.convert("L").resize((hash_size + 1, hash_size), Image.Resampling.LANCZOS)
    pixels = np.asarray(img, dtype=np.float32)
    diff = pixels[:, 1:] > pixels[:, :-1]
    return _binary_array_to_hex(diff)


def compute_phash(image: Image.Image, hash_size: int = 8, highfreq_factor: int = 4) -> str:
    """DCT-based Perceptual Hash (pHash).
    
    1. Reduce size to 32x32 (hash_size * highfreq_factor)
    2. Convert to grayscale
    3. Compute 2D Discrete Cosine Transform (DCT)
    4. Extract low-frequency top-left block (hash_size x hash_size)
    5. Exclude DC component (0,0) and compute median
    6. Set bit to 1 if coefficient > median, else 0
    """
    size = hash_size * highfreq_factor
    img = image.convert("L").resize((size, size), Image.Resampling.LANCZOS)
    pixels = np.asarray(img, dtype=np.float32)
    
    # 2D DCT
    dct_matrix = dct(dct(pixels, axis=0, norm="ortho"), axis=1, norm="ortho")
    
    # Top-left hash_size x hash_size
    sub_dct = dct_matrix[:hash_size, :hash_size]
    
    # Compute median excluding DC component (0,0)
    dc_free = sub_dct.flatten()[1:]
    med = np.median(dc_free)
    
    diff = sub_dct > med
    return _binary_array_to_hex(diff)


def compute_whash(image: Image.Image, hash_size: int = 8) -> str:
    """Haar Wavelet / Multi-Scale Gradient Hash (wHash).
    
    Uses 2D multi-scale Haar wavelet low-low approximation subband.
    """
    img_size = hash_size * 2
    img = image.convert("L").resize((img_size, img_size), Image.Resampling.LANCZOS)
    pixels = np.asarray(img, dtype=np.float32)

    # 1-level 2D Haar wavelet decomposition (LL subband)
    # Row average
    ll_row = (pixels[:, 0::2] + pixels[:, 1::2]) * 0.5
    # Column average
    ll = (ll_row[0::2, :] + ll_row[1::2, :]) * 0.5
    
    med = np.median(ll)
    diff = ll > med
    return _binary_array_to_hex(diff)


def compute_perceptual_hashes(image: Image.Image) -> PerceptualHashes:
    """Computes full suite of visual perceptual hashes for an image."""
    try:
        ahash = compute_ahash(image)
    except Exception:
        ahash = None

    try:
        dhash = compute_dhash(image)
    except Exception:
        dhash = None

    try:
        phash = compute_phash(image)
    except Exception:
        phash = None

    try:
        whash = compute_whash(image)
    except Exception:
        whash = None

    return PerceptualHashes(
        ahash=ahash,
        dhash=dhash,
        phash=phash,
        whash=whash,
    )


def hamming_distance(hex1: str, hex2: str) -> int:
    """Calculates the bitwise Hamming distance between two hex hashes."""
    if len(hex1) != len(hex2):
        raise ValueError(f"Hash lengths differ: {len(hex1)} vs {len(hex2)}")
    val1 = int(hex1, 16)
    val2 = int(hex2, 16)
    xor_val = val1 ^ val2
    return bin(xor_val).count("1")


def perceptual_similarity(hex1: str, hex2: str, bit_length: int = 64) -> float:
    """Calculates normalized visual similarity between two perceptual hashes.
    
    Returns:
        Score between 0.0 (completely dissimilar) and 1.0 (identical visual structure).
    """
    dist = hamming_distance(hex1, hex2)
    return max(0.0, 1.0 - (dist / float(bit_length)))
