"""Unit tests for perceptual visual fingerprinting."""

from PIL import Image
from forensic_image.hashing.perceptual import (
    compute_ahash,
    compute_dhash,
    compute_phash,
    compute_whash,
    hamming_distance,
    perceptual_similarity,
)


def test_perceptual_hashes() -> None:
    img = Image.new("RGB", (256, 256), "gray")
    
    ahash = compute_ahash(img)
    dhash = compute_dhash(img)
    phash = compute_phash(img)
    whash = compute_whash(img)

    assert len(ahash) == 16  # 64-bit hex = 16 characters
    assert len(dhash) == 16
    assert len(phash) == 16
    assert len(whash) == 16


def test_perceptual_similarity_preservation() -> None:
    # Slightly resized or slightly recompressed image must have high perceptual similarity
    img1 = Image.new("RGB", (400, 300), "red")
    img2 = img1.resize((200, 150), Image.Resampling.LANCZOS)

    h1 = compute_phash(img1)
    h2 = compute_phash(img2)

    sim = perceptual_similarity(h1, h2)
    dist = hamming_distance(h1, h2)

    assert sim >= 0.90
    assert dist <= 6
