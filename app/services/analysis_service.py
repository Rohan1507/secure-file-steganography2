"""
analysis_service.py
====================
Security / quality analysis of stego images:
  - MSE  (Mean Squared Error)
  - PSNR (Peak Signal-to-Noise Ratio)
  - SSIM (Structural Similarity - simplified global implementation, documented)
  - Chi-square LSB steganalysis test (educational)
  - Difference-image generation for visual comparison

NOTE ON SSIM: a full windowed SSIM (as in scikit-image) is more precise.
This project implements a simplified single-window global SSIM to avoid an
extra heavyweight dependency, which is accurate enough for demonstrating the
concept in an academic setting. This simplification is documented here and
in PROJECT_REPORT.md.
"""
import numpy as np
from PIL import Image



def _load_rgb_array(path: str) -> np.ndarray:
    with Image.open(path) as img:
        return np.array(img.convert("RGB")).astype(np.float64)


def compute_mse(cover_path: str, stego_path: str) -> float:
    a = _load_rgb_array(cover_path)
    b = _load_rgb_array(stego_path)
    if a.shape != b.shape:
        raise ValueError("Cover and stego image dimensions do not match.")
    return float(np.mean((a - b) ** 2))


def compute_psnr(mse: float, max_pixel_value: float = 255.0) -> float:
    if mse == 0:
        return float("inf")
    return float(10 * np.log10((max_pixel_value ** 2) / mse))


def compute_ssim_simplified(cover_path: str, stego_path: str) -> float:
    """
    Simplified global SSIM (single window = whole image), per-channel then averaged.
    Standard constants C1, C2 for 8-bit images.
    """
    a = _load_rgb_array(cover_path)
    b = _load_rgb_array(stego_path)
    if a.shape != b.shape:
        raise ValueError("Cover and stego image dimensions do not match.")

    C1 = (0.01 * 255) ** 2
    C2 = (0.03 * 255) ** 2

    ssim_channels = []
    for c in range(3):
        x = a[:, :, c].flatten()
        y = b[:, :, c].flatten()
        mu_x, mu_y = x.mean(), y.mean()
        var_x, var_y = x.var(), y.var()
        cov_xy = np.mean((x - mu_x) * (y - mu_y))
        numerator = (2 * mu_x * mu_y + C1) * (2 * cov_xy + C2)
        denominator = (mu_x ** 2 + mu_y ** 2 + C1) * (var_x + var_y + C2)
        ssim_channels.append(numerator / denominator)

    return float(np.mean(ssim_channels))


def compute_chi_square(stego_path: str) -> float:
    """
    Classic chi-square LSB steganalysis test (Westfeld & Pfitzmann style, simplified).
    Compares observed frequency of pixel-value pairs (2k, 2k+1) against the
    expected frequency if LSBs were randomly distributed (a hallmark of LSB embedding).
    Returns the chi-square statistic; LOWER values suggest more randomized LSBs
    (which can indicate the presence of embedded data), but this is only an
    educational heuristic, not a reliable detector on its own.
    """
    arr = np.array(Image.open(stego_path).convert("RGB"))
    flat = arr.flatten()

    hist, _ = np.histogram(flat, bins=256, range=(0, 256))
    observed = []
    expected = []
    for k in range(128):
        h2k = hist[2 * k]
        h2k1 = hist[2 * k + 1]
        avg = (h2k + h2k1) / 2.0
        if avg == 0:
            continue
        # Both members of the pair are compared against their shared average,
        # which keeps sum(observed) == sum(expected) exactly, as required by
        # the chi-square goodness-of-fit test.
        observed.append(h2k)
        expected.append(avg)
        observed.append(h2k1)
        expected.append(avg)

    if len(observed) < 2:
        return 0.0

     observed_arr = np.array(observed, dtype=np.float64)
    expected_arr = np.array(expected, dtype=np.float64)
    chi2 = float(np.sum((observed_arr - expected_arr) ** 2 / expected_arr))
    return chi2


def generate_difference_image(cover_path: str, stego_path: str, output_path: str,
                               amplify: int = 20) -> None:
    """Save an amplified visual difference image (cover vs stego) for the UI."""
    a = _load_rgb_array(cover_path)
    b = _load_rgb_array(stego_path)
    diff = np.abs(a - b) * amplify
    diff = np.clip(diff, 0, 255).astype(np.uint8)
    Image.fromarray(diff, mode="RGB").save(output_path, format="PNG")


def full_analysis(cover_path: str, stego_path: str, payload_bytes: int,
                   capacity_bytes: int, diff_output_path: str = None) -> dict:
    mse = compute_mse(cover_path, stego_path)
    psnr = compute_psnr(mse)
    ssim = compute_ssim_simplified(cover_path, stego_path)
    chi2 = compute_chi_square(stego_path)
    ratio = (payload_bytes / capacity_bytes) if capacity_bytes else 0.0

    if diff_output_path:
        generate_difference_image(cover_path, stego_path, diff_output_path)

    return {
        "mse": round(mse, 6),
        "psnr": round(psnr, 4) if psnr != float("inf") else None,
        "ssim": round(ssim, 6),
        "chi_square": round(chi2, 4),
        "payload_bytes": payload_bytes,
        "capacity_bytes": capacity_bytes,
        "payload_ratio": round(ratio, 6),
    }
