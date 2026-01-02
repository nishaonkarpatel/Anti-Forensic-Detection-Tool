# stego_detection.py
"""
Multi-stage steganography detection with confidence scoring.
Progressive filtering: Fast triage → Medium analysis → Deep analysis
"""

import numpy as np
from pathlib import Path
from typing import Tuple, Dict, Optional
from PIL import Image
import io

# ============================================================
# STAGE 1: FAST TRIAGE
# ============================================================

def quick_file_size_check(file_path: Path, width: int, height: int, format_type: str) -> Tuple[int, str]:
    """
    Fast file size heuristic.
    Returns: (score, reason)
    """
    actual_size = file_path.stat().st_size
    pixels = width * height
    
    if pixels == 0:
        return 0, "zero_pixels"
    
    ratio = actual_size / pixels
    
    if format_type == "jpeg":
        # JPEG: typical 0.05-0.15 bytes per pixel
        if ratio < 0.3:
            return 0, "normal_size"
        elif ratio < 0.5:
            return 2, "slightly_large"
        else:
            return 5, "very_large_for_jpeg"
    
    elif format_type == "png":
        # PNG: typical 0.3-1.0 bytes per pixel (varies by content)
        if ratio < 1.5:
            return 0, "normal_size"
        elif ratio < 2.5:
            return 2, "slightly_large"
        else:
            return 5, "very_large_for_png"
    
    return 0, "unknown_format"


def quick_metadata_scan(data: bytes, format_type: str) -> Tuple[int, Dict]:
    """
    Fast scan for tool signatures and oversized metadata.
    Returns: (score, details)
    """
    score = 0
    details = {}
    
    # Known stego tool signatures
    signatures = [
        b"steghide", b"openstego", b"outguess", b"stegano",
        b"OpenStego", b"Steghide", b"OutGuess", b"STEGANO"
    ]
    
    for sig in signatures:
        if sig in data:
            score += 15  # Immediate high confidence
            details["tool_signature"] = sig.decode('latin-1')
            details["confirmed_tool"] = True
            return score, details
    
    # Check for suspicious text patterns (base64, hex)
    if format_type == "jpeg":
        # Look for EXIF comment markers
        if b"UserComment" in data or b"ImageDescription" in data:
            # Find the data after these markers and check size
            # Simplified: just check if there's a lot of ASCII data
            ascii_count = sum(1 for b in data if 32 <= b <= 126)
            if ascii_count > 5000:  # More than 5KB of ASCII
                score += 3
                details["large_metadata"] = True
    
    return score, details


def check_trailing_data(data: bytes, format_type: str) -> Tuple[int, Optional[int]]:
    """
    Check for data after EOF marker.
    Returns: (score, extra_bytes_count)
    """
    if format_type == "jpeg":
        # JPEG ends with FF D9
        eof_marker = b"\xFF\xD9"
        idx = data.rfind(eof_marker)
        if idx != -1:
            eof_end = idx + 2
            extra = len(data) - eof_end
            if extra > 100:
                return 5, extra
    
    elif format_type == "png":
        # PNG ends with IEND chunk
        iend_marker = b"IEND"
        idx = data.rfind(iend_marker)
        if idx != -1:
            # IEND is followed by 4-byte CRC
            eof_end = idx + 4 + 4
            if eof_end < len(data):
                extra = len(data) - eof_end
                if extra > 100:
                    return 5, extra
    
    return 0, None


# ============================================================
# STAGE 2: MEDIUM ANALYSIS (Pixel-level)
# ============================================================

def extract_lsb_plane(image: Image.Image) -> np.ndarray:
    """
    Extract the least significant bit plane from image.
    Returns: binary array of LSBs for all channels
    """
    img_array = np.array(image)
    
    # Handle grayscale
    if len(img_array.shape) == 2:
        img_array = np.expand_dims(img_array, axis=2)
    
    # Extract LSB (bit 0) from each pixel value
    lsb = img_array & 1
    
    return lsb


def analyze_lsb_distribution(lsb_plane: np.ndarray) -> Tuple[int, Dict]:
    """
    Analyze LSB bit distribution.
    Natural images should have ~50/50 distribution of 0s and 1s.
    Returns: (score, details)
    """
    score = 0
    details = {}
    
    total_bits = lsb_plane.size
    ones_count = np.sum(lsb_plane)
    frequency = ones_count / total_bits
    
    details["lsb_frequency"] = frequency
    details["total_bits"] = total_bits
    
    # Check deviation from 0.5
    deviation = abs(frequency - 0.5)
    
    # MAKE MORE SENSITIVE:
    if deviation < 0.01:
        score = 0  # Very normal (49-51%)
    elif deviation < 0.03:
        score = 2  # Was 1 - slightly off (47-53%)
    elif deviation < 0.06:
        score = 4  # Was 3 - suspicious (44-56%)
    else:
        score = 6  # Was 5 - very suspicious (<44% or >56%)
    
    details["deviation"] = deviation
    
    # Check per-channel consistency (if RGB)
    if len(lsb_plane.shape) == 3 and lsb_plane.shape[2] >= 3:
        channel_freqs = []
        for c in range(min(3, lsb_plane.shape[2])):
            channel_lsb = lsb_plane[:, :, c]
            channel_freq = np.sum(channel_lsb) / channel_lsb.size
            channel_freqs.append(channel_freq)
        
        details["channel_frequencies"] = channel_freqs
        
        # If channels have very different frequencies, suspicious
        freq_variance = np.var(channel_freqs)
        if freq_variance > 0.005:  # Was 0.01 - more sensitive
            score += 4  # Was 3
            details["channel_inconsistency"] = True
        
        # If all channels have same unusual pattern (coordinated embedding)
        if all(abs(f - 0.5) > 0.03 for f in channel_freqs):  # Was 0.05
            score += 3  # Was 2
            details["coordinated_embedding"] = True
    
    return score, details


def calculate_entropy(data: np.ndarray) -> float:
    """
    Calculate Shannon entropy of data.
    Returns: entropy in bits per byte (0-8)
    """
    # Flatten and convert to bytes (0-255)
    flat = data.flatten()
    
    # Count frequency of each value
    unique, counts = np.unique(flat, return_counts=True)
    probabilities = counts / len(flat)
    
    # Shannon entropy: -sum(p * log2(p))
    entropy = -np.sum(probabilities * np.log2(probabilities + 1e-10))
    
    return entropy


def analyze_entropy(image: Image.Image, lsb_plane: np.ndarray, format_type: str) -> Tuple[int, Dict]:
    """
    Analyze entropy of image and LSB plane.
    NOW INCLUDES LSB replacement pattern detection.
    Returns: (score, details)
    """
    score = 0
    details = {}
    
    # Convert image to array
    img_array = np.array(image)
    
    # Calculate file entropy
    h_file = calculate_entropy(img_array)
    details["file_entropy"] = h_file
    
    # Calculate LSB entropy
    h_lsb = calculate_entropy(lsb_plane)
    details["lsb_entropy"] = h_lsb
    
    # *** NEW: Check for LSB replacement pattern FIRST ***
    replacement_score, replacement_details = detect_lsb_replacement_pattern(
        lsb_plane, h_file, h_lsb
    )
    score += replacement_score
    details.update(replacement_details)
    
    # If LSB replacement detected, log it prominently
    if replacement_details.get("lsb_replacement_pattern"):
        details["ALERT"] = "Classic LSB replacement steganography signature detected"
    
    # Context-aware thresholds (keep existing logic)
    if format_type == "jpeg":
        if h_file > 7.8:
            score += 3
            details["high_file_entropy"] = True
    elif format_type == "png":
        if h_file > 7.5:
            score += 3
            details["high_file_entropy"] = True
    
    # LSB entropy check (ADJUSTED THRESHOLD)
    if h_lsb > 7.5:
        score += 4
        details["high_lsb_entropy"] = True
    elif h_lsb < 1.5:  # NEW: Also flag VERY LOW entropy
        score += 5
        details["very_low_lsb_entropy"] = True
    
    # Entropy difference check
    entropy_diff = h_file - h_lsb
    details["entropy_difference"] = entropy_diff
    
    if entropy_diff < 0.8:
        score += 5
        details["lsb_too_random"] = True
    elif entropy_diff > 5.0:  # NEW: Also flag LARGE gaps
        score += 4
        details["lsb_too_structured"] = True
    
    return score, details

def detect_lsb_replacement_pattern(lsb_plane: np.ndarray, file_entropy: float, lsb_entropy: float) -> Tuple[int, Dict]:
    """
    Detect LSB replacement steganography pattern.
    
    Classic LSB replacement creates a specific signature:
    - LSB frequency stays near 0.5 (looks normal)
    - BUT LSB entropy becomes very low (structured payload)
    - File entropy remains high (photo content unchanged)
    
    This catches sophisticated stego that passes basic tests.
    Returns: (score, details)
    """
    score = 0
    details = {}
    
    # Calculate LSB frequency
    flat = lsb_plane.flatten()
    lsb_frequency = np.sum(flat) / len(flat)
    
    details["lsb_frequency"] = lsb_frequency
    details["file_entropy"] = file_entropy
    details["lsb_entropy"] = lsb_entropy
    
    # Pattern 1: Low LSB entropy with normal frequency
    # This is the CLASSIC LSB replacement signature
    if lsb_entropy < 2.0 and 0.45 <= lsb_frequency <= 0.55:
        score += 10
        details["lsb_replacement_pattern"] = True
        details["pattern_type"] = "classic_lsb_replacement"
    
    # Pattern 2: Very low LSB entropy (< 1.5) regardless of frequency
    # Even more suspicious - highly structured payload
    if lsb_entropy < 1.5:
        score += 8
        details["very_low_lsb_entropy"] = True
    
    # Pattern 3: Large gap between file and LSB entropy
    entropy_gap = file_entropy - lsb_entropy
    details["entropy_gap"] = entropy_gap
    
    if entropy_gap > 5.0:  # File is complex but LSBs are simple
        score += 6
        details["suspicious_entropy_gap"] = True
    
    # Pattern 4: Check for periodic patterns in LSB (common in sequential embedding)
    try:
        # Take a sample and look for repeating patterns
        sample = flat[:10000] if len(flat) > 10000 else flat
        
        # Check autocorrelation at lag 8 (byte boundary)
        if len(sample) > 16:
            lag8_corr = np.corrcoef(sample[:-8], sample[8:])[0, 1]
            details["lag8_autocorrelation"] = lag8_corr
            
            if abs(lag8_corr) > 0.3:  # Strong periodicity
                score += 5
                details["periodic_pattern_detected"] = True
    except:
        pass
    
    return score, details


def analyze_pixel_correlation(lsb_plane: np.ndarray) -> Tuple[int, Dict]:
    """
    Analyze correlation between adjacent pixels in LSB plane.
    Natural images have high correlation; stego reduces it.
    Returns: (score, details)
    """
    score = 0
    details = {}
    
    # Flatten for horizontal adjacent pairs
    flat = lsb_plane.flatten()
    
    if len(flat) < 100:
        return 0, {"error": "image_too_small"}
    
    # Calculate correlation coefficient between adjacent pixels
    x = flat[:-1]
    y = flat[1:]
    
    # Correlation coefficient
    correlation = np.corrcoef(x, y)[0, 1]
    details["lsb_correlation"] = correlation
    
    # Natural LSBs have low correlation (0.0-0.3 is normal)
    # But stego LSBs have even lower or negative correlation
    if correlation < -0.1:
        score += 5
        details["negative_correlation"] = True
    elif correlation < 0.1:
        score += 3
        details["very_low_correlation"] = True
    elif correlation > 0.5:
        # Unusually high correlation in LSBs (suspicious pattern)
        score += 2
        details["high_lsb_correlation"] = True
    
    return score, details


# ============================================================
# STAGE 3: DEEP ANALYSIS (Statistical tests)
# ============================================================

def chi_square_test(lsb_plane: np.ndarray) -> Tuple[int, Dict]:
    """
    Chi-square attack for LSB stego detection.
    Tests if LSB distribution follows expected randomness.
    Returns: (score, details)
    """
    score = 0
    details = {}
    
    try:
        # Flatten LSB plane
        flat = lsb_plane.flatten()
        
        # Expected: 50/50 distribution
        observed_1 = np.sum(flat)
        observed_0 = len(flat) - observed_1
        expected = len(flat) / 2
        
        # Chi-square statistic: sum((O - E)^2 / E)
        chi_square = ((observed_1 - expected) ** 2 / expected + 
                      (observed_0 - expected) ** 2 / expected)
        
        details["chi_square_statistic"] = chi_square
        
        # Critical value for 1 degree of freedom at p=0.05 is 3.841
        if chi_square > 3.841:
            score += 10
            details["chi_square_significant"] = True
            details["p_value"] = "< 0.05"
        
    except Exception as e:
        details["error"] = str(e)
    
    return score, details


def sample_pair_analysis(image: Image.Image) -> Tuple[int, Dict]:
    """
    Sample Pair Analysis (SPA) for LSB detection.
    Analyzes pixel pair correlations at bit level.
    Returns: (score, details)
    """
    score = 0
    details = {}
    
    try:
        img_array = np.array(image)
        
        # Handle grayscale
        if len(img_array.shape) == 2:
            img_array = np.expand_dims(img_array, axis=2)
        
        # Take first channel
        channel = img_array[:, :, 0].flatten()
        
        # Count sample pairs
        # Adjacent pixels where both are even or both are odd
        pairs = channel[:-1:2], channel[1::2]
        
        same_parity = np.sum((pairs[0] % 2) == (pairs[1] % 2))
        total_pairs = len(pairs[0])
        
        ratio = same_parity / total_pairs
        details["same_parity_ratio"] = ratio
        
        # Natural images: ~0.5
        # LSB embedding: significantly different
        if abs(ratio - 0.5) > 0.1:
            score += 10
            details["spa_anomaly_detected"] = True
    
    except Exception as e:
        details["error"] = str(e)
    
    return score, details


# ============================================================
# MAIN ORCHESTRATOR
# ============================================================

class StegoAnalyzer:
    """
    Multi-stage steganography analyzer with progressive filtering.
    """
    
    # Scoring thresholds
    STAGE_1_THRESHOLD = 0  # Below this: likely clean, skip Stage 2
    STAGE_2_THRESHOLD = 5  # Below this: suspicious but not confirmed
    STAGE_3_THRESHOLD = 8  # Above this: run deep analysis
    
    def __init__(self, log_callback=print):
        self.log = log_callback
    
    def analyze_image(self, file_path: Path, data: bytes) -> Tuple[int, str, Dict]:
        """
        Full multi-stage analysis.
        Returns: (total_score, severity, details)
        """
        total_score = 0
        all_details = {}
        
        # Determine format
        if data.startswith(b"\xFF\xD8"):
            format_type = "jpeg"
        elif data.startswith(b"\x89PNG"):
            format_type = "png"
        else:
            return 0, "unknown", {"error": "unsupported_format"}
        
        all_details["format"] = format_type
        
        # ===== STAGE 1: FAST TRIAGE =====
        try:
            # Load image to get dimensions
            image = Image.open(io.BytesIO(data))
            width, height = image.size
            all_details["dimensions"] = {"width": width, "height": height}
            
            # File size check
            size_score, size_reason = quick_file_size_check(file_path, width, height, format_type)
            total_score += size_score
            all_details["size_check"] = {"score": size_score, "reason": size_reason}
            
            # Metadata scan
            meta_score, meta_details = quick_metadata_scan(data, format_type)
            total_score += meta_score
            all_details["metadata_scan"] = {"score": meta_score, **meta_details}
            
            # If tool signature found, return immediately
            if meta_details.get("confirmed_tool"):
                self.log(f"[!] CONFIRMED: Stego tool signature found in {file_path.name}")
                return total_score, "HIGH", all_details
            
            # Trailing data check
            trailer_score, extra_bytes = check_trailing_data(data, format_type)
            total_score += trailer_score
            all_details["trailer_check"] = {"score": trailer_score, "extra_bytes": extra_bytes}
            
            self.log(f"[i] Stage 1 complete: {file_path.name} scored {total_score} points")
            
            # Short-circuit if likely clean
            if total_score < self.STAGE_1_THRESHOLD:
                all_details["stage_1_verdict"] = "likely_clean"
                return total_score, "CLEAN", all_details
            
        except Exception as e:
            all_details["stage_1_error"] = str(e)
            return 0, "ERROR", all_details
        
        # ===== STAGE 2: MEDIUM ANALYSIS =====
        try:
            self.log(f"[i] Stage 2 analysis: {file_path.name}")
            
            # Extract LSB plane
            lsb_plane = extract_lsb_plane(image)
            
            # LSB distribution
            lsb_score, lsb_details = analyze_lsb_distribution(lsb_plane)
            total_score += lsb_score
            all_details["lsb_analysis"] = {"score": lsb_score, **lsb_details}
            self.log(f"[DEBUG] LSB: freq={lsb_details.get('lsb_frequency', 'N/A'):.4f}, dev={lsb_details.get('deviation', 'N/A'):.4f}, score={lsb_score}")

            
            # Entropy analysis
            entropy_score, entropy_details = analyze_entropy(image, lsb_plane, format_type)
            total_score += entropy_score
            all_details["entropy_analysis"] = {"score": entropy_score, **entropy_details}
            self.log(f"[DEBUG] Entropy: file={entropy_details.get('file_entropy', 'N/A'):.2f}, lsb={entropy_details.get('lsb_entropy', 'N/A'):.2f}, diff={entropy_details.get('entropy_difference', 'N/A'):.2f}, score={entropy_score}")

            # Correlation analysis
            corr_score, corr_details = analyze_pixel_correlation(lsb_plane)
            total_score += corr_score
            all_details["correlation_analysis"] = {"score": corr_score, **corr_details}
            self.log(f"[DEBUG] Correlation: {corr_details.get('lsb_correlation', 'N/A'):.4f}, score={corr_score}")
            
            self.log(f"[i] Stage 2 complete: {file_path.name} scored {total_score} points total")
            
            # If score below Stage 2 threshold, return as suspicious
            if total_score < self.STAGE_3_THRESHOLD:
                severity = "MEDIUM" if total_score >= self.STAGE_2_THRESHOLD else "LOW"
                all_details["stage_2_verdict"] = severity
                return total_score, severity, all_details
            
        except Exception as e:
            all_details["stage_2_error"] = str(e)
            # Continue with what we have
        
        # ===== STAGE 3: DEEP ANALYSIS =====
        try:
            self.log(f"[!] Stage 3 analysis (deep): {file_path.name}")
            
            # Chi-square test
            chi_score, chi_details = chi_square_test(lsb_plane)
            total_score += chi_score
            all_details["chi_square_test"] = {"score": chi_score, **chi_details}
            
            # Sample pair analysis
            spa_score, spa_details = sample_pair_analysis(image)
            total_score += spa_score
            all_details["sample_pair_analysis"] = {"score": spa_score, **spa_details}
            
            self.log(f"[!] Stage 3 complete: {file_path.name} FINAL SCORE: {total_score} points")
            
        except Exception as e:
            all_details["stage_3_error"] = str(e)
        
        # ===== FINAL VERDICT =====
        if total_score >= 15:
            severity = "CRITICAL"
        elif total_score >= self.STAGE_3_THRESHOLD:
            severity = "HIGH"
        elif total_score >= self.STAGE_2_THRESHOLD:
            severity = "MEDIUM"
        else:
            severity = "LOW"
        
        all_details["final_score"] = total_score
        all_details["final_verdict"] = severity
        
        return total_score, severity, all_details