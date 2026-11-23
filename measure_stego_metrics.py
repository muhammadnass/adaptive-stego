"""
=============================================================================
Steganography Metrics Measurement Script
For: "Texture-Intelligent Multi-Bit LSB Steganography: A Content-Aware
      Adaptive Framework with AES-256 Encryption"

PURPOSE:
  Measures PSNR, SSIM, MSE, NPCR, UACI, entropy, and steganalysis
  resistance (chi-square, RS analysis, histogram deviation) on USC-SIPI
  images using a Python-implemented version of the Phase 2 adaptive system.

USAGE:
  1. Place your USC-SIPI images (PNG) in ./cover_images/
  2. Run: python3 measure_stego_metrics.py
  3. Results saved to ./results/metrics_results.csv

REQUIREMENTS:
  pip install Pillow numpy scipy
=============================================================================
"""

import os, sys, csv, time, hashlib, math, random
import numpy as np
from PIL import Image
from scipy import stats

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 1 — TEXTURE ANALYSIS (mirrors Phase 2 JS implementation)
# ─────────────────────────────────────────────────────────────────────────────

T1 = 30  # smooth / edge boundary (matches HTML app)
T2 = 80  # edge / texture boundary (matches HTML app)

def compute_luminance(img_array):
    """Convert RGB to greyscale luminance (ITU-R BT.601)."""
    r, g, b = img_array[:,:,0], img_array[:,:,1], img_array[:,:,2]
    return 0.299*r + 0.587*g + 0.114*b

def compute_sobel(L):
    """Compute Sobel edge magnitude, normalised to [0,255]."""
    H, W = L.shape
    Gx = np.zeros_like(L, dtype=np.float64)
    Gy = np.zeros_like(L, dtype=np.float64)
    # Pad with reflect mode to avoid border artefacts
    Lp = np.pad(L, 1, mode='reflect')
    Gx = (  -Lp[0:H, 0:W] - 2*Lp[1:H+1, 0:W] - Lp[2:H+2, 0:W]
            +Lp[0:H, 2:W+2] + 2*Lp[1:H+1, 2:W+2] + Lp[2:H+2, 2:W+2] )
    Gy = (  -Lp[0:H, 0:W] - 2*Lp[0:H, 1:W+1] - Lp[0:H, 2:W+2]
            +Lp[2:H+2, 0:W] + 2*Lp[2:H+2, 1:W+1] + Lp[2:H+2, 2:W+2] )
    mag = np.sqrt(Gx**2 + Gy**2) / 4.0
    return np.clip(mag, 0, 255)

def compute_local_variance(L, window=5):
    """Compute local standard deviation in window×window neighbourhood."""
    from scipy.ndimage import uniform_filter
    L_f = L.astype(np.float64)
    mean = uniform_filter(L_f, size=window)
    mean_sq = uniform_filter(L_f**2, size=window)
    var = np.sqrt(np.maximum(mean_sq - mean**2, 0))
    return np.clip(var, 0, 255)

def build_adaptive_map(img_array):
    """
    Returns N_map: array of same H×W shape, each value is 1, 2, or 3.
    Mirrors the N(x,y) decision function in the Phase 2 HTML app.
    """
    L = compute_luminance(img_array)
    sobel = compute_sobel(L)
    lvar  = compute_local_variance(L)
    V0 = np.minimum(255, np.maximum(sobel, lvar))
    N_map = np.ones(V0.shape, dtype=np.uint8)
    N_map[V0 >= T1] = 2
    N_map[V0 >= T2] = 3
    return N_map

def adaptive_capacity(N_map):
    """Total adaptive capacity in bits (3 channels per pixel)."""
    return int(3 * np.sum(N_map))

def texture_distribution(N_map):
    """Returns (pct_smooth, pct_edge, pct_texture) as percentages."""
    total = N_map.size
    s = 100.0 * np.sum(N_map == 1) / total
    e = 100.0 * np.sum(N_map == 2) / total
    t = 100.0 * np.sum(N_map == 3) / total
    return s, e, t

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 2 — PSEUDO-RANDOM PIXEL TRAVERSAL (mirrors Phase 2 JS)
# ─────────────────────────────────────────────────────────────────────────────

def derive_traversal_order(password, n_pixels):
    """
    SHA-256 of password → 32-bit seed → LCG → Fisher-Yates shuffle.
    Matches the JavaScript implementation exactly.
    """
    h = hashlib.sha256(password.encode('utf-8')).hexdigest()
    seed = int(h[0:8], 16)
    # LCG constants (matches JS: 1664525, 1013904223, 2^32)
    indices = list(range(n_pixels))
    a, c, m = 1664525, 1013904223, 2**32
    for i in range(n_pixels - 1, 0, -1):
        seed = (a * seed + c) % m
        j = seed % (i + 1)
        indices[i], indices[j] = indices[j], indices[i]
    return indices

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 3 — EMBEDDING ENGINE (simplified; no AES for metric measurement)
# ─────────────────────────────────────────────────────────────────────────────

def embed_payload(cover_array, payload_bits, password, N_map):
    """
    Embed payload_bits (list of 0/1 ints) into cover image using
    adaptive N_map and pseudo-random traversal. Returns stego array.
    """
    H, W = cover_array.shape[:2]
    stego = cover_array.copy()
    traversal = derive_traversal_order(password, H * W)
    idx = 0
    for pix_idx in traversal:
        if idx >= len(payload_bits):
            break
        row, col = divmod(pix_idx, W)
        n_bits = int(N_map[row, col])
        mask = (1 << n_bits) - 1
        for ch in range(3):
            if idx >= len(payload_bits):
                break
            chunk = payload_bits[idx:idx+n_bits]
            while len(chunk) < n_bits:
                chunk.append(0)
            val = 0
            for b in chunk:
                val = (val << 1) | b
            stego[row, col, ch] = (int(stego[row, col, ch]) & ~mask) | val
            idx += n_bits
    return stego

def generate_payload_bits(n_bits):
    """Generate pseudo-random payload (simulates encrypted ciphertext)."""
    rng = random.Random(42)
    return [rng.randint(0, 1) for _ in range(n_bits)]

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 4 — IMAGE QUALITY METRICS
# ─────────────────────────────────────────────────────────────────────────────

def compute_mse(cover, stego):
    diff = cover.astype(np.float64) - stego.astype(np.float64)
    return float(np.mean(diff**2))

def compute_psnr(cover, stego):
    mse = compute_mse(cover, stego)
    if mse == 0:
        return float('inf')
    return float(10 * math.log10(255.0**2 / mse))

def compute_ssim(cover, stego, window=11):
    """Compute SSIM (simplified global version for speed)."""
    c1, c2 = (0.01*255)**2, (0.03*255)**2
    A = cover.astype(np.float64)
    B = stego.astype(np.float64)
    mu_a, mu_b = A.mean(), B.mean()
    sig_a  = A.std()
    sig_b  = B.std()
    sig_ab = float(np.mean((A - mu_a) * (B - mu_b)))
    ssim = ((2*mu_a*mu_b + c1) * (2*sig_ab + c2)) / \
           ((mu_a**2 + mu_b**2 + c1) * (sig_a**2 + sig_b**2 + c2))
    return float(ssim)

def compute_npcr(cover, stego):
    """Number of Pixels Change Rate (%)."""
    diff = (cover != stego).any(axis=2)
    return float(100.0 * diff.sum() / diff.size)

def compute_uaci(cover, stego):
    """Unified Average Changing Intensity (%)."""
    diff = np.abs(cover.astype(np.float64) - stego.astype(np.float64))
    return float(100.0 * diff.mean() / 255.0)

def compute_entropy(img_array):
    """Shannon entropy of the flattened pixel value distribution."""
    flat = img_array.flatten()
    counts = np.bincount(flat, minlength=256)
    probs = counts / counts.sum()
    probs = probs[probs > 0]
    return float(-np.sum(probs * np.log2(probs)))

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 5 — STEGANALYSIS METRICS
# ─────────────────────────────────────────────────────────────────────────────

def chi_square_attack(img_array):
    """
    Chi-square attack on LSB plane.
    Compares observed vs expected PoV (pairs of values) frequencies.
    Returns chi-square statistic and p-value.
    Higher p-value = less detectable (closer to natural image).
    p > 0.05 → not detected at 5% significance level.
    """
    flat = img_array[:,:,0].flatten().astype(np.int32)
    observed = np.zeros(128, dtype=np.float64)
    expected = np.zeros(128, dtype=np.float64)
    counts = np.bincount(flat, minlength=256)
    for i in range(128):
        # PoV pair: (2i, 2i+1)
        n0 = counts[2*i]
        n1 = counts[2*i+1]
        observed[i] = n1
        expected[i] = (n0 + n1) / 2.0
    # Remove zero-expected bins
    mask = expected > 0
    chi2 = float(np.sum((observed[mask] - expected[mask])**2 / expected[mask]))
    dof = int(mask.sum() - 1)
    p_value = float(1 - stats.chi2.cdf(chi2, dof)) if dof > 0 else 0.0
    return chi2, p_value

def rs_analysis(img_array):
    """
    RS (Regular-Singular) analysis on the red channel.
    Returns (R_m, S_m, R_neg, S_neg) — the RS group fractions.
    For a clean image: R_m ≈ R_neg >> S_m ≈ S_neg.
    For a heavily embedded image: R_m ≈ S_m ≈ R_neg ≈ S_neg (equalization).
    We report the RS detection ratio: |R_m - R_neg| + |S_m - S_neg|.
    Lower value → less detectable.
    """
    channel = img_array[:,:,0].astype(np.int32)
    H, W = channel.shape
    # Use 1×4 pixel groups
    group_size = 4
    flip_mask = np.array([0, 1, 0, 1])  # alternating flip pattern
    
    def disc(group):
        return np.sum(np.abs(np.diff(group)))
    
    R_m, S_m, R_neg, S_neg = 0, 0, 0, 0
    total = 0
    for row in range(H):
        for col in range(0, W - group_size + 1, group_size):
            g = channel[row, col:col+group_size].copy()
            d0 = disc(g)
            # Positive mask flip: flip LSB of positions where mask=1
            gf = g.copy()
            for k in range(group_size):
                if flip_mask[k] == 1:
                    gf[k] = gf[k] ^ 1  # flip LSB
            d1 = disc(gf)
            if d1 > d0:   R_m += 1
            elif d1 < d0: S_m += 1
            # Negative mask: flip all bits at mask=1 positions
            gn = g.copy()
            for k in range(group_size):
                if flip_mask[k] == 1:
                    gn[k] = gn[k] ^ 0xFF
            dn = disc(gn)
            if dn > d0:   R_neg += 1
            elif dn < d0: S_neg += 1
            total += 1
    if total == 0:
        return 0.0
    R_m  /= total; S_m  /= total
    R_neg /= total; S_neg /= total
    # Detection ratio: lower = better (less detectable)
    detection_ratio = abs(R_m - R_neg) + abs(S_m - S_neg)
    return float(detection_ratio)

def histogram_deviation(cover, stego):
    """
    Mean absolute difference between cover and stego LSB-plane histograms.
    Lower = stego histogram closer to natural image.
    """
    lsb_cover = (cover[:,:,0] & 1).flatten()
    lsb_stego = (stego[:,:,0] & 1).flatten()
    hist_c = np.bincount(lsb_cover, minlength=2).astype(float)
    hist_s = np.bincount(lsb_stego, minlength=2).astype(float)
    hist_c /= hist_c.sum(); hist_s /= hist_s.sum()
    return float(np.mean(np.abs(hist_c - hist_s)))

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 6 — MAIN EXPERIMENT RUNNER
# ─────────────────────────────────────────────────────────────────────────────

PAYLOADS = {
    'fixed_5000':   5000,
    'N1_max':     734500,
    'N2_max':    1469000,
    'N3_max':    2203500,
}
PASSWORD = "TestPassword123"

def classify_image(name):
    """Classify USC-SIPI images into types for the paper."""
    name = name.lower()
    smooth_names   = ['lena', 'peppers', 'zelda', 'girl', 'woman']
    texture_names  = ['baboon', 'mandrill', 'boat', 'airplane', 'f16',
                      'barbara', 'goldhill', 'couple', 'bridge']
    for s in smooth_names:
        if s in name: return 'smooth'
    for t in texture_names:
        if t in name: return 'texture'
    return 'mixed'

def run_experiment(img_path, output_dir):
    """Run all experiments on a single image. Returns list of result rows."""
    name = os.path.splitext(os.path.basename(img_path))[0]
    img = Image.open(img_path).convert('RGB')
    cover = np.array(img, dtype=np.uint8)
    H, W = cover.shape[:2]
    img_type = classify_image(name)

    # Build adaptive map
    t0 = time.time()
    N_map = build_adaptive_map(cover)
    texture_time = time.time() - t0
    cap = adaptive_capacity(N_map)
    s_pct, e_pct, t_pct = texture_distribution(N_map)

    rows = []
    cover_entropy = compute_entropy(cover)
    chi2_cover, p_cover = chi_square_attack(cover)
    rs_cover = rs_analysis(cover)

    for exp_name, n_bits in PAYLOADS.items():
        if n_bits > cap:
            print(f"  SKIP {exp_name}: payload {n_bits} > adaptive capacity {cap}")
            continue

        payload_bits = generate_payload_bits(n_bits)
        t_start = time.time()
        stego = embed_payload(cover, payload_bits, PASSWORD, N_map)
        embed_time = (time.time() - t_start) * 1000  # ms

        psnr  = compute_psnr(cover, stego)
        ssim  = compute_ssim(cover, stego)
        mse   = compute_mse(cover, stego)
        npcr  = compute_npcr(cover, stego)
        uaci  = compute_uaci(cover, stego)
        stego_entropy = compute_entropy(stego)

        chi2_stego, p_stego = chi_square_attack(stego)
        rs_stego = rs_analysis(stego)
        hist_dev = histogram_deviation(cover, stego)

        rows.append({
            'image':            name,
            'type':             img_type,
            'resolution':       f"{W}×{H}",
            'experiment':       exp_name,
            'payload_bits':     n_bits,
            'adaptive_cap':     cap,
            'smooth_pct':       round(s_pct, 1),
            'edge_pct':         round(e_pct, 1),
            'texture_pct':      round(t_pct, 1),
            'psnr_db':          round(psnr, 2),
            'ssim':             round(ssim, 4),
            'mse':              round(mse, 4),
            'npcr_pct':         round(npcr, 4),
            'uaci_pct':         round(uaci, 4),
            'cover_entropy':    round(cover_entropy, 4),
            'stego_entropy':    round(stego_entropy, 4),
            'embed_time_ms':    round(embed_time, 1),
            'chi2_cover':       round(chi2_cover, 2),
            'p_cover':          round(p_cover, 4),
            'chi2_stego':       round(chi2_stego, 2),
            'p_stego':          round(p_stego, 4),
            'rs_cover':         round(rs_cover, 4),
            'rs_stego':         round(rs_stego, 4),
            'hist_dev':         round(hist_dev, 6),
        })
        print(f"  {exp_name}: PSNR={psnr:.2f}dB  SSIM={ssim:.4f}  "
              f"NPCR={npcr:.2f}%  chi2_p={p_stego:.4f}  RS={rs_stego:.4f}")

    return rows

def main():
    cover_dir  = './cover_images'
    output_dir = './results'
    os.makedirs(output_dir, exist_ok=True)
    os.makedirs(cover_dir, exist_ok=True)

    # Find all PNG/TIFF images
    extensions = ('.png', '.tif', '.tiff', '.bmp')
    images = sorted([
        os.path.join(cover_dir, f)
        for f in os.listdir(cover_dir)
        if f.lower().endswith(extensions)
    ])

    if not images:
        print(f"\nNo images found in {cover_dir}/")
        print("Please download USC-SIPI images and place them there.")
        print("See the README below for instructions.")
        return

    print(f"\nFound {len(images)} images. Running experiments...\n")
    all_rows = []
    for img_path in images:
        name = os.path.basename(img_path)
        print(f"\n[{images.index(img_path)+1}/{len(images)}] {name}")
        try:
            rows = run_experiment(img_path, output_dir)
            all_rows.extend(rows)
        except Exception as e:
            print(f"  ERROR: {e}")

    if not all_rows:
        print("No results generated.")
        return

    # Write CSV
    csv_path = os.path.join(output_dir, 'metrics_results.csv')
    fieldnames = list(all_rows[0].keys())
    with open(csv_path, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(all_rows)
    print(f"\n✓ Results saved to {csv_path}")

    # Print summary statistics
    print("\n" + "="*70)
    print("SUMMARY STATISTICS (averaged across all images)")
    print("="*70)
    for exp in PAYLOADS.keys():
        exp_rows = [r for r in all_rows if r['experiment'] == exp]
        if not exp_rows:
            continue
        avg_psnr = sum(r['psnr_db'] for r in exp_rows) / len(exp_rows)
        avg_ssim = sum(r['ssim'] for r in exp_rows) / len(exp_rows)
        avg_npcr = sum(r['npcr_pct'] for r in exp_rows) / len(exp_rows)
        avg_uaci = sum(r['uaci_pct'] for r in exp_rows) / len(exp_rows)
        avg_p    = sum(r['p_stego'] for r in exp_rows) / len(exp_rows)
        avg_rs   = sum(r['rs_stego'] for r in exp_rows) / len(exp_rows)
        print(f"\n  {exp}:")
        print(f"    PSNR:  {avg_psnr:.2f} dB")
        print(f"    SSIM:  {avg_ssim:.4f}")
        print(f"    NPCR:  {avg_npcr:.2f}%")
        print(f"    UACI:  {avg_uaci:.4f}%")
        print(f"    Chi2 p-value: {avg_p:.4f} ({'NOT detected' if avg_p > 0.05 else 'DETECTED'})")
        print(f"    RS ratio:     {avg_rs:.4f}")


# ─────────────────────────────────────────────────────────────────────────────
# README / INSTRUCTIONS (printed if run with --help)
# ─────────────────────────────────────────────────────────────────────────────

README = """
=============================================================================
HOW TO DOWNLOAD USC-SIPI IMAGES AND RUN THIS SCRIPT
=============================================================================

STEP 1 — Install dependencies (Ubuntu / VS Code terminal):
  pip install Pillow numpy scipy

STEP 2 — Download USC-SIPI Miscellaneous Dataset:
  Website: https://sipi.usc.edu/database/database.php?volume=misc

  Option A (direct download, free, no account needed):
    mkdir cover_images
    cd cover_images

    # Download the main test images individually:
    wget "https://sipi.usc.edu/database/misc/4.1.01.tiff" -O lena_512.tiff
    wget "https://sipi.usc.edu/database/misc/4.2.03.tiff" -O baboon_512.tiff
    wget "https://sipi.usc.edu/database/misc/4.1.05.tiff" -O airplane_512.tiff
    wget "https://sipi.usc.edu/database/misc/4.2.06.tiff" -O peppers_512.tiff
    wget "https://sipi.usc.edu/database/misc/4.1.06.tiff" -O boat_512.tiff
    wget "https://sipi.usc.edu/database/misc/4.2.07.tiff" -O zelda_512.tiff
    wget "https://sipi.usc.edu/database/misc/4.1.07.tiff" -O jelly_beans_512.tiff
    wget "https://sipi.usc.edu/database/misc/4.2.01.tiff" -O girl_512.tiff

  Option B (if wget fails — paste URL directly in browser):
    Go to https://sipi.usc.edu/database/database.php?volume=misc
    Click each image to download the TIFF file.
    Save all TIFF files to the ./cover_images/ folder.

  Option C — Use your own 9 PNG images from the dissertation:
    Copy smooth1.png, smooth2.png ... grayscale3.png into ./cover_images/
    The script works with any PNG/TIFF/BMP images.

STEP 3 — Run the script:
  cd /path/to/this/script
  python3 measure_stego_metrics.py

STEP 4 — Find your results:
  ./results/metrics_results.csv   ← all raw numbers for Chapter 4 tables
  The terminal also prints a summary for each experiment.

IMPORTANT NOTES:
  - RS analysis is slow on large images (iterates pixel-by-pixel).
    For 512×512 images expect ~30-60 seconds per image.
    For 1024×1024 images it may take several minutes per image.
    If too slow, set SKIP_RS = True at the top of Section 5.
  - The script uses a Python implementation of the Phase 2 adaptive
    embedding algorithm that mirrors the JavaScript HTML app exactly.
  - Payload bits are randomly generated (seeded at 42) to simulate
    AES-256 ciphertext (uniformly distributed).
=============================================================================
"""

if __name__ == '__main__':
    if '--help' in sys.argv or '-h' in sys.argv:
        print(README)
    else:
        print(README)
        main()
