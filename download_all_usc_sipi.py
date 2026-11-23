#!/usr/bin/env python3
"""
Download ALL working images from USC‑SIPI Miscellaneous volume,
convert to PNG, and store in ./cover_images/.
Uses live web scraping to get the exact URLs.
"""

import os
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from PIL import Image
import tempfile
import time

# ----------------------------------------------------------------------
# CONFIGURATION
# ----------------------------------------------------------------------
MISC_URL = "https://sipi.usc.edu/database/database.php?volume=misc"
OUTPUT_DIR = "./cover_images"
USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
TIMEOUT = 30

# ----------------------------------------------------------------------
# FUNCTIONS
# ----------------------------------------------------------------------
def get_misc_image_links():
    """Scrape the Miscellaneous volume page and return all image URLs."""
    headers = {"User-Agent": USER_AGENT}
    resp = requests.get(MISC_URL, headers=headers, timeout=TIMEOUT)
    resp.raise_for_status()
    soup = BeautifulSoup(resp.text, "html.parser")
    
    links = []
    for a in soup.find_all("a", href=True):
        href = a["href"]
        if href.lower().endswith((".tiff", ".tif")):
            full = urljoin("https://sipi.usc.edu/database/", href)
            links.append(full)
    # Remove duplicates
    seen = set()
    unique = []
    for link in links:
        if link not in seen:
            seen.add(link)
            unique.append(link)
    return unique

def download_file(url, dest_path):
    """Download a file with simple progress indicator."""
    headers = {"User-Agent": USER_AGENT}
    response = requests.get(url, headers=headers, stream=True, timeout=TIMEOUT)
    response.raise_for_status()
    total = int(response.headers.get("content-length", 0))
    downloaded = 0
    with open(dest_path, "wb") as f:
        for chunk in response.iter_content(chunk_size=8192):
            if chunk:
                f.write(chunk)
                downloaded += len(chunk)
                if total:
                    percent = (downloaded / total) * 100
                    print(f"\r    Progress: {percent:.1f}%", end="")
    print()

def convert_tiff_to_png(tiff_path, png_path):
    with Image.open(tiff_path) as img:
        # Convert to RGB if necessary (e.g., palette or grayscale)
        if img.mode not in ("RGB", "RGBA"):
            img = img.convert("RGB")
        img.save(png_path, "PNG")

# ----------------------------------------------------------------------
# MAIN
# ----------------------------------------------------------------------
def main():
    print("🔍 Fetching image list from USC‑SIPI Miscellaneous page...")
    try:
        urls = get_misc_image_links()
    except Exception as e:
        print(f"❌ Failed to fetch page: {e}")
        return

    if not urls:
        print("❌ No image links found. The website structure may have changed.")
        return

    print(f"✅ Found {len(urls)} images.")
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    for idx, url in enumerate(urls, 1):
        orig_name = os.path.basename(url.split("?")[0])
        if not orig_name:
            orig_name = f"misc_{idx}.tiff"
        png_name = os.path.splitext(orig_name)[0] + ".png"
        png_path = os.path.join(OUTPUT_DIR, png_name)

        if os.path.exists(png_path):
            print(f"[{idx}/{len(urls)}] ⏭️  {png_name} already exists – skipping")
            continue

        print(f"[{idx}/{len(urls)}] ⬇️  Downloading {orig_name} ...")
        with tempfile.NamedTemporaryFile(suffix=".tiff", delete=False) as tmp:
            tmp_path = tmp.name

        try:
            download_file(url, tmp_path)
            print(f"    Converting to PNG ...")
            convert_tiff_to_png(tmp_path, png_path)
            print(f"    ✅ Saved {png_name}")
        except Exception as e:
            print(f"    ❌ Failed: {e}")
        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
        time.sleep(0.5)  # be polite to the server

    print(f"\n🎉 Done. {len(urls)} images (converted to PNG) are in '{OUTPUT_DIR}/'.")

if __name__ == "__main__":
    main()