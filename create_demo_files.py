"""
create_demo_files.py
=====================
Generates sample files so you can test the full workflow immediately:
  - sample_cover.png   (a 500x500 generated cover image, plenty of capacity)
  - sample_secret.txt  (a small text file to hide)

Usage:
    python create_demo_files.py
"""
import os
from PIL import Image, ImageDraw
import random

OUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "demo_files")


def create_sample_cover(path, size=(500, 500)):
    random.seed(42)
    img = Image.new("RGB", size, (18, 22, 38))
    draw = ImageDraw.Draw(img)

    # Some soft gradient bands + shapes so the image has natural pixel variance
    for y in range(size[1]):
        shade = int(18 + (y / size[1]) * 40)
        draw.line([(0, y), (size[0], y)], fill=(shade, shade + 6, shade + 20))

    for _ in range(60):
        x0 = random.randint(0, size[0])
        y0 = random.randint(0, size[1])
        r = random.randint(5, 40)
        color = (random.randint(20, 80), random.randint(150, 220), random.randint(150, 210))
        draw.ellipse([x0 - r, y0 - r, x0 + r, y0 + r], outline=color, width=2)

    draw.text((20, 20), "SecureStego Sample Cover Image", fill=(200, 220, 240))
    img.save(path, format="PNG")
    print(f"Created cover image: {path} ({size[0]}x{size[1]})")


def create_sample_secret(path):
    content = (
        "SECURE FILE SHARING WITH STEGANOGRAPHY\n"
        "=======================================\n\n"
        "This is a sample secret file used to demonstrate the complete\n"
        "encryption -> LSB embedding -> extraction -> decryption pipeline.\n\n"
        "If you can read this after extracting it from a stego image,\n"
        "the entire system is working correctly end-to-end.\n\n"
        "Try embedding this file into sample_cover.png with a password,\n"
        "then extract it back out and compare the SHA-256 hashes.\n"
    )
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    print(f"Created secret file: {path} ({len(content.encode('utf-8'))} bytes)")


if __name__ == "__main__":
    os.makedirs(OUT_DIR, exist_ok=True)
    create_sample_cover(os.path.join(OUT_DIR, "sample_cover.png"))
    create_sample_secret(os.path.join(OUT_DIR, "sample_secret.txt"))
    print(f"\nDemo files ready in: {OUT_DIR}")
    print("Run the app (python run.py), register an account, then use these files "
          "on the Embed and Extract pages to test the full workflow.")
