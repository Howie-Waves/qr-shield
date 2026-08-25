# AI-assisted implementation: written with AI assistance and reviewed by the
# project author.
"""Generate controlled robustness perturbations for E4-US1.

Reads the original QR images placed directly under
``data/test_images/e4_us1_robustness`` and writes deterministically distorted
copies into ``.../e4_us1_robustness/perturbed/<perturbation>/``.

Three controlled perturbations are applied (as requested):
  * rotation           - fixed angles, canvas expanded so nothing is clipped
  * perspective warp   - top edge pinched inward by a fixed fraction
  * gaussian noise      - zero-mean noise at a fixed sigma (seeded, reproducible)

The decoded content (ground truth) is unchanged by these geometric/photometric
transforms, so every perturbed image is expected to decode to the same payload
as its source. A ``perturbations_index.json`` records source/type/param for each
output; it is a generation log only (no ground-truth text yet).
"""

from __future__ import annotations

import io
import json
from pathlib import Path

import cv2
import numpy as np
from PIL import Image


ROOT = Path(__file__).resolve().parents[1]
BASE = ROOT / "data" / "test_images" / "e4_us1_robustness"
OUTPUT = BASE / "perturbed"

# Proprietary / non-standard codes that no open decoder can read (e.g. WeChat
# mini-program "sunflower" codes). Perturbing them only yields noise, so skip.
EXCLUDE = {"小程序.png"}

# Controlled, reproducible parameters.
ROTATION_ANGLES = (10, 25, 45)          # degrees, clockwise
PERSPECTIVE_FRACTIONS = {"mild": 0.10, "strong": 0.22}
NOISE_SIGMAS = (15, 35)
WHITE = (255, 255, 255)
PAD = 24                                 # extra quiet-zone padding before warps


def _load_bgr(path: Path) -> np.ndarray:
    """Load an image as BGR, flattening any transparency onto a white background."""
    with Image.open(io.BytesIO(path.read_bytes())) as image:
        if image.mode in ("RGBA", "LA", "P"):
            rgba = image.convert("RGBA")
            background = Image.new("RGB", rgba.size, WHITE)
            background.paste(rgba, mask=rgba.split()[-1])
            rgb = background
        else:
            rgb = image.convert("RGB")
        return np.array(rgb)[:, :, ::-1].copy()  # RGB -> BGR


def _save(path: Path, image: np.ndarray) -> None:
    """Encode to PNG and write bytes (handles non-ASCII paths on Windows)."""
    ok, encoded = cv2.imencode(".png", image)
    if not ok:
        raise RuntimeError(f"Could not encode {path.name}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(encoded.tobytes())


def _pad(image: np.ndarray, border: int = PAD) -> np.ndarray:
    return cv2.copyMakeBorder(image, border, border, border, border, cv2.BORDER_CONSTANT, value=WHITE)


def rotate(image: np.ndarray, angle: float) -> np.ndarray:
    """Rotate by `angle` degrees, expanding the canvas so no content is clipped."""
    image = _pad(image)
    height, width = image.shape[:2]
    center = (width / 2, height / 2)
    matrix = cv2.getRotationMatrix2D(center, angle, 1.0)
    cos, sin = abs(matrix[0, 0]), abs(matrix[0, 1])
    new_width = int(height * sin + width * cos)
    new_height = int(height * cos + width * sin)
    matrix[0, 2] += (new_width / 2) - center[0]
    matrix[1, 2] += (new_height / 2) - center[1]
    return cv2.warpAffine(
        image, matrix, (new_width, new_height),
        borderMode=cv2.BORDER_CONSTANT, borderValue=WHITE,
    )


def perspective(image: np.ndarray, fraction: float) -> np.ndarray:
    """Apply a fixed trapezoidal perspective by pinching the top edge inward."""
    image = _pad(image)
    height, width = image.shape[:2]
    shift = fraction * width
    source = np.float32([[0, 0], [width, 0], [width, height], [0, height]])
    target = np.float32([[shift, 0], [width - shift, 0], [width, height], [0, height]])
    matrix = cv2.getPerspectiveTransform(source, target)
    return cv2.warpPerspective(
        image, matrix, (width, height),
        borderMode=cv2.BORDER_CONSTANT, borderValue=WHITE,
    )


def gaussian_noise(image: np.ndarray, sigma: float, seed: int) -> np.ndarray:
    """Add zero-mean Gaussian noise at a fixed sigma using a seeded generator."""
    rng = np.random.default_rng(seed)
    noisy = image.astype(np.float32) + rng.normal(0.0, sigma, image.shape)
    return np.clip(noisy, 0, 255).astype(np.uint8)


def generate(base: Path = BASE, output: Path = OUTPUT) -> list[dict]:
    sources = sorted(
        path for path in base.glob("*")
        if path.is_file() and path.suffix.lower() in {".png", ".jpg", ".jpeg"}
        and path.name not in EXCLUDE
    )
    records: list[dict] = []
    for file_index, source in enumerate(sources):
        image = _load_bgr(source)
        stem = source.stem

        for angle in ROTATION_ANGLES:
            name = f"{stem}__rot{angle}.png"
            _save(output / "rotation" / name, rotate(image, angle))
            records.append({"file": f"rotation/{name}", "source": source.name,
                            "perturbation": "rotation", "param": f"{angle}deg"})

        for label, fraction in PERSPECTIVE_FRACTIONS.items():
            name = f"{stem}__persp_{label}.png"
            _save(output / "perspective" / name, perspective(image, fraction))
            records.append({"file": f"perspective/{name}", "source": source.name,
                            "perturbation": "perspective", "param": label})

        for sigma_index, sigma in enumerate(NOISE_SIGMAS):
            name = f"{stem}__noise{sigma}.png"
            seed = 12345 + file_index * 100 + sigma_index
            _save(output / "noise" / name, gaussian_noise(image, sigma, seed))
            records.append({"file": f"noise/{name}", "source": source.name,
                            "perturbation": "noise", "param": f"sigma{sigma}"})

    index = {
        "dataset": "QR Shield E4-US1 controlled perturbations",
        "version": "1.0",
        "sources": [path.name for path in sources],
        "excluded": sorted(EXCLUDE),
        "perturbations": {
            "rotation": [f"{angle}deg" for angle in ROTATION_ANGLES],
            "perspective": list(PERSPECTIVE_FRACTIONS),
            "noise": [f"sigma{sigma}" for sigma in NOISE_SIGMAS],
        },
        "records": records,
    }
    output.mkdir(parents=True, exist_ok=True)
    (output / "perturbations_index.json").write_text(
        json.dumps(index, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    return records


if __name__ == "__main__":
    created = generate()
    print(f"Generated {len(created)} perturbed images under {OUTPUT}")
