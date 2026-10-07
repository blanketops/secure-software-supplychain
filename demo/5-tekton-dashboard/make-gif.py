#!/usr/bin/env python3
"""Assembles the frames record.py saved into one GIF. Needs Pillow.

    make-gif.py frames/ demo.gif [--width 1100] [--ms 900]

Frames identical to the one before them are merged into a longer pause, and
the last frame is held.
"""
import argparse
import glob
import os

from PIL import Image, ImageChops


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('frames')
    parser.add_argument('output')
    parser.add_argument('--width', type=int, default=1100)
    parser.add_argument('--ms', type=int, default=900, help='how long each frame is shown')
    parser.add_argument('--hold', type=int, default=5000, help='how long the last frame is shown')
    args = parser.parse_args()

    images, durations, previous = [], [], None
    for path in sorted(glob.glob(os.path.join(args.frames, '*.png'))):
        image = Image.open(path).convert('RGB')
        image = image.resize((args.width, round(image.height * args.width / image.width)), Image.LANCZOS)
        if previous is not None and ImageChops.difference(image, previous).getbbox() is None:
            durations[-1] += args.ms
            continue
        previous = image
        images.append(image.quantize(colors=128, method=Image.Quantize.MEDIANCUT, dither=Image.Dither.NONE))
        durations.append(args.ms)
    if not images:
        raise SystemExit('no frames')
    durations[-1] = args.hold
    images[0].save(args.output, save_all=True, append_images=images[1:], duration=durations, loop=0, optimize=True)
    print(f'{len(images)} frames, {sum(durations) / 1000:.0f}s, {os.path.getsize(args.output) / 1e6:.1f} MB')


if __name__ == '__main__':
    main()
