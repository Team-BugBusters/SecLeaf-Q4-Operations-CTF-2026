# Night Shift Keying – full writeup

[← Back to Hardware](../README.md) · [Challenge overview](README.md)

**Category:** Hardware · **Points:** 80 · **Flag:** `SecLeaf{R4d10_W4v35}`

**Author:** [Rutwik](https://github.com/Rutwik-712) · **Team:** Bug Busters

## TL;DR

1. `signal.wav` is 30 s of low-level noise followed by a 0.178 s burst that is about 26 times louder.
2. Crop the burst: `sox signal.wav burst.wav trim 30`.
3. Demodulate it as 1200-baud Bell 202 AFSK (mark 1200 Hz, space 2200 Hz) with 8N1 ASCII framing: `minimodem --rx 1200 --mark 1200 --space 2200 ...`.
4. Output: `SecLeaf{R4d10_W4v35}`.

## The challenge

We were given `signal.wav`, a noisy radio recording that hides a short data transmission. The job was to find the transmission and turn it back into text.

The title is the hint. *Night Shift Keying* is a pun on **Frequency Shift Keying (FSK)**. FSK sends digital data by switching a carrier between two frequencies, one standing for binary 1 ("mark") and the other for 0 ("space"). AFSK (audio FSK) does the same with two audible tones, so a modem's bit stream can travel over a voice radio channel or be stored in an ordinary WAV file.

The challenge information pointed at 1200-baud AFSK, so we treated the file as a modem signal rather than as noise with text hidden in it some other way.

## Step 1 – Inspect the recording

```bash
soxi signal.wav
```

| Property | Value |
| --- | --- |
| Channels | 1 (mono) |
| Sample rate | 44,100 Hz |
| Encoding | 16-bit signed integer PCM |
| Samples | 1,330,864 |
| Duration | ~30.18 s |

Plain PCM at a standard rate: no resampling or conversion needed before decoding.

Two different rates are in play, and it helps not to confuse them. The **sample rate** (44,100 Hz) is how finely the audio waveform was recorded. The **baud rate** (1200) is how fast the transmitted symbols change. At 44.1 kHz each 1200-baud bit spans about 36.75 samples, which is plenty to tell the two tones apart.

## Step 2 – Find the burst

A data burst at full volume should stand out from background noise in plain loudness. We measured the RMS amplitude (the average signal strength) of the first 30 seconds and of everything after:

```bash
sox signal.wav -n trim 0 30 stat
sox signal.wav -n trim 30 stat
```

(`trim` selects the time range, `-n` discards the audio output, `stat` prints measurements.)

| Section | Length | RMS amplitude |
| --- | --- | ---: |
| 0–30 s | 30.000000 s | 0.026966 |
| 30 s–end | 0.178322 s (7,864 samples) | 0.707093 |

The tail is about 26 times stronger than the rest. An RMS of 0.707 is also what a full-scale sine wave gives (1/√2), which is what a steady tone looks like. So the last 0.178 s is the transmission and the first 30 s is cover noise.

We cut it out, keeping the original sample rate and encoding:

```bash
sox signal.wav burst.wav trim 30
```

With only a start time, `trim` keeps everything from 30 s to the end.

## Step 3 – Choose the modem settings

1200-baud AFSK almost always means **Bell 202**:

| Setting | Value | Meaning |
| --- | --- | --- |
| Baud | 1200 | 1200 symbols per second, one bit each |
| Mark | 1200 Hz | logical 1 (also the idle line state) |
| Space | 2200 Hz | logical 0 |
| Framing | 8N1 | 1 start bit, 8 data bits, no parity, 1 stop bit |

Bell 202 at 1200 baud is also the physical layer used in amateur packet radio, which could mean AX.25 frames on top. The tones alone do not decide that, so we tried the simplest framing first, plain asynchronous ASCII, and it produced readable output.

How 8N1 works: the line idles on the mark tone. Each character starts with one space bit (the start bit, which also lets the receiver resynchronise), then eight data bits, least significant first, then one mark bit (the stop bit). Ten bit times per character.

## Step 4 – Decode

```bash
minimodem --rx 1200 --mark 1200 --space 2200 \
          --ascii --startbits 1 --stopbits 1 -f burst.wav
```

`--rx 1200` sets the receive rate, `--mark`/`--space` set the two tones, `--startbits`/`--stopbits` set the framing, and `-f` reads the WAV instead of a microphone.

```text
### CARRIER 1200 @ 1200.0 Hz ###
SecLeaf{R4d10_W4v35}
```

minimodem's diagnostics estimated the rate at 1198.37 bits per second, within a fraction of a percent of the configured 1200. A correct rate estimate plus readable text is strong evidence that the tone pair, rate and framing are all right.

## Step 5 – Sanity checks

- **Uncropped file.** Running the same command on the full `signal.wav` also produces the flag at the end, but preceded by junk characters the demodulator invents from the noise. Cropping removes that.
- **Does the size fit?** One bit lasts 1/1200 s ≈ 0.833 ms; an 8N1 character is 10 bits ≈ 8.3 ms. The 20-character flag is 200 bits ≈ 0.167 s, which fits inside the 0.178 s burst with a little room to spare.
- **No further layers.** The output is already a `SecLeaf{...}` string; no Base64 or decryption was needed.

## Flag

```text
SecLeaf{R4d10_W4v35}
```

## Why this is the right answer

- The burst was located by measurement (26x RMS jump), not by ear.
- The demodulator locked onto a carrier at exactly the mark frequency and measured the bit rate at 1198.37 bps, matching 1200 baud.
- The decoded text is clean printable ASCII in the event's flag format, and it reads "Radio Waves", which matches the challenge theme.
- The timing arithmetic (20 characters × 10 bits ÷ 1200 baud ≈ 0.167 s) is consistent with the 0.178 s burst length.

## What we learned

- **Check the whole recording.** A short transmission can sit at the very end of a long, boring file.
- **Isolate before you decode.** Cropping to the loud region turned a noisy decode into a clean one.
- **Baud rate is not enough.** The tone pair (mark/space) and the character framing (start/stop bits, parity) must also match.
- **Try the simplest framing first.** Bell 202 suggested packet radio, but plain asynchronous ASCII was the actual format.

## Reproduce

With SoX and minimodem:

```bash
sox signal.wav burst.wav trim 30
minimodem --rx 1200 --mark 1200 --space 2200 \
          --ascii --startbits 1 --stopbits 1 -f burst.wav
```

Without any tools beyond Python, the solver repeats the same steps: it finds the burst with a windowed RMS, measures the strength of the 1200 Hz and 2200 Hz tones over a one-bit sliding window, and reads 8N1 characters from the resulting bit stream.

```bash
# copy signal.wav into ../attachments/ first
cd solve
python3 solve.py
```

Full solver: [`solve/solve.py`](solve/solve.py)

---

[← Back to Hardware](../README.md) · [Challenge overview](README.md)
