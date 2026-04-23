// Audio transcode via ffmpeg. The GHL media API rejects anything
// outside { mp3, wav, ogg, oga } with INVALID_FILE_TYPE — which hits
// on every iPhone voice memo (.m4a), every browser MediaRecorder
// WebM capture (.weba), and a handful of less common formats (.aac,
// .aiff, .caf). We transcode to a universally-playable mp3 before
// sending to GHL.
//
// Output: 64 kbps mono MP3 at 44.1 kHz. Voice-memo quality — matches
// the settings listen.bizapp.club has been using in production for
// months. MP3 is a less efficient codec than AAC (what iPhone uses
// inside .m4a), so naively upscaling to higher bitrates balloons the
// output well past GHL's 25 MB non-video cap and trips 413. 64 kbps
// keeps a 60-min voice memo at ~29 MB — still risky on the edge, so
// the caller does a post-transcode size check below.

const { execFileSync } = require('node:child_process');
const path = require('node:path');
const os = require('node:os');
const fs = require('node:fs');
const { nanoid } = require('nanoid');

/**
 * Transcode the file at `inputPath` to a new mp3 in the OS temp dir.
 * Returns the new file path. Caller is responsible for deleting the
 * temp file after GHL upload completes.
 *
 * Throws Error on failure — ffmpeg stderr is captured and surfaced.
 */
function transcodeToMp3(inputPath) {
  if (!fs.existsSync(inputPath)) {
    throw new Error(`transcode: input missing: ${inputPath}`);
  }
  const outputPath = path.join(os.tmpdir(), 'share-mp3-' + nanoid(10) + '.mp3');
  const args = [
    '-y',                    // overwrite output
    '-hide_banner',
    '-loglevel', 'error',
    '-i', inputPath,
    '-vn',                   // drop any video stream
    '-ac', '1',              // mono — voice memos don't need stereo
    '-ar', '44100',          // 44.1 kHz
    '-codec:a', 'libmp3lame',
    '-b:a', '64k',
    outputPath,
  ];
  try {
    execFileSync('ffmpeg', args, {
      stdio: 'pipe',
      timeout: 5 * 60 * 1000, // 5 min hard cap
    });
  } catch (err) {
    const stderr = (err.stderr || err.stdout || Buffer.from('')).toString();
    try { fs.unlinkSync(outputPath); } catch {}
    throw new Error(`ffmpeg transcode failed: ${(stderr || err.message).slice(0, 400)}`);
  }
  if (!fs.existsSync(outputPath) || fs.statSync(outputPath).size === 0) {
    throw new Error('ffmpeg produced no output');
  }
  return outputPath;
}

module.exports = { transcodeToMp3 };
