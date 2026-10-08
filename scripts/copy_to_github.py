"""11 milyon karar setini Hugging Face'ten GitHub'a (Releases) kopyalar.
Ücretsiz, kart gerektirmez; her dosya 2 GB'tan küçük olmalı. Lisans: CC0-1.0."""
from __future__ import annotations
import json, os, shutil, subprocess, sys, tempfile, time
from huggingface_hub import HfApi, hf_hub_download

MIRRORS = [
    "hamzabagirsakci/turkish-court-decisions",
    "esnucil/turkish-court-decisions",
    "geginhug/turkish-court-decisions",
    "Alptekinege/turkish-court-decisions",
    "serdarsrts/turkish-court-decisions-duplicate",
    "Gyrevortex/turkish-court-decisions",
    "mrfg/turkish-court-decisions",
]
TAG = "veri-11m"
MAX_ASSET = 2 * 1024**3 - 1
EXPECTED_TOTAL = 11_045_085


def gh(*args, check=True):
    r = subprocess.run(["gh", *args], capture_output=True, text=True)
    if check and r.returncode != 0:
        sys.exit(f"HATA (gh {' '.join(args[:2])}): {r.stderr.strip()[:500]}")
    return r.stdout


def asset_name(path):
    return path.replace("/", "__")


def pick_mirror(api):
    extra = os.environ.get("HF_REPO", "").strip()
    for repo in ([extra] if extra else []) + MIRRORS:
        try:
            files = [f for f in api.list_repo_tree(repo, repo_type="dataset", recursive=True)
                     if getattr(f, "size", None) is not None]
            if any(f.path.endswith(".parquet") for f in files):
                print(f"Kaynak bulundu: {repo}")
                return repo, files
            print(f"{repo}: parquet dosyası yok, atlanıyor")
        except Exception as exc:
            print(f"{repo}: erişilemedi ({type(exc).__name__})")
    sys.exit("HATA: Hiçbir ayna erişilebilir değil. 'hf_repo' kutusuna yeni bir kopya adı yazıp tekrar çalıştırın.")


def main():
    api = HfApi()
    repo, files = pick_mirror(api)
    files = [f for f in files if f.path.endswith((".parquet", ".md"))]
    total = sum(f.size for f in files)
    print(f"Toplam {len(files)} dosya, {total / 1e9:.2f} GB")
    too_big = [f.path for f in files if f.size > MAX_ASSET]
    if too_big:
        sys.exit("DURDURULDU: 2 GB'tan büyük dosya var: " + ", ".join(too_big))
    if subprocess.run(["gh", "release", "view", TAG], capture_output=True).returncode != 0:
        gh("release", "create", TAG, "--title", "11 milyon karar verisi (CC0)",
           "--notes", f"Kaynak: huggingface.co/datasets/{repo} — lisans CC0-1.0. Otomatik kopya.")
    existing = {a["name"]: a["size"] for a in json.loads(gh("release", "view", TAG, "--json", "assets"))["assets"]}
    manifest = {"source_repo": repo, "license": "CC0-1.0", "expected_rows": EXPECTED_TOTAL,
                "copied_at": int(time.time()), "release_tag": TAG, "files": []}
    done = 0
    for i, f in enumerate(files, 1):
        name = asset_name(f.path)
        manifest["files"].append({"path": f.path, "asset": name, "size": f.size})
        if existing.get(name) == f.size:
            done += f.size
            print(f"[{i}/{len(files)}] zaten var: {name}")
            continue
        tmp = tempfile.mkdtemp(prefix="hf_")
        try:
            local = hf_hub_download(repo, f.path, repo_type="dataset", local_dir=tmp)
            target = os.path.join(tmp, name)
            os.replace(local, target)
            gh("release", "upload", TAG, target, "--clobber")
            done += f.size
            print(f"[{i}/{len(files)}] yüklendi: {name} ({f.size / 1e6:.0f} MB) — toplam %{100 * done / total:.1f}")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
            shutil.rmtree(os.path.expanduser("~/.cache/huggingface"), ignore_errors=True)
    mpath = os.path.join(tempfile.mkdtemp(), "manifest.json")
    with open(mpath, "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, ensure_ascii=False, indent=1)
    gh("release", "upload", TAG, mpath, "--clobber")
    print("TAMAMLANDI: Tüm dosyalar GitHub'da 'veri-11m' sürümünde.")


if __name__ == "__main__":
    main()
