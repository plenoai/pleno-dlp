#!/usr/bin/env python3
"""Derive the Japanese report from sanitized measurements, without raw secrets."""
from collections import Counter
from datetime import datetime, timezone
import json
import math
from pathlib import Path
import statistics

from study import HERE, ROOT, save


def summarize(inventory, results):
    assert {r["repo"] for r in inventory} == results["repositories"].keys()
    rows = []
    for entry in inventory:
        samples = results["repositories"][entry["repo"]]
        row = {**entry, "tools": {}}
        for tool, values in samples.items():
            assert len(values) == results["runs"] and all(v["canary_found"] for v in values)
            row["tools"][tool] = {
                **{k: statistics.median(v[k] for v in values) for k in ("seconds", "rss_bytes", "findings")},
                "cpu_seconds": statistics.median(v["user_seconds"] + v["system_seconds"] for v in values),
                "seconds_min": min(v["seconds"] for v in values), "seconds_max": max(v["seconds"] for v in values),
                "findings_min": min(v["findings"] for v in values), "findings_max": max(v["findings"] for v in values),
                "stable_locations": len({v["locations_sha256"] for v in values}) == 1,
            }
        p, t = row["tools"]["pleno-dlp"], row["tools"]["trufflehog"]
        row["speedup"] = t["seconds"] / p["seconds"]
        row["rss_ratio"] = p["rss_bytes"] / t["rss_bytes"]
        rows.append(row)
    totals = {}
    for tool in results["tools"]:
        seconds = sum(row["tools"][tool]["seconds"] for row in rows)
        totals[tool] = {
            "seconds": seconds,
            "input_mib_per_second": (sum(row["bytes"] for row in rows) + 54 * len(rows)) / 2**20 / seconds,
            "cpu_seconds": sum(row["tools"][tool]["cpu_seconds"] for row in rows),
            "median_peak_rss_bytes": statistics.median(row["tools"][tool]["rss_bytes"] for row in rows),
            "worst_observed_rss_bytes": max(v["rss_bytes"] for samples in results["repositories"].values() for v in samples[tool]),
            "findings": sum(row["tools"][tool]["findings"] for row in rows),
            "unstable_repositories": [row["repo"] for row in rows if not row["tools"][tool]["stable_locations"]],
        }
    return {"repositories": len(rows), "files": sum(r["files"] for r in rows), "bytes": sum(r["bytes"] for r in rows),
            "totals": totals, "aggregate_speedup": totals["trufflehog"]["seconds"] / totals["pleno-dlp"]["seconds"],
            "geometric_mean_speedup": math.exp(statistics.mean(math.log(r["speedup"]) for r in rows)),
            "pleno_faster_repositories": sum(r["speedup"] > 1 for r in rows),
            "pleno_lower_rss_repositories": sum(r["rss_ratio"] < 1 for r in rows), "rows": rows}


def main():
    inventory = json.loads((HERE / "inventory.json").read_text())
    results = json.loads((HERE / "results.json").read_text())
    accuracy = json.loads((HERE / "accuracy.json").read_text())
    cred_inventory = json.loads((HERE / "creddata-inventory.json").read_text())
    integrity = json.loads((HERE / "input-verification.json").read_text())
    assert integrity["inventories_match"]
    unique_repos = len({r["repo"].lower() for r in inventory + cred_inventory["repositories"]})
    summary = summarize(inventory, results)
    save(HERE / "summary.json", summary)
    p, t = [summary["totals"][tool] for tool in ("pleno-dlp", "trufflehog")]
    pa, ta = [accuracy["tools"][tool]["score"] for tool in ("pleno-dlp", "trufflehog")]
    times = [v["started_unix"] for samples in results["repositories"].values() for values in samples.values() for v in values]
    loads = [v["load_average_after"][0] for samples in results["repositories"].values() for values in samples.values() for v in values]
    excluded = Counter()
    for entry in inventory:
        excluded.update(entry["excluded"])
    positive = pa.get("tp", 0) + pa.get("fn", 0)
    negative = pa.get("fp", 0) + pa.get("tn", 0)
    password = pa["categories"]["Password"]
    uuid = pa["categories"]["UUID"]
    percent = lambda value: "N/A" if value is None else f"{100 * value:.2f}%"
    lines = [
        "# pleno-dlp / TruffleHog 大規模OSS比較レポート",
        "",
        "**実行時間・CPU・メモリは、他の開発作業が同時に動いたMacでの参考値である。専有環境での速度順位や倍率を示すものではない。**",
        "",
        f"計測日（UTC）: {datetime.fromtimestamp(min(times), timezone.utc).date()}。対象: pleno-dlp v0.65.0相当のソースビルド / TruffleHog v3.97.5公式バイナリ。",
        f"性能用50スナップショットと精度用100スナップショットを合わせ、重複を除いて{unique_repos}リポジトリを調べた。",
        "",
        f"50リポジトリの **{summary['files']:,}ファイル・{summary['bytes']/2**30:.2f} GiB** を両ツールで実測した。"
        f"リポジトリ別所要時間の中央値を合計すると、pleno-dlpは **{p['seconds']:.2f}秒**、TruffleHogは **{t['seconds']:.2f}秒**。"
        f"観測された時間比（TruffleHog時間 ÷ pleno-dlp時間）は **{summary['aggregate_speedup']:.2f}倍** だった。"
        f"pleno-dlpの観測時間が短いリポジトリは **{summary['pleno_faster_repositories']}/50**、ピークRSSが小さいものは **{summary['pleno_lower_rss_repositories']}/50** だった。",
        "",
        f"第三者データセットCredDataの100スナップショットでは、正解ラベル付き開始行に限定した再現率はpleno-dlp **{percent(pa['recall_on_labelled_lines'])}**、"
        f"TruffleHog **{percent(ta['recall_on_labelled_lines'])}**、同じ評価範囲での適合率はそれぞれ **{percent(pa['precision_on_labelled_lines'])}**、"
        f"**{percent(ta['precision_on_labelled_lines'])}** だった。これは秘密値単位の精度や、有効な認証情報の発見率ではない。",
        "",
        "## 比較で見つかった技術負債と今回の対応",
        "",
        "| 負債 | 比較への影響 | 対応 |",
        "|---|---|---|",
        "| 過去の実OSSベンチマークが小規模 | 大きなコードツリーに外挿できない | 50リポジトリをコミット固定、入力一覧・サイズ・ハッシュを保存 |",
        "| 既存ベンチのTruffleHog固定版が3.96.0 | 現行版の評価にならない | 計測時最新の3.97.5を取得し公式アーカイブのSHA-256を検証 |",
        "| 既定のパス除外とサイズ上限が異なる | 読んだ量の違いを速度差と誤認する | 同じテキスト入力を渡し、pleno-dlpの既定除外を解除 |",
        "| 検出件数と精度の混同 | 誤検出が多いツールを高性能と誤認する | 実OSSの候補件数と第三者ラベルの混同行列を分離 |",
        "| ダウンロード欠落を検出漏れとして集計する危険 | 再現率を過小評価する | CredDataの全対象ファイルを照合、export-ignore欠落はGitから補完 |",
        "| アーカイブの件数を実ファイル数とみなす | 大文字小文字を区別しないファイルシステムで過大計数する | 展開後の実体を数え、アーカイブ内の件数・ハッシュも別に残す |",
        "",
        "## 対象と測定条件",
        "",
        f"- {results.get('cpu_model', 'CPU model not recorded')}、{results['cpu_count']}論理CPU、{results.get('memory_bytes', 0)/2**30:.2f} GiB、{results['platform']}。{results.get('runner', 'local development machine')}。",
        f"- pleno-dlp: `{results['source_commit']}`、{results['tools']['pleno-dlp'].get('go_version', 'Go version not recorded')}。TruffleHog: {results['tools']['trufflehog']['version']}、{results['tools']['trufflehog'].get('go_version', 'Go version not recorded')}。コンパイラも含む製品構成の比較である。",
        "- 各ツール8ワーカー、`GOMAXPROCS=8`。API検証は両者で無効、pleno-dlpのPIIはoff。各リポジトリ1回のウォームアップ後に3回測定し、実行順を交互に入れ替えた。",
        "- 各回は別プロセス。起動、ファイル読取り、検出、JSONのファイル出力を含む。取得・ビルド・出力の解析は所要時間に含めない。",
        "- 別作業と重なったMacの初回23件の計測を残し、同じバイナリ・引数で残り27件を再開した。競合時に待機する仕組みは明示的に無効化した。クラウド計測は中止し、その値は混ぜていない。重い計測CIは追加していない。",
        f"- 各試行後の1分load averageは **{min(loads):.2f}–{max(loads):.2f}**、中央値 **{statistics.median(loads):.2f}**。load averageはCPU使用率ではなく、これを使って競合のない所要時間へ補正することはできない。",
        *([f"- 実行ログ: [GitHub Actions]({results['workflow_run']})。", ""] if results.get('workflow_run') else []),
        "- 各入力に54バイトの合成GitHubトークン用ファイルを1個追加し、全実行で検出を確認した。候補件数からこの1件を除いた。",
        "- 最新ツリーのソースアーカイブから、1 MiB以下・UTF-8・NULなしの通常ファイルを抽出した。履歴、サブモジュール本体、LFS本体は対象外。GitHubアーカイブのexport-ignoreも適用される。",
        "- `export-subst` により同一コミットでもアーカイブの内容が変わり得る。予備取得と最初のクラウド取得でKubernetesの `hack/lib/version.sh` に28バイトの差があった。両ツールには同じ取得済みツリーを渡した。再実験ではコミットだけでなく入力ハッシュも照合する。",
        "- Mac上ではLinuxの大文字小文字だけが異なる13組のパスが上書きで統合された。アーカイブ内の594,154ファイルに対し、実際に渡したのは594,141ファイルだった。同一SHA-256のLinuxアーカイブを再取得し、上書き順を含めて全実ファイルの内容を照合した。[衝突一覧](../bench/oss-study/case-collisions.json)を保存し、以下は実ファイル数・容量で集計する。",
        f"- アーカイブ内の除外: 非通常ファイル {excluded['non_regular']:,}、1 MiB超 {excluded['over_1_mib']:,}、NULあり {excluded['nul_byte']:,}、非UTF-8 {excluded['non_utf8']:,}。条件はこの順で排他的に計数した。",
        "- 50件は言語・用途の幅を確保するために選んだ有名プロジェクトで、GitHub全体の無作為標本ではない。検出器の種類・フィルタ・重複排除は各製品の既定設定を使う。",
        f"- vendor等に共通コードを含む。内容SHA-256で重複を除くと **{integrity['unique_file_contents']:,}種類・{integrity['unique_content_bytes']/2**30:.2f} GiB**。測定では実ツリーの重複を残したため、ファイル数を独立標本数として扱わない。49件は取得時の入力ハッシュと一致し、Linuxは上記のアーカイブ照合で実体を検証した。",
        f"- 保存した測定サンプルの開始範囲（UTC）: {datetime.fromtimestamp(min(times), timezone.utc).isoformat()} ～ {datetime.fromtimestamp(max(times), timezone.utc).isoformat()}。",
        "",
        "全コミット・入力ハッシュは [manifest.json](../bench/oss-study/manifest.json) と [inventory.json](../bench/oss-study/inventory.json)、"
        "全サンプル・実行引数・バイナリハッシュは [results.json](../bench/oss-study/results.json) に記録した。",
        "",
        "## 実行時間・CPU・メモリ",
        "",
        *(["![Input size, runtime and peak memory](assets/oss-study-2026-09-21/performance.svg)", ""]
          if (ROOT / "docs/assets/oss-study-2026-09-21/performance.svg").exists() else []),
        "| 指標 | pleno-dlp | TruffleHog |",
        "|---|---:|---:|",
        f"| リポジトリ別中央値の時間合計 | {p['seconds']:.2f} s | {t['seconds']:.2f} s |",
        f"| 入力サイズ / 上記時間 | {p['input_mib_per_second']:.2f} MiB/s | {t['input_mib_per_second']:.2f} MiB/s |",
        f"| CPU時間の中央値合計（user + sys） | {p['cpu_seconds']:.2f} s | {t['cpu_seconds']:.2f} s |",
        f"| リポジトリ別ピークRSS中央値の中央値 | {p['median_peak_rss_bytes']/2**20:.2f} MiB | {t['median_peak_rss_bytes']/2**20:.2f} MiB |",
        f"| 全計測中の最大ピークRSS | {p['worst_observed_rss_bytes']/2**20:.2f} MiB | {t['worst_observed_rss_bytes']/2**20:.2f} MiB |",
        f"| 候補件数のリポジトリ別中央値合計 | {p['findings']:,.0f} | {t['findings']:,.0f} |",
        "",
        f"各リポジトリを等しく重み付けした時間比の幾何平均は **{summary['geometric_mean_speedup']:.2f}倍**。"
        "合計時間は大きな入力の影響を受け、幾何平均は小さなプロジェクトの起動時間差も同じ重さで数える。両者を併記した。"
        "MiB/sの分子は渡した入力サイズであり、内部で検査されたバイト数のテレメトリではない。メモリ値を加算して必要RAMと解釈してはいけない。",
        "",
        "各値は3回の反復による記述統計である。同時負荷は試行間で一定ではなく、統計的有意差や競合のない環境での同じ順位・倍率は主張しない。",
        f"検出位置・種別・値ハッシュの集合が反復間で変化したリポジトリはpleno-dlp {len(p['unstable_repositories'])}件、TruffleHog {len(t['unstable_repositories'])}件。"
        "該当リポジトリはsummary.jsonに列挙し、候補件数も中央値で集計した。",
        "",
        "## 正解ラベルによる検出性能",
        "",
        *(["![Labelled-line precision, recall and F1](assets/oss-study-2026-09-21/accuracy.svg)", ""]
          if (ROOT / "docs/assets/oss-study-2026-09-21/accuracy.svg").exists() else []),
        f"[Samsung CredData](https://github.com/Samsung/CredData/tree/{accuracy['creddata_commit']}) の固定版にある337スナップショットから、snapshotキーのSHA-256が小さい順に100件を選んだ。"
        f"検出結果もラベル比率も選択には使っていない。{accuracy['corpus']['files']:,}ファイル、{accuracy['corpus']['bytes']/2**20:.2f} MiBを取得し、公式処理で値を難読化した。"
        "100件すべてのメタデータ対象ファイルが存在することを確認した。",
        "",
        f"評価単位は同じファイルの同じ開始行。Tを正例、F/Xを負例とし、同じ行の重複候補をまとめた。正負が混在する **{pa.get('ambiguous_lines_excluded', 0)}行** は除外した。"
        f"評価対象は正例 **{positive:,}行**、負例 **{negative:,}行**。異なる値が同じ行にある場合の個別抽出精度は評価しない。複数行の値も開始行の完全一致を要求し、別の行で検出した場合は正解に数えない。",
        "行をまとめたmicro集計であり、ラベルが多いリポジトリほど全体値への影響が大きい。リポジトリごとの均等平均ではない。",
        "両ツールを交互に3回実行し、以下は事前に定めた最初の実行の集計を示す。"
        f"カテゴリ別を含む全集計の3回の一致状況: pleno-dlp **{'一致' if accuracy['tools']['pleno-dlp']['score_stable'] else '不一致'}**、TruffleHog **{'一致' if accuracy['tools']['trufflehog']['score_stable'] else '不一致'}**。全反復はaccuracy.jsonに保存した。",
        "",
        "| 指標 | pleno-dlp | TruffleHog |",
        "|---|---:|---:|",
    ]
    for title, key in (("TP: 正例を検出", "tp"), ("FN: 正例を見逃し", "fn"), ("FP: 既知負例を検出", "fp"), ("TN: 既知負例を除外", "tn"),
                       ("未ラベルの検出開始行（精度計算外）", "unlabelled_predicted_lines")):
        lines.append(f"| {title} | {pa.get(key, 0):,} | {ta.get(key, 0):,} |")
    for title, key in (("適合率（ラベル付き行に限定）", "precision_on_labelled_lines"), ("再現率", "recall_on_labelled_lines"), ("F1", "f1_on_labelled_lines")):
        lines.append(f"| {title} | {percent(pa[key])} | {percent(ta[key])} |")
    lines += ["", f"この標本では正例行が `UUID` に **{uuid.get('tp', 0) + uuid.get('fn', 0):,}行**、`Password` に **{password.get('tp', 0) + password.get('fn', 0):,}行** と多い。"
              "特定サービスのAPIキーを中心とする運用へ、この全体値をそのまま一般化できない。"
              f"pleno-dlpも正例 {pa.get('fn', 0):,}行を見逃し、既知負例 {pa.get('fp', 0):,}行を検出した。再現率の相対差だけで運用品質が十分とはいえない。"]
    pk, tk = [accuracy["tools"][tool]["without_private_keys"] for tool in ("pleno-dlp", "trufflehog")]
    lines += ["", "秘密鍵カテゴリを除いた感度分析:", "",
              "| 指標 | pleno-dlp | TruffleHog |", "|---|---:|---:|"]
    for title, key in (("適合率（ラベル付き行に限定）", "precision_on_labelled_lines"), ("再現率", "recall_on_labelled_lines"), ("F1", "f1_on_labelled_lines")):
        lines.append(f"| {title} | {percent(pk[key])} | {percent(tk[key])} |")
    lines += ["", "CredDataの[秘密鍵の匿名化処理](https://github.com/Samsung/CredData/blob/c09c0c52fc6dae4ae5438ae69ba486f9f8059f0d/obfuscate_creds.py#L495)はPEM本文を書き換える。"
              "[TruffleHogの検出器](https://github.com/trufflesecurity/trufflehog/blob/v3.97.5/pkg/detectors/privatekey/privatekey.go#L79)は鍵の解析に失敗すると通常は候補を破棄する一方、"
              "[pleno-dlpの検出器](https://github.com/plenoai/pleno-dlp/blob/3c525ce46a98f4eaa88cf27ba53491f25612bf41/pkg/detectors/privatekey/privatekey.go#L103)はPEMブロックを候補として残す。"
              "したがって、全カテゴリの再現率差には検出方針に加えて匿名化の影響が入り得る。上表ではCategoryに `Private Key` を含む行を除いた。"]
    lines += ["秘密鍵以外の形式に対する匿名化の影響は未評価であり、秘密鍵を除いた数字も匿名化の影響を完全に除いた値ではない。"]
    probe_path = HERE / "pem-probe.json"
    if probe_path.exists():
        probe = json.loads(probe_path.read_text())
        lines += ["", "補助検証では、その場で生成した未使用のRSA-2048鍵と、同じ公式匿名化処理を適用した鍵を比較した。"
                  f"OpenSSLの鍵チェック終了コードは元の鍵 {probe['openssl_check']['original.pem']}、変更後 {probe['openssl_check']['obfuscated.pem']}。"
                  "検出結果は次のとおりだった。これは匿名化で鍵が壊れ得ることを示すもので、CredDataの全秘密鍵が壊れているという主張ではない。",
                  "", "| 補助入力 | pleno-dlp | TruffleHog |", "|---|---:|---:|"]
        for name in ("original.pem", "obfuscated.pem"):
            lines.append(f"| {name} | {probe['tools']['pleno-dlp'].get(name, 0)} | {probe['tools']['trufflehog'].get(name, 0)} |")
    lines += ["", "適合率 = TP/(TP+FP)、再現率 = TP/(TP+FN)、F1 = 2TP/(2TP+FP+FN)。未ラベルの検出行を誤検出として扱っていないため、"
              "この適合率を実OSS全体の適合率として引用してはいけない。CredDataのTにはテスト用の値も含まれ、現在有効な認証情報を意味しない。",
              "", "正例数が多いラベルカテゴリの結果。複数カテゴリが同一行に付く場合があるため、行を単純に合計して全体値に戻すことはできない。",
              "", "| カテゴリ | 正例行 | pleno-dlp TP / 再現率 | TruffleHog TP / 再現率 |", "|---|---:|---:|---:|"]
    categories = sorted(pa["categories"], key=lambda c: pa["categories"][c].get("tp", 0) + pa["categories"][c].get("fn", 0), reverse=True)
    for category in categories[:15]:
        pc, tc = pa["categories"][category], ta["categories"][category]
        total = pc.get("tp", 0) + pc.get("fn", 0)
        if total:
            lines.append(f"| {category} | {total} | {pc.get('tp', 0)} / {percent(pc.get('tp', 0)/total)} | {tc.get('tp', 0)} / {percent(tc.get('tp', 0)/total)} |")
    lines += ["", "全カテゴリと混同行列は [accuracy.json](../bench/oss-study/accuracy.json)、取得元は [creddata-inventory.json](../bench/oss-study/creddata-inventory.json) を参照。",
              "", "## リポジトリ別の実測値", "",
              "時間は中央値［最小–最大］、RSSは各回ピークの中央値。時間比はTruffleHog時間 ÷ pleno-dlp時間で、1超ならpleno-dlpの観測時間が短い。候補数は有効な秘密情報の件数ではない。",
              "", "| リポジトリ | 入力 MiB / ファイル | pleno-dlp 秒［範囲］ | TruffleHog 秒［範囲］ | 時間比 T/P | RSS MiB P / T | 候補 P / T |",
              "|---|---:|---:|---:|---:|---:|---:|"]
    for row in summary["rows"]:
        rp, rt = row["tools"]["pleno-dlp"], row["tools"]["trufflehog"]
        timing = lambda r: f"{r['seconds']:.2f}［{r['seconds_min']:.2f}–{r['seconds_max']:.2f}］"
        lines.append(f"| [{row['repo']}](https://github.com/{row['repo']}/tree/{row['commit']}) | {row['bytes']/2**20:.1f} / {row['files']:,} | {timing(rp)} | {timing(rt)} | {row['speedup']:.2f} | {rp['rss_bytes']/2**20:.1f} / {rt['rss_bytes']/2**20:.1f} | {rp['findings']:.0f} / {rt['findings']:.0f} |")
    lines += ["", "## 適用範囲と次の改善", "",
              "1. 実運用の全体適合率を決めるには、未ラベル候補の独立したレビューが必要である。候補数の多さを検出品質の良さと解釈しない。",
              "公開データを使っているため、既存ツールの開発時に利用されていた可能性は排除できない。第三者が付けたラベルであり、未使用の秘密評価セットではない。",
              "2. 回帰監視には今回の固定入力・ラベル・実行引数を再利用する。性能修正と同時にコーパスや比較版を変えると改善の原因を分離できない。",
              "3. この比較がカバーするのはローカルのテキストスナップショットと静的検出である。Git履歴、アーカイブ、バイナリ、PII、オンライン検証の品質・速度は別のワークロードで測る。",
              f"4. pleno-dlpの既知誤検出 {pa.get('fp', 0):,}行のうち、`Password` カテゴリは **{password.get('fp', 0):,}行**。まずこのカテゴリの文脈判定と除外を改善し、再現率が落ちないか同じラベルで検証する。",
              f"5. `UUID` カテゴリの見逃しはpleno-dlp **{uuid.get('fn', 0):,}行**。UUIDを一律に秘密情報と判定するとノイズを増やすため、認証用途を識別できる文脈とセットで検討する。",
              "6. 両製品の検出器集合が異なり、今回は同時負荷もある。速度最適化の効果を判定する段階では、同じ固定入力を競合のない端末で手動再計測する。重いCIの常時実行は必要ない。",
              "", "再実行手順と集計コード: [bench/oss-study](../bench/oss-study/README.md)。原文の秘密値・生のスキャン出力は公開成果物に含めていない。",
              "TruffleHogの比較版と検証オプションは [公式v3.97.5](https://github.com/trufflesecurity/trufflehog/tree/v3.97.5) を参照。", ""]
    output = ROOT / "docs/oss-comparison-2026-09-21.md"
    output.write_text("\n".join(lines))
    print(output)


if __name__ == "__main__":
    main()
