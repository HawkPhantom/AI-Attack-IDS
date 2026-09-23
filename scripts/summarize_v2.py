#!/usr/bin/env python3
"""Generate the reviewable corrected report from persisted experiment outputs."""
import hashlib
import json
import re
from collections import Counter
from pathlib import Path
import numpy as np

ROOT=Path(__file__).resolve().parents[1]

def f(x): return '—' if x is None else f'{x:.3f}'

def main():
    host=json.loads((ROOT/'experiments/host_v2.json').read_text())
    net=json.loads((ROOT/'experiments/network_v2.json').read_text())
    intent=json.loads((ROOT/'experiments/intent_v2.json').read_text())
    sessions=[json.loads(p.read_text()) for p in sorted((ROOT/'harness/runs/corrected_v2').glob('*.json'))]
    counts=Counter(r['origin'] for r in sessions)
    zero=Counter(r['origin'] for r in sessions if r['network']['zero_traffic'])
    collector_errors=[(r['id'], e) for r in sessions for e in r.get('errors', [])]
    lines=['# Düzeltilmiş host + network deneyleri (v2)',
           '', 'Bu rapor README/REPORT içindeki tarihsel sayısal iddiaların yerine geçer. '
           'Kod/protokol hataları düzeltildi; gerçek insanlarla eş görevli veri toplama ve bağımsız ajan altyapıları henüz tamamlanmadı.',
           '', '## Deney kapsamı', '',
           f'- Yeni eşlenmiş oturum sayısı: **{len(sessions)}**; köken dağılımı: `{dict(counts)}`.',
           f'- Sıfır giden-trafik oturumları: `{dict(zero)}`. Bunlar analizden çıkarılmadı.',
           f'- Veri toplama sırasında `{len(collector_errors)}` oturumda collector hatası kaldı; bunlar sonuçlarda ayrı tutuldu ve başarılı model oturumu sayılmadı.',
           '- Her yeni oturumda komutlar ve pcap birlikte kaydedildi. Dört yerel model, iki servis profili, iki bağlam politikası ve iki görev kullanıldı.',
           '- İnsan sınıfı yeni bir insan katılımcı çalışması değil, arşivlenmiş insan komutlarının replay verisidir. Script kontrolleri ayrı tutulur.',
           '- Tarihsel network pcap sayısı: 14 (8 AI, 6 replay). Port 22 paketleri eski yakalama filtresi yüzünden geri getirilemez.',
           '', '## Host: sürücü kaynaklı dönüşüm denetimi', '']
    audit=host['audit']
    lines += [f"Malicious/evasion tarihsel verisinde {audit['recorded_commands']} kayıtlı komutun "
              f"**{audit['known_substitutions']}** tanesi ham model çıktısından çıkarılan komutla uyuşmuyor. "
              'Bu dönüşümler model tarafından yazılmış komut analizinden çıkarıldı.',
              '', f"Durum kontrolü komutları: kayıtlı {audit['recorded_state_checks']}; dönüşümler çıkarılınca {audit['authored_state_checks']}. "
              'Bu düşüş, promptların durum kontrolünü teşvik etme etkisini ortadan kaldırmaz.',
              '', f"İnsan train/calibration/test sayıları: `{host['human_split']}`. Gruplar birbirinden ayrıdır. "
              'Tarihsel heuristic filtreler kaldırıldığı, benign AI çıkarıldığı ve iki AI ortamı birlikte kullanıldığı için eski skorlarla fark tek bir düzeltmenin etkisi değildir.',
              '', '## Host: görülmemiş model', '',
              'Aynı ilk-20-komut sınırı ve yalnız eğitimden türetilen ortak sözlük, tüm host modellerine uygulanır. '
              'GNN üç tohumla çalıştırıldı. Tablodaki aralık güven aralığı değil, tohumlar arası min–max değeridir.', '',
              '| Dışarıda tutulan model | AI n | SVC recall | SVC %95 Wilson | SVC FPR | GNN recall aralığı | Ensemble recall aralığı |',
              '|---|---:|---:|---|---:|---|---|']
    for fold in host['folds']:
        if not fold['fold'].startswith('model:'): continue
        m=fold['models']['svc']['default']
        g=[fold['models'][f'graph_seed{s}']['default']['recall'] for s in host['seeds']]
        e=[fold['models'][f'ensemble_seed{s}']['default']['recall'] for s in host['seeds']]
        lines.append(f"| {fold['fold'][6:]} | {m['n_ai']} | {f(m['recall'])} | {f(m['recall_wilson95'][0])}–{f(m['recall_wilson95'][1])} | {f(m['fpr'])} | {f(min(g))}–{f(max(g))} | {f(min(e))}–{f(max(e))} |")
    lines += ['', '**Sonuç:** evrensel 1.00 GNN/ensemble tabanı korunmuyor. '
              'SVC, kategori-frekansı, sırası karıştırılmış grafik ve kenarsız grafik sonuçları birlikte değerlendirilmelidir; '
              'yüksek skor tek başına topolojinin katkısını kanıtlamaz.', '',
              '### Grafik katkısı: model foldlarının ortalama recall değeri', '',
              '| Yöntem | Ortalama recall | Ortalama insan FPR |','|---|---:|---:|']
    folds=[x for x in host['folds'] if x['fold'].startswith('model:')]
    for method in ('svc','categories','graph_seed42','shuffle_seed42','no_edges_seed42','ensemble_seed42'):
        ms=[x['models'][method]['default'] for x in folds]
        lines.append(f"| {method} | {f(np.mean([m['recall'] for m in ms]))} | {f(np.mean([m['fpr'] for m in ms]))} |")
    lines += ['', 'Bu ortalamalar model foldlarına eşit ağırlık verir. Aynı insan test grubu farklı foldlarda tekrar kullanılır; '
              'bunlar bağımsız yeni insan gözlemleri olarak toplanmaz.', '',
              '### Diğer host kontrolleri', '', '| Deney | SVC recall | SVC FPR | Macro F1 |','|---|---:|---:|---:|']
    for fold in host['folds']:
        if fold['fold'].startswith('model:'): continue
        m=fold['models']['svc']['default']
        lines.append(f"| {fold['fold']} | {f(m['recall'])} | {f(m['fpr'])} | {f(m['macro_f1'])} |")
    lines += ['', '### Düşük FPR hedefi', '',
              'Eşikler yalnız 80 calibration insanından seçilir; test insanı sayısı 40 olduğu için test FPR çözünürlüğü %2.5’tir. '
              'Bu veriyle %1 gerçek popülasyon FPR garantisi verilmez. Ayrıntılı hedef/gerçekleşen değerler `host_v2.json` içindedir.', '',
              '| Dışarıda tutulan model | %1 hedefinde recall / test FPR | %5 hedefinde recall / test FPR |',
              '|---|---|---|']
    for fold in folds:
        vals=[fold['models']['svc'][f'calibrated_fpr_{v}']['metrics'] for v in (.01,.05)]
        lines.append(f"| {fold['fold'][6:]} | {f(vals[0]['recall'])} / {f(vals[0]['fpr'])} | {f(vals[1]['recall'])} / {f(vals[1]['fpr'])} |")
    lines += ['', '### GNN kaçınma ve durum-komutu kontrolleri', '',
              '| Deney | SVC recall | GNN ortalama recall / FPR | Ensemble ortalama recall / FPR |',
              '|---|---:|---|---|']
    for fold in host['folds']:
        if not fold['fold'].startswith(('evasion:', 'evasion_retrain:', 'no_state:')): continue
        mm=fold['models']
        if 'graph_seed42' not in mm: continue
        gg=[mm[f'graph_seed{s}']['default'] for s in host['seeds']]
        ee=[mm[f'ensemble_seed{s}']['default'] for s in host['seeds']]
        lines.append(f"| {fold['fold']} | {f(mm['svc']['default']['recall'])} | {f(np.mean([x['recall'] for x in gg]))} / {f(np.mean([x['fpr'] for x in gg]))} | {f(np.mean([x['recall'] for x in ee]))} / {f(np.mean([x['fpr'] for x in ee]))} |")
    artifact_path=ROOT/'experiments/artifact_ablation_v2.json'
    if artifact_path.exists():
        artifact=json.loads(artifact_path.read_text())
        lines += ['', '## Tek değişkenli artefakt kontrolleri', '',
                  'Aynı örneklem ve splitler korunarak yalnız tarihsel komut dönüşümlerini çıkarmanın SVC recall etkisi:', '',
                  '| Model | Kayıtlı komutlar | Modelden çıkarılan komutlar |','|---|---:|---:|']
        for row in artifact['host']:
            lines.append(f"| {row['held']} | {f(row['conditions']['recorded']['default']['recall'])} | {f(row['conditions']['authored']['default']['recall'])} |")
        n=artifact['network']
        lines += ['', f"Aynı 14 pcap, aynı Random Forest ve oturum-dışı split ile eski network özelliklerinin macro F1'i **{f(n['legacy']['metrics']['macro_f1'])}**, yön ayrımı düzeltildikten sonra **{f(n['directional']['metrics']['macro_f1'])}**. "
                  'Bu bir ön-işleme ablation kontrolüdür; görülmemiş model genelleme deneyi değildir.']
    lines += ['', '## Network ve ortak katman değerlendirmesi', '',
              'Aşağıdaki değerler aynı test oturumlarında macro F1’dir. AI modelinin tüm oturumları eğitimden çıkarılır; '
              'negatif replay kaynak grupları da train/calibration/test arasında ayrılır. Zamanlamasız network, '
              'paket hızını ve SYN aralıklarını kullanmaz; araç seçimi/tarama bütçesi karışıklığı yine kalabilir.', '',
              '| Veri / fold | Host | Network (zamansız) | Host+network (zamansız) | Network (+zamanlama) | Host+network (+zamanlama) |',
              '|---|---:|---:|---:|---:|---:|']
    for kind,title in [('legacy_folds','Eski pcap'),('corrected_folds','Yeni eşlenmiş')]:
        for fold in net[kind]:
            if fold['fold'].startswith('counterfactual:'): continue
            if not fold.get('models'): continue
            vals=[fold['models'][k]['default']['macro_f1'] for k in ('host_only','network_no_timing','host_network_no_timing','network_with_timing','host_network_with_timing')]
            lines.append('| '+title+' / '+fold['fold']+' | '+' | '.join(f(v) for v in vals)+' |')
    lines += ['', 'Yeni negatifler canlı insan değil replay olduğundan bu sonuçlar insan–AI saha başarısı değildir. '
              'AI’ye verilen dar port bütçesi ile arşiv komutlarının görevleri aynı değildir. '
              'Dört script kontrolü eğitimde görülmemiştir; bunların F1’i yalnız negatiflerden oluştuğu için aşağıda daha anlamlı olan yanlış alarm oranı ayrıca verilir.', '',
              '| Yöntem | Görülmemiş script FPR |','|---|---:|']
    for fold in net['corrected_folds']:
        if fold['fold']!='unseen_script_controls': continue
        for method,m in fold.get('models',{}).items():
            lines.append(f"| {method} | {f(m['default']['fpr'])} |")
    lines += ['', '### Komut üretebilen AI oturumlarıyla duyarlılık kontrolü', '',
              f"Komut üreten AI oturumu: {net.get('nonempty_ai_n',0)}. Tam-denominator sonuçları yukarıdadır; "
              "`nonempty_ai_folds` içindeki ikinci analiz boş ajan yanıtlarının ayrımı ne kadar taşıdığını gösterir.", '',
              '| Dışarıda tutulan model | Host F1 | Network zamansız F1 | Birleşik zamansız F1 |','|---|---:|---:|---:|']
    for fold in net.get('nonempty_ai_folds',[]):
        if not fold['fold'].startswith('model:') or not fold.get('models'): continue
        vals=[fold['models'][k]['default']['macro_f1'] for k in ('host_only','network_no_timing','host_network_no_timing')]
        lines.append('| '+fold['fold'][6:]+' | '+' | '.join(f(v) for v in vals)+' |')
    lines += ['', '### Aynı AI komutlarının script olarak tekrar oynatılması', '',
              'Bu kontrol, komut kaynağı ile o anda karar veren operatörü ayırır. Host girdisi aynıdır; '
              'yalnız yürütme/zamanlama ve ağ tepkileri değişebilir. Skorlar kalibre edilmiş olasılık değildir.', '',
              '| Çift | Host AI / script skoru | Network zamansız AI / script skoru | Network zamanlı AI / script skoru |',
              '|---|---|---|---|']
    for fold in net['corrected_folds']:
        if not fold['fold'].startswith('counterfactual:') or not fold.get('models'): continue
        vals=[]
        for k in ('host_only','network_no_timing','network_with_timing'):
            ps=fold['models'][k]['predictions']
            vals.append(' / '.join(f(p['score']) for p in ps))
        lines.append('| '+fold['fold'].split('counterfactual_',1)[-1]+' | '+' | '.join(vals)+' |')
    coverage_path=ROOT/'experiments/task_coverage_v2.json'
    if coverage_path.exists():
        coverage=json.loads(coverage_path.read_text())
        lines += ['', '## Görev kapsamı ve yürütme başarısızlıkları', '',
                  'Kapsam, beklenen açık servislerden pcap içinde SYN+ACK yanıtı gözlenenlerin oranıdır. '
                  'Ajanın çıktıyı doğru anladığını veya exploit yaptığını kanıtlamaz. '
                  'Buna rağmen hiç ilerlemeyen ajanları başarılı recon ile karıştırmamak için yararlıdır.', '',
                  '| Model / köken | Oturum | Ortalama açık-servis kapsamı | Çalıştırılan komut | Timeout | Sıfır dışı çıkış kodu |',
                  '|---|---:|---:|---:|---:|---:|']
        keys=sorted({r['model'] if r['origin']=='ai' else r['origin'] for r in coverage})
        for key in keys:
            rr=[r for r in coverage if (r['model'] if r['origin']=='ai' else r['origin'])==key]
            lines.append(f"| {key} | {len(rr)} | {f(np.mean([r['coverage_proxy'] for r in rr]))} | {sum(r['executed'] for r in rr)} | {sum(r['timeouts'] for r in rr)} | {sum(r['nonzero_exits'] for r in rr)} |")
    retry_path=ROOT/'experiments/collector_retries.json'
    if retry_path.exists():
        retries=json.loads(retry_path.read_text())
        lines += ['', '### Veri toplama hataları ve tekrarlar', '',
                  f"{len(retries)} denemede servis banner'ı UTF-8 çözümleme hatası oluştu. İlk denemeler `collector_failures/` altında pcap ile saklandı; "
                  'hata düzeltildikten sonra aynı görev/tohumla tekrarlandı. Boş model yanıtları, retler ve shell hataları bu nedenle yeniden denenmedi. '
                  'Ayrıntılar `collector_retries.json` içindedir.']
    lines += ['', '## Niyet ekseni', '',
              f"Tüm korpuslarda grup-dışı macro F1: **{f(intent['all_corpora_grouped']['metrics']['macro_f1'])}**. "
              f"Yalnız AI içinde model-dışı macro F1: **{f(intent['ai_only_leave_model_out']['metrics']['macro_f1'])}**.", '',
              'Bunlar kötü niyetin bağımsız doğrulanması değildir: MUNI ve Schonlau farklı kaynak/dönemlerdir. '
              'Etiketler gerçek zarar kanıtından değil verilen görevlerden gelir. Canlı, eş görevli insan benign/malicious deneyi olmadan '
              'bu sorun çözülmüş sayılmaz.', '',
              '## Tamamlananlar ve kalanlar', '',
              '- Tamamlandı: komut fallback düzeltmesi, provenance kayıtları, yönlü network özellikleri, SYN tabanlı SSH yönü, '
              'eğitim-içi ön işleme, aynı girdili modeller, üç GNN tohumu, ablation kontrolleri, Wilson aralıkları ve calibration eşikleri.',
              '- Tamamlandı: tarihsel host/pcap yeniden analizi ve yeni eşlenmiş laboratuvar koleksiyonu; '
              'aynı splitlerde host/network/birleşik değerlendirme; script ve başarısız-ajan kontrolleri.',
              '- Kalan: aynı görev ve bütçede canlı insan katılımcıları, bağımsız ajan frameworkleri, daha geniş görev/ortam örneklemi, '
              'yeni protokolde görev başarısı korunarak adaptif kaçınma, gerçek ağ jitter/loss deneyi, bağımsız saha testi.',
              '- HASSH için yeni bir AI-origin doğrulaması yapılmadı. İstemci kimliği otonom AI operatörünün kanıtı değildir.',
              '', '## Tekrar üretim ve artefaktlar', '',
              '- [Protokol ve çalıştırma komutları](PROTOCOL.md)',
              '- [Host tahminleri, CI ve eşikler](host_v2.json)',
              '- [Network ve birleşik katman tahminleri](network_v2.json)',
              '- [Niyet analizi](intent_v2.json)',
              '- [Model/imaj kimlikleri](runtime_manifest.json)',
              '- [Paket sürümleri](requirements-lock.txt)',
              '', 'Ham oturumlar ve pcap dosyaları `harness/runs/corrected_v2/` altında yereldir ve git-ignore kapsamındadır. '
              'Sonuç JSON’ları ve bu rapor versiyonlanabilir. Wilson aralıkları oturum bağımlılığı ve eğitim belirsizliğini kapsamaz; '
              'küçük pilot sonuçları dağıtım garantisi değildir.', '']
    (ROOT/'experiments/RESULTS_V2.md').write_text('\n'.join(lines))
    # Compact shareable manifest: outcome counts and pcap digests, no raw terminal output.
    (ROOT/'experiments/paired_manifest.json').write_text(json.dumps([
        {k:r.get(k) for k in ['id','origin','model','env','scaffold','task','source_group','pcap_sha256','errors','observed_open_ports']} |
        {'commands_executed':sum(bool(c.get('executed')) for c in r['commands']),
         'nonzero_exit_commands':sum(c.get('returncode',0)!=0 for c in r['commands']),
         'network':r['network']} for r in sessions],indent=2))
    print('Wrote experiments/RESULTS_V2.md and paired_manifest.json')

if __name__=='__main__': main()
