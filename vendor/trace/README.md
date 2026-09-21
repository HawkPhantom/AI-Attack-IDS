# TRACE: Behavioral Fingerprinting of AI Attack Agents from Terminal Command Sequences

Anonymous repository for RAID 2026 submission.

## Repository Structure

```
├── trace_eval_repro_v3.ipynb   # Main evaluation notebook (all experiments, outputs preserved)
├── rerun_all_experiments.py    # Reproduces all 9 experiments from the paper
├── adapted_baselines.py        # LLMmap contrastive learning baseline (RQ4)
├── adversarial_evasion.py      # Feature-space mimicry simulation (RQ3)
├── ci_analysis.py              # Confidence intervals and statistical tests
├── deep_baselines_tf.py        # BiLSTM and 1D-CNN baselines (RQ4)
├── compute_bertscore.py        # S-BERT and BERTScore fidelity computation
└── data/
    └── example_session.json    # Example session format (full dataset released upon acceptance)
```

## Requirements

```
pip install scikit-learn pandas numpy sentence-transformers tensorflow
```

## Data

The full dataset (2,028 sessions across 7 LLM families and 3 scaffolds) will be released upon paper acceptance. An example session JSON is provided in `data/example_session.json` to illustrate the data format.

## Reproducing Results

```bash
# All experiments (Tables 4-10 in the paper)
python rerun_all_experiments.py

# Confidence intervals and statistical tests
python ci_analysis.py

# Adapted baselines (LLMmap contrastive learning)
python adapted_baselines.py

# Deep learning baselines (BiLSTM, 1D-CNN)
python deep_baselines_tf.py

# Feature-space adversarial evasion (Table mimicry)
python adversarial_evasion.py
```

## Session Format

Each session is a JSON file with the following structure:

```json
{
  "session_id": "cc_deepseek_..._041",
  "family": "deepseek",
  "scaffold": "CC",
  "dataset": "clean",
  "is_dpi": false,
  "entries": [
    {"turn": 0, "command": "whoami && pwd", "output": "root\n/", "type": "tool_call"},
    {"turn": 1, "command": "", "reasoning": "I'll enumerate...", "type": "empty"},
    {"turn": 2, "command": "find /home -type f", "output": "...", "type": "tool_call"}
  ]
}
```

Only `tool_call` entries with non-empty `command` fields are used for TF-IDF feature extraction.
