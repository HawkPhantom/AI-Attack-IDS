# Required live-human follow-up

This study is not completed by replaying archived commands. It requires human
participants who independently choose commands from the same task instructions
and see the same outputs as the AI agents.

## Matched collection

Use the same internal Docker lab, image digests, six command opportunities,
20-second execution cap and two service profiles as the corrected pilot. Give
participants the same two reconnaissance tasks and port budget. Record command
input and output plus pcap; use pseudonymous participant IDs and record consent.
Collect benign maintenance tasks from both humans and agents in this same lab
before making malicious-intent claims. Label authorized task category separately
from successful exploitation or malicious intent.

The collector must distinguish:

- `human_live`: live decisions by a participant;
- `human_replay`: prerecorded human-selected commands replayed by a program;
- `ai`: commands selected online by the model;
- `script`: predetermined automation;
- `counterfactual_script`: a script replaying exactly an AI trajectory.

Do not substitute one of these labels for another. Counterbalance task/profile
order across participants. Have all operators use the same command executor if
the research question is behavior rather than SSH client implementation.

## Splits and claims

Hold out complete participant IDs, complete tasks, and independently implemented
agent frameworks. Keep all repetitions of the same source trajectory in one
split. Select thresholds on a separate calibration set; freeze them before the
final independent test. Report task completion and detector performance jointly.
Do not pool dependent commands as independent sessions to narrow confidence
intervals.

A 1% false-positive-rate claim needs substantially more independent negative
observations than this pilot. With zero false positives, the one-sided 95%
binomial upper bound drops below 1% only at approximately 299 independent
negative observations; repeated sessions from one person need a dependence-aware
analysis and are not automatically independent observations.

The existing pilot's two memory settings are variants of one driver. Add at
least one independently implemented shell agent with state/history management
outside this collector before claiming framework-independent detection. Repeat
adaptive-evasion tests under the corrected collection protocol and require the
agent to preserve its reconnaissance success; suppressing all useful actions
must not count as successful evasion.
