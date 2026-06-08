# GuardianNet

A Multi-Agent Intrusion Detection Framework for Software-Defined Networks (SDN).

## Architecture

- Agent A: KNN-based Flow Classification
- Agent B: Entropy-based Anomaly Detection
- Agent C: LLM-assisted Decision Fusion

## Technologies

- Python
- Ryu SDN Controller
- Mininet
- OpenFlow
- Ollama / LLM

## Dataset Features

- Packet Count
- Byte Count
- Duration
- Delta Packet Count
- Packets Per Second (PPS)

## Experimental Results

| Method | Accuracy |
|----------|----------:|
| KNN | 86.36% |
| Random Forest | 91.32% |
| LSTM | 92.50% |
| Entropy Only | 83.40% |
| GuardianNet | 95.40% |

## Authors

Fakhri Andian
