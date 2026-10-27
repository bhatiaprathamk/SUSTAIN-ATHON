# HCRL Car-Hacking Dataset Samples

## Overview
This folder contains trimmed sample recordings from the **Car-Hacking Dataset for Intrusion Detection** created by the **Hacking and Countermeasure Research Lab (HCRL)** at Korea University.

The dataset was collected from real in-vehicle CAN traffic via the OBD-II port of a Hyundai YF Sonata while the engine was running.

## Files
- `normal_run_data.txt`: First 100,000 frames from the attack-free normal driving recording (~8.4 MB).
- `DoS_dataset.csv`: First 100,000 frames from the DoS intrusion recording (~4.9 MB), containing 76,327 normal frames (`R`) and 23,673 injected attack frames (`T`) with CAN ID `0x000`.

## Format
- **normal_run_data.txt**:
  `Timestamp: <float_seconds>        ID: <hex_id>    <flags>    DLC: <int>    <hex_data_bytes...>`
  All frames are legitimate in-vehicle CAN messages (label = 0).
- **DoS_dataset.csv**:
  `<timestamp_seconds>,<hex_id>,<dlc>,<byte0>,...,<byte7>,<flag>`
  Where `<flag>` is `R` for Regular (normal) frame or `T` for Target (injected attack frame).

## Source & Citation
- **Source**: [HCRL Car-Hacking Dataset](https://ocslab.hksecurity.net/Datasets/car-hacking-dataset)
- **Lab**: Hacking and Countermeasure Research Lab (HCRL), Korea University.
- **Reference Papers**:
  - Eunbi Seo, Hyun Min Song, and Huy Kang Kim, "GIDS: GAN based Intrusion Detection System for In-Vehicle Network," *Privacy and Security in Mobile Systems (PRISMS)*, 2018.
  - Kyong-Tak Cho and Kang G. Shin, "Vulnerability Analysis of Controller Area Network (CAN) and a Cyber-Attack Prevention," *ACM Transactions on Intelligent Systems and Technology*, 2016.
  - Hyunsung Lee, Seong Hoon Jeong, and Huy Kang Kim, "OTIDS: A Novel Intrusion Detection System for In-vehicle Network by Using Remote Frame," *Proceedings of the 2017 ACM ACM-TUR-C Conference*, 2017.

## License / Terms of Use
The dataset is made publicly available for academic and educational research into in-vehicle network security and intrusion detection systems. Commercial use must comply with HCRL / Korea University terms.
